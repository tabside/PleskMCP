"""Periodic maintenance. Exactly one active instance (leader lock in Redis).

Tasks:
* prune expired rows in the database (hourly)
* refresh quota and plan caches of every active account (QUOTA_CACHE_TTL / PLAN_CACHE_TTL)
* enqueue a low-priority retention job per subscription (RETENTION_INTERVAL_HOURS)
* requeue jobs whose worker disappeared (every minute)
* signup (SIGNUP_ENABLED): poll open orders for payment (SIGNUP_PAYMENT_POLL_SECONDS, 5 min),
  lifecycle of active and suspended orders (SIGNUP_LIFECYCLE_SECONDS, 1 h)
"""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
import signal
import socket
import time
from typing import Any

from redis.asyncio import Redis

from .accounts import AccountService
from .config import Settings
from .db import Store
from .plesk_api import DomainInfo
from .queue import LO, JobQueue, touch_heartbeat_file

logger = logging.getLogger(__name__)

LEADER_KEY = "sched:leader"
LEADER_TTL = 30


class Scheduler:
    def __init__(self, settings: Settings, store: Store, redis: Redis, queue: JobQueue, accounts: AccountService, signup: Any | None = None):
        self._settings = settings
        self._signup = signup
        self._store = store
        self._redis = redis
        self._queue = queue
        self._accounts = accounts
        self.instance_id = f"{socket.gethostname()}-{os.getpid()}-{secrets.token_hex(3)}"
        self._stopping = asyncio.Event()
        self.is_leader = False

    def install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.stop)
            except (NotImplementedError, RuntimeError):  # pragma: no cover
                pass

    def stop(self) -> None:
        self._stopping.set()

    # ------------------------------------------------------------- leader lock
    async def acquire_leadership(self) -> bool:
        if await self._redis.set(LEADER_KEY, self.instance_id, nx=True, ex=LEADER_TTL):
            self.is_leader = True
            return True
        current = await self._redis.get(LEADER_KEY)
        if current == self.instance_id:
            await self._redis.expire(LEADER_KEY, LEADER_TTL)
            self.is_leader = True
            return True
        self.is_leader = False
        return False

    async def release_leadership(self) -> None:
        if await self._redis.get(LEADER_KEY) == self.instance_id:
            await self._redis.delete(LEADER_KEY)
        self.is_leader = False

    # ------------------------------------------------------------------- tasks
    async def _due(self, task: str, interval: int) -> bool:
        """Interval bookkeeping in Redis so a restarted scheduler does not repeat everything."""
        key = f"sched:last:{task}"
        last = await self._redis.get(key)
        if last and time.time() - float(last) < interval:
            return False
        await self._redis.set(key, str(time.time()))
        return True

    async def run_due_tasks(self) -> list[str]:
        ran: list[str] = []
        if await self._due("requeue_stale", 60):
            await self.requeue_stale()
            ran.append("requeue_stale")
        if await self._due("prune_db", 3600):
            result = await self._store.prune()
            logger.info("pruned database rows: %s", result)
            ran.append("prune_db")
        if await self._due("refresh_caches", self._settings.quota_cache_ttl):
            await self.refresh_caches()
            ran.append("refresh_caches")
        if await self._due("retention", self._settings.retention_interval_hours * 3600):
            await self.enqueue_retention()
            ran.append("retention")
        if self._signup is not None:
            cfg = self._signup.cfg
            if await self._due("signup_payments", cfg.payment_poll_seconds):
                n = await self._signup.run_payment_polls()
                logger.info("signup: %d open orders checked for payment", n)
                ran.append("signup_payments")
            if await self._due("signup_lifecycle", cfg.lifecycle_seconds):
                n = await self._signup.run_lifecycle()
                logger.info("signup: lifecycle of %d orders checked", n)
                ran.append("signup_lifecycle")
        return ran

    async def alive_workers(self) -> set[str]:
        workers: set[str] = set()
        async for key in self._redis.scan_iter(match="worker:*", count=100):
            workers.add(key.split(":", 1)[1])
        return workers

    async def requeue_stale(self) -> int:
        alive = await self.alive_workers()
        n = await self._queue.requeue_stale(older_than=self._settings.job_time_limit * 2, alive_workers=alive)
        if n:
            logger.warning("requeued %d stale jobs", n)
        return n

    async def refresh_caches(self) -> int:
        count = 0
        for account in await self._store.list_accounts(active_only=True):
            login = account["plesk_login"]
            seen: set[int] = set()
            for raw in account["domains"]:
                domain = DomainInfo.from_dict(raw)
                ws_id = domain.webspace_id or domain.id
                if ws_id is None or ws_id in seen or domain.kind != "webspace":
                    continue
                seen.add(ws_id)
                try:
                    await self._accounts.quota_for(login, domain, refresh=True)
                    await self._accounts.profile_for(login, domain)
                except Exception as exc:  # noqa: BLE001 - one account must not stop the loop
                    logger.debug("cache refresh for %s/%s: %s", login, domain.name, exc)
                count += 1
        return count

    async def enqueue_retention(self) -> int:
        count = 0
        for account in await self._store.list_accounts(active_only=True):
            login = account["plesk_login"]
            for raw in account["domains"]:
                domain = DomainInfo.from_dict(raw)
                if domain.kind != "webspace" or domain.status != 0:
                    continue
                limits = await self.limits_for(login, domain)
                limits["time_limit"] = self._settings.job_time_limit
                request: dict[str, Any] = {"v": 2, "op": "retention", "domain": domain.name, "docroot": domain.docroot, "limits": limits, "args": {}, "tool": "scheduler"}
                await self._queue.submit(login=login, domain=domain.name, sysuser=domain.sysuser, request=request, write=False, priority=LO, tool="retention")
                count += 1
        logger.info("enqueued %d retention jobs", count)
        return count

    async def limits_for(self, login: str, domain: DomainInfo) -> dict[str, Any]:
        """Helper limits for a domain: service defaults, profile values and the cached quota."""
        limits: dict[str, Any] = dict(self._settings.helper_limits)
        try:
            profile = await self._accounts.profile_for(login, domain)
            limits.update(profile.limits(self._settings.profile_defaults))
        except Exception:  # noqa: BLE001 - no profile: defaults apply to retention
            pass
        quota = await self._accounts.quota_for(login, domain)
        limits["quota_bytes"] = quota.quota_bytes
        limits["used_bytes"] = quota.used_bytes
        return limits

    # -------------------------------------------------------------------- loop
    async def run_forever(self) -> None:
        logger.info("scheduler %s started", self.instance_id)
        while not self._stopping.is_set():
            touch_heartbeat_file()
            try:
                if await self.acquire_leadership():
                    await self.run_due_tasks()
                else:
                    logger.debug("scheduler %s: standby", self.instance_id)
            except Exception as exc:  # noqa: BLE001
                logger.exception("scheduler loop error: %s", exc)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=10)
            except asyncio.TimeoutError:
                pass
        await self.release_leadership()
        logger.info("scheduler %s stopped", self.instance_id)
