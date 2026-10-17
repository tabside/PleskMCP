"""Job queue on Redis with per-login fairness.

Every tool call that needs the Plesk server becomes a job. Jobs are kept in
one list per login (two priorities), and a ring of logins is rotated so that
workers serve logins round-robin: a login with hundreds of queued jobs gets
one turn per round, the same as a login with a single job. At most
LOGIN_MAX_CONCURRENCY jobs of one login run at the same time.

Keys:
  jobs:<id>            hash with the job and its result (expires JOB_RESULT_TTL after finishing)
  q:hi:<login>, q:lo:<login>   job ids waiting, per priority
  q:logins / q:loginset        ring of logins that have waiting jobs
  run:<login>          number of running jobs of a login
  q:wake               wake-up tokens for idle workers
  done:<id>            signal list the api blocks on for a synchronous answer
  running              zset of running job ids (score: start time) for stale-job recovery
  worker:<id>          heartbeat
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import signal
import socket
import time
from dataclasses import dataclass
from typing import Any

from redis.asyncio import Redis

from .config import Settings
from .remote import HelperError, RemoteError, SSHPool

logger = logging.getLogger(__name__)

HI, LO = "hi", "lo"

HEARTBEAT_FILE = os.environ.get("PLESKMCP_HEARTBEAT_FILE", "/tmp/pleskmcp-heartbeat")


def touch_heartbeat_file() -> None:
    """Container healthchecks of worker and scheduler look at this file's mtime."""
    try:
        with open(HEARTBEAT_FILE, "a"):
            os.utime(HEARTBEAT_FILE, None)
    except OSError:  # pragma: no cover - read-only filesystem
        pass

_ENQUEUE = """
-- KEYS: jobs:<id>, q:<prio>:<login>, q:logins, q:loginset, q:wake ; ARGV: login, fields json
local login = ARGV[1]
local fields = cjson.decode(ARGV[2])
for k, v in pairs(fields) do redis.call('HSET', KEYS[1], k, v) end
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[3]))
redis.call('RPUSH', KEYS[2], ARGV[4])
if redis.call('SADD', KEYS[4], login) == 1 then
  redis.call('RPUSH', KEYS[3], login)
end
redis.call('RPUSH', KEYS[5], '1')
redis.call('LTRIM', KEYS[5], -1000, -1)
return 1
"""

_PICK = """
-- KEYS: q:logins, q:loginset, running ; ARGV: max_per_login, now, worker
local n = redis.call('LLEN', KEYS[1])
for i = 1, n do
  local login = redis.call('RPOPLPUSH', KEYS[1], KEYS[1])
  if not login then return nil end
  local running = tonumber(redis.call('GET', 'run:' .. login) or '0')
  local hi = 'q:hi:' .. login
  local lo = 'q:lo:' .. login
  if running < tonumber(ARGV[1]) then
    local id = redis.call('LPOP', hi)
    if not id then id = redis.call('LPOP', lo) end
    if id then
      redis.call('INCR', 'run:' .. login)
      if redis.call('LLEN', hi) == 0 and redis.call('LLEN', lo) == 0 then
        redis.call('LREM', KEYS[1], 1, login)
        redis.call('SREM', KEYS[2], login)
      end
      redis.call('HSET', 'jobs:' .. id, 'status', 'running', 'started', ARGV[2], 'worker', ARGV[3])
      redis.call('ZADD', KEYS[3], ARGV[2], id)
      return id
    else
      redis.call('LREM', KEYS[1], 1, login)
      redis.call('SREM', KEYS[2], login)
    end
  end
end
return nil
"""

_FINISH = """
-- KEYS: jobs:<id>, done:<id>, running ; ARGV: login, ttl, status, result_json, error_json, finished
redis.call('HSET', KEYS[1], 'status', ARGV[3], 'result', ARGV[4], 'error', ARGV[5], 'finished', ARGV[6])
-- the request (it may carry database credentials for the helper) is not kept with the result
redis.call('HDEL', KEYS[1], 'request')
redis.call('EXPIRE', KEYS[1], tonumber(ARGV[2]))
local run = redis.call('DECR', 'run:' .. ARGV[1])
if run <= 0 then redis.call('DEL', 'run:' .. ARGV[1]) end
redis.call('ZREM', KEYS[3], ARGV[7])
redis.call('RPUSH', KEYS[2], '1')
redis.call('EXPIRE', KEYS[2], tonumber(ARGV[2]))
return 1
"""

_REQUEUE = """
-- KEYS: jobs:<id>, q:hi:<login>, q:logins, q:loginset, running, q:wake ; ARGV: id, login
local status = redis.call('HGET', KEYS[1], 'status')
if status ~= 'running' then return 0 end
redis.call('HSET', KEYS[1], 'status', 'queued', 'retries', tonumber(redis.call('HGET', KEYS[1], 'retries') or '0') + 1)
redis.call('RPUSH', KEYS[2], ARGV[1])
if redis.call('SADD', KEYS[4], ARGV[2]) == 1 then redis.call('RPUSH', KEYS[3], ARGV[2]) end
local run = redis.call('DECR', 'run:' .. ARGV[2])
if run <= 0 then redis.call('DEL', 'run:' .. ARGV[2]) end
redis.call('ZREM', KEYS[5], ARGV[1])
redis.call('RPUSH', KEYS[6], '1')
return 1
"""


@dataclass
class JobInfo:
    id: str
    login: str
    domain: str
    op: str
    status: str
    created: int
    started: int | None
    finished: int | None
    result: Any | None
    error: dict[str, Any] | None
    retries: int = 0

    def public(self) -> dict[str, Any]:
        data: dict[str, Any] = {"job_id": self.id, "status": self.status, "operation": self.op, "domain": self.domain, "created": self.created}
        if self.started:
            data["started"] = self.started
        if self.finished:
            data["finished"] = self.finished
        if self.status == "done":
            data["result"] = self.result
        if self.status == "failed" and self.error:
            data["error"] = self.error
        return data


class JobQueue:
    def __init__(self, settings: Settings, redis: Redis):
        self._settings = settings
        self._redis = redis
        self._enqueue = redis.register_script(_ENQUEUE)
        self._pick = redis.register_script(_PICK)
        self._finish = redis.register_script(_FINISH)
        self._requeue = redis.register_script(_REQUEUE)

    # ------------------------------------------------------------------ submit
    async def submit(
        self,
        *,
        login: str,
        domain: str,
        sysuser: str,
        request: dict[str, Any],
        write: bool,
        priority: str = HI,
        tool: str = "",
    ) -> str:
        job_id = secrets.token_urlsafe(12)
        now = int(time.time())
        fields = {
            "login": login,
            "domain": domain,
            "sysuser": sysuser,
            "op": request.get("op", ""),
            "tool": tool,
            "request": json.dumps(request, ensure_ascii=False),
            "status": "queued",
            "created": str(now),
            "write": "1" if write else "0",
            "priority": priority,
            "retries": "0",
        }
        ttl = self._settings.job_result_ttl + self._settings.job_time_limit * 4
        await self._enqueue(
            keys=[f"jobs:{job_id}", f"q:{priority}:{login}", "q:logins", "q:loginset", "q:wake"],
            args=[login, json.dumps(fields), ttl, job_id],
        )
        return job_id

    async def wait(self, job_id: str, timeout: float) -> JobInfo | None:
        """Block until the job finished or `timeout` seconds passed. Returns the job either way."""
        info = await self.get(job_id)
        if info is not None and info.status in ("done", "failed"):
            return info
        if timeout > 0:
            await self._redis.blpop([f"done:{job_id}"], timeout=max(1, int(timeout)))
        return await self.get(job_id)

    async def get(self, job_id: str) -> JobInfo | None:
        data = await self._redis.hgetall(f"jobs:{job_id}")
        if not data:
            return None
        result = None
        error = None
        if data.get("result"):
            try:
                result = json.loads(data["result"])
            except ValueError:
                result = None
        if data.get("error"):
            try:
                error = json.loads(data["error"])
            except ValueError:
                error = {"code": "unknown", "message": data["error"]}
        return JobInfo(
            id=job_id,
            login=data.get("login", ""),
            domain=data.get("domain", ""),
            op=data.get("op", ""),
            status=data.get("status", "unknown"),
            created=int(data.get("created") or 0),
            started=int(data["started"]) if data.get("started") else None,
            finished=int(data["finished"]) if data.get("finished") else None,
            result=result,
            error=error,
            retries=int(data.get("retries") or 0),
        )

    async def get_for_login(self, login: str, job_id: str) -> JobInfo | None:
        info = await self.get(job_id)
        if info is None or info.login != login:
            return None
        return info

    async def queue_length(self) -> int:
        total = 0
        async for key in self._redis.scan_iter(match="q:hi:*", count=200):
            total += await self._redis.llen(key)
        async for key in self._redis.scan_iter(match="q:lo:*", count=200):
            total += await self._redis.llen(key)
        return total

    async def running_count(self) -> int:
        return int(await self._redis.zcard("running"))

    # ------------------------------------------------------------------ worker
    async def pick(self, worker_id: str) -> str | None:
        job_id = await self._pick(keys=["q:logins", "q:loginset", "running"], args=[self._settings.login_max_concurrency, int(time.time()), worker_id])
        return str(job_id) if job_id else None

    async def wait_for_work(self, timeout: int = 1) -> None:
        await self._redis.blpop(["q:wake"], timeout=timeout)

    async def finish(self, job_id: str, login: str, *, status: str, result: Any | None, error: dict[str, Any] | None) -> None:
        await self._finish(
            keys=[f"jobs:{job_id}", f"done:{job_id}", "running"],
            args=[login, self._settings.job_result_ttl, status, json.dumps(result, ensure_ascii=False) if result is not None else "", json.dumps(error) if error else "", int(time.time()), job_id],
        )

    async def requeue_stale(self, *, older_than: int, alive_workers: set[str]) -> int:
        """Put jobs back whose worker died. Safe because write operations are idempotent (request_id markers)."""
        cutoff = time.time() - older_than
        stale = await self._redis.zrangebyscore("running", "-inf", cutoff)
        requeued = 0
        for job_id in stale:
            data = await self._redis.hgetall(f"jobs:{job_id}")
            if not data:
                await self._redis.zrem("running", job_id)
                continue
            if data.get("worker") in alive_workers and float(data.get("started") or 0) > time.time() - self._settings.job_time_limit * 3:
                continue
            if int(data.get("retries") or 0) >= 2:
                await self.finish(job_id, data.get("login", ""), status="failed", result=None, error={"code": "worker_lost", "message": "the job was interrupted repeatedly"})
                continue
            login = data.get("login", "")
            requeued += int(await self._requeue(keys=[f"jobs:{job_id}", f"q:hi:{login}", "q:logins", "q:loginset", "running", "q:wake"], args=[job_id, login]))
        return requeued

    async def record_metric(self, op: str, ok: bool, duration: float) -> None:
        key = "metrics:jobs"
        pipe = self._redis.pipeline()
        pipe.hincrby(key, f"{op}:{'ok' if ok else 'failed'}", 1)
        pipe.hincrbyfloat(key, f"{op}:duration_sum", duration)
        pipe.hincrby(key, f"{op}:count", 1)
        await pipe.execute()

    async def metrics(self) -> dict[str, float]:
        raw = await self._redis.hgetall("metrics:jobs")
        return {k: float(v) for k, v in raw.items()}


class Worker:
    """Takes jobs from the queue and runs the helper over SSH."""

    def __init__(self, settings: Settings, queue: JobQueue, redis: Redis, pool: SSHPool, *, worker_id: str | None = None):
        self._settings = settings
        self._queue = queue
        self._redis = redis
        self._pool = pool
        self.worker_id = worker_id or f"{socket.gethostname()}-{os.getpid()}-{secrets.token_hex(3)}"
        self._stopping = asyncio.Event()
        self._tasks: set[asyncio.Task[None]] = set()
        self._slots = asyncio.Semaphore(settings.ssh_max_concurrency)

    def install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            try:
                loop.add_signal_handler(sig, self.stop)
            except (NotImplementedError, RuntimeError):  # pragma: no cover - not on this platform
                pass

    def stop(self) -> None:
        logger.info("worker %s: stop requested, finishing running jobs", self.worker_id)
        self._stopping.set()

    async def heartbeat(self) -> None:
        await self._redis.set(f"worker:{self.worker_id}", str(int(time.time())), ex=30)
        touch_heartbeat_file()

    async def preflight(self) -> bool:
        """Check the SSH configuration once at start; the result is visible in /readyz (ssh_preflight)."""
        check = getattr(self._pool, "preflight", None)
        ok, message = (True, "no preflight") if check is None else await check()
        if ok:
            logger.info("worker %s: ssh preflight ok: %s", self.worker_id, message)
        else:
            logger.error("worker %s: ssh preflight FAILED, every job will fail until this is fixed: %s", self.worker_id, message)
        await self._redis.set(f"preflight:{self.worker_id}", json.dumps({"ok": ok, "message": message, "ts": int(time.time())}), ex=3600)
        return ok

    async def run_forever(self) -> None:
        logger.info("worker %s started (max %d parallel helper runs)", self.worker_id, self._settings.ssh_max_concurrency)
        try:
            await self.preflight()
        except Exception as exc:  # noqa: BLE001 - never block the loop on the self-check
            logger.error("worker %s: preflight could not run: %s", self.worker_id, exc)
        last_beat = 0.0
        while not self._stopping.is_set():
            if time.time() - last_beat > 10:
                await self.heartbeat()
                last_beat = time.time()
            await self._slots.acquire()
            try:
                job_id = await self._queue.pick(self.worker_id)
            except Exception as exc:  # noqa: BLE001 - redis hiccup, keep going
                self._slots.release()
                logger.error("worker %s: pick failed: %s", self.worker_id, exc)
                await asyncio.sleep(1)
                continue
            if job_id is None:
                self._slots.release()
                try:
                    await self._queue.wait_for_work(timeout=1)
                except Exception as exc:  # noqa: BLE001
                    logger.error("worker %s: wait failed: %s", self.worker_id, exc)
                    await asyncio.sleep(1)
                continue
            task = asyncio.create_task(self._run_job(job_id, release_slot=True))
            self._tasks.add(task)
            task.add_done_callback(self._tasks.discard)
        if self._tasks:
            logger.info("worker %s: waiting for %d running jobs", self.worker_id, len(self._tasks))
            await asyncio.wait(self._tasks, timeout=self._settings.job_time_limit + 10)
        await self._redis.delete(f"worker:{self.worker_id}", f"preflight:{self.worker_id}")
        await self._pool.close()
        logger.info("worker %s stopped", self.worker_id)

    async def run_one(self) -> bool:
        """Process at most one job (used by tests and the in-process test worker)."""
        job_id = await self._queue.pick(self.worker_id)
        if job_id is None:
            return False
        await self._run_job(job_id)
        return True

    async def _run_job(self, job_id: str, release_slot: bool = False) -> None:
        started = time.time()
        login = ""
        op = ""
        try:
            data = await self._redis.hgetall(f"jobs:{job_id}")
            if not data:
                return
            login = data.get("login", "")
            op = data.get("op", "")
            request = json.loads(data["request"])
            limits = request.get("limits") or {}
            time_limit = int(limits.get("time_limit") or self._settings.helper_time_limit)
            try:
                result = await self._pool.run(data["sysuser"], request, timeout=time_limit + 10)
            except HelperError as exc:
                error: dict[str, Any] = {"code": exc.code, "message": exc.message}
                if exc.details:
                    error["details"] = exc.details
                await self._queue.finish(job_id, login, status="failed", result=None, error=error)
                await self._queue.record_metric(op, False, time.time() - started)
                return
            except RemoteError as exc:
                # the message may name hosts or files: it goes to the log, only the code to the client
                logger.error("job %s (%s/%s): remote error [%s]: %s", job_id, login, op, exc.code, exc)
                await self._queue.finish(job_id, login, status="failed", result=None, error={"code": exc.code, "message": "helper not reachable"})
                await self._queue.record_metric(op, False, time.time() - started)
                return
            await self._queue.finish(job_id, login, status="done", result=result, error=None)
            await self._queue.record_metric(op, True, time.time() - started)
        except Exception as exc:  # noqa: BLE001
            logger.exception("job %s (%s/%s) crashed: %s", job_id, login, op, exc)
            try:
                await self._queue.finish(
                    job_id, login, status="failed", result=None, error={"code": "internal", "message": "job failed", "details": {"error": exc.__class__.__name__}}
                )
                await self._queue.record_metric(op, False, time.time() - started)
            except Exception:  # noqa: BLE001
                pass
        finally:
            if release_slot:
                self._slots.release()
