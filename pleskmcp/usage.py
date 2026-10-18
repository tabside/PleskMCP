"""Per-login usage counters in Redis for the operator endpoint /admin/usage.

Every tool call increments the counters of the calling login (total, writes,
last call, last client and tool) plus a per-day counter that keeps 100 days,
so the report can show calls in the last 7 and 30 days. No paths, contents or
domains are recorded here; the audit log has the details of write operations.
"""

from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import Any

from redis.asyncio import Redis

logger = logging.getLogger(__name__)

LOGINS_KEY = "usage:logins"
DAY_RETENTION = 100 * 86400


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


class UsageTracker:
    def __init__(self, redis: Redis):
        self._redis = redis

    async def record(self, login: str, *, client_id: str | None, tool: str | None = None, write: bool = False) -> None:
        """Count one tool call (or one write when the tool name is known). Never raises."""
        now = time.time()
        key = f"usage:login:{login}"
        try:
            pipe = self._redis.pipeline(transaction=False)
            if write:
                pipe.hincrby(key, "writes", 1)
                if tool:
                    pipe.hset(key, mapping={"last_write_tool": tool, "last_write_at": int(now)})
            else:
                pipe.hincrby(key, "calls", 1)
                pipe.hsetnx(key, "first_call_at", int(now))
                mapping: dict[str, Any] = {"last_call_at": int(now)}
                if client_id:
                    mapping["last_client"] = client_id
                pipe.hset(key, mapping=mapping)
                day_key = f"usage:day:{_day(now)}"
                pipe.hincrby(day_key, login, 1)
                pipe.expire(day_key, DAY_RETENTION)
                pipe.sadd(LOGINS_KEY, login)
            await pipe.execute()
        except Exception as exc:  # noqa: BLE001 - counters must never break a tool call
            logger.warning("usage counter update failed for %s: %s", login, exc.__class__.__name__)

    async def summary(self) -> dict[str, dict[str, Any]]:
        """Counters of every login that ever called a tool, keyed by login."""
        logins = sorted(await self._redis.smembers(LOGINS_KEY))
        now = time.time()
        days_7 = [_day(now - i * 86400) for i in range(7)]
        days_30 = [_day(now - i * 86400) for i in range(30)]
        result: dict[str, dict[str, Any]] = {}
        for login in logins:
            raw = await self._redis.hgetall(f"usage:login:{login}")
            result[login] = {
                "calls": int(raw.get("calls") or 0),
                "writes": int(raw.get("writes") or 0),
                "first_call_at": _int_or_none(raw.get("first_call_at")),
                "last_call_at": _int_or_none(raw.get("last_call_at")),
                "last_client": raw.get("last_client"),
                "last_write_tool": raw.get("last_write_tool"),
                "last_write_at": _int_or_none(raw.get("last_write_at")),
                "calls_7d": 0,
                "calls_30d": 0,
            }
        for day in days_30:
            raw = await self._redis.hgetall(f"usage:day:{day}")
            for login, count in raw.items():
                if login not in result:
                    continue
                n = int(count or 0)
                result[login]["calls_30d"] += n
                if day in days_7:
                    result[login]["calls_7d"] += n
        return result


def _int_or_none(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
