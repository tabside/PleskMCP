"""Rate limits in Redis, shared by every api replica.

Login limits (failures per IP, per login, global budget of failed Plesk
authentications) and per-login tool limits (calls per minute, writes per
minute, written bytes per hour) are token buckets implemented as counters
with expiry. Lua keeps the check-and-count atomic.
"""

from __future__ import annotations

import time

from redis.asyncio import Redis

from ..config import Settings

# Sliding counter: increments KEYS[1] if below ARGV[1], sets expiry ARGV[2] on first increment.
# Returns {allowed(0/1), current, ttl}.
_BUCKET = """
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
if limit > 0 and current + cost > limit then
  local ttl = redis.call('TTL', KEYS[1])
  if ttl < 0 then ttl = window end
  return {0, current, ttl}
end
local value = redis.call('INCRBY', KEYS[1], cost)
if value == cost then
  redis.call('EXPIRE', KEYS[1], window)
end
local ttl = redis.call('TTL', KEYS[1])
return {1, value, ttl}
"""


class RateLimited(Exception):
    def __init__(self, scope: str, retry_after: int):
        super().__init__(f"rate limited ({scope}), retry in {retry_after}s")
        self.scope = scope
        self.retry_after = retry_after


class RedisLimiter:
    def __init__(self, settings: Settings, redis: Redis):
        self._settings = settings
        self._redis = redis
        self._bucket = redis.register_script(_BUCKET)

    async def _take(self, key: str, limit: int, window: int, cost: int = 1) -> tuple[bool, int, int]:
        allowed, current, ttl = await self._bucket(keys=[key], args=[limit, window, cost])
        return bool(allowed), int(current), int(ttl)

    async def _peek(self, key: str) -> int:
        raw = await self._redis.get(key)
        return int(raw) if raw else 0

    # ------------------------------------------------------------------ logins
    async def check_login(self, *, ip: str, login: str) -> None:
        """Raise RateLimited before a login attempt is processed. Counts nothing."""
        s = self._settings
        if await self._peek(f"rl:login:ip:{ip}") >= s.login_fail_limit_ip:
            raise RateLimited("ip", await self._ttl(f"rl:login:ip:{ip}"))
        if login and await self._peek(f"rl:login:user:{login.lower()}") >= s.login_fail_limit_login:
            raise RateLimited("login", await self._ttl(f"rl:login:user:{login.lower()}"))
        if s.plesk_fail_budget > 0 and await self._peek("rl:login:plesk") >= s.plesk_fail_budget:
            raise RateLimited("plesk_budget", await self._ttl("rl:login:plesk"))

    async def _ttl(self, key: str) -> int:
        ttl = await self._redis.ttl(key)
        return max(int(ttl), 1)

    async def record_login_failure(self, *, ip: str, login: str, plesk_checked: bool) -> None:
        s = self._settings
        ip_key = f"rl:login:ip:{ip}"
        allowed_before = await self._peek(ip_key) < s.login_fail_limit_ip
        await self._take(ip_key, 0, s.login_fail_window)
        if login:
            await self._take(f"rl:login:user:{login.lower()}", 0, s.login_fail_window)
        # The global budget only counts failures from IPs that were not already
        # locked out: an attacker who is blocked per IP cannot exhaust it for everyone.
        if plesk_checked and s.plesk_fail_budget > 0 and allowed_before:
            await self._take("rl:login:plesk", 0, s.plesk_fail_budget_window)

    async def record_login_success(self, *, ip: str, login: str) -> None:
        await self._redis.delete(f"rl:login:user:{login.lower()}")

    # ------------------------------------------------------------------- tools
    async def take_tool_call(self, login: str, *, write: bool, write_bytes: int = 0, limits: dict[str, int] | None = None) -> None:
        s = self._settings
        limits = limits or {}
        calls_limit = int(limits.get("tool_calls_per_minute", s.tool_calls_per_minute))
        writes_limit = int(limits.get("tool_writes_per_minute", s.tool_writes_per_minute))
        bytes_limit = int(limits.get("write_bytes_per_hour", s.write_bytes_per_hour))
        key = login.lower()
        allowed, _, ttl = await self._take(f"rl:tool:calls:{key}", calls_limit, 60)
        if not allowed:
            raise RateLimited("tool_calls", ttl)
        if write:
            allowed, _, ttl = await self._take(f"rl:tool:writes:{key}", writes_limit, 60)
            if not allowed:
                raise RateLimited("tool_writes", ttl)
            if write_bytes > 0:
                allowed, _, ttl = await self._take(f"rl:tool:bytes:{key}", bytes_limit, 3600, write_bytes)
                if not allowed:
                    raise RateLimited("write_bytes", ttl)

    async def status(self, login: str) -> dict[str, int]:
        key = login.lower()
        return {
            "calls_this_minute": await self._peek(f"rl:tool:calls:{key}"),
            "writes_this_minute": await self._peek(f"rl:tool:writes:{key}"),
            "bytes_this_hour": await self._peek(f"rl:tool:bytes:{key}"),
        }


def now() -> int:
    return int(time.time())
