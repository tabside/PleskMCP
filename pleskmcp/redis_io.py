"""Redis client factory and small helpers (keys, JSON caching)."""

from __future__ import annotations

import json
from typing import Any

from redis.asyncio import Redis


def make_redis(redis_url: str) -> Redis:
    return Redis.from_url(redis_url, decode_responses=True, socket_timeout=10, socket_connect_timeout=5)


async def cache_get_json(redis: Redis, key: str) -> Any | None:
    raw = await redis.get(key)
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


async def cache_set_json(redis: Redis, key: str, value: Any, ttl: int) -> None:
    await redis.set(key, json.dumps(value), ex=ttl)
