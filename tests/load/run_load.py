"""Load test for the job queue and worker (not part of the CI suite).

One login submits jobs as fast as it can while a few other logins send one
job at a time. The fake helper sleeps for a fixed time per job. Fairness
means the latency of the light logins stays close to one helper run,
however hard the heavy login pushes.

    .venv/bin/python tests/load/run_load.py --seconds 20 --heavy-concurrency 20 --light-logins 3

Uses fakeredis in-process by default; pass --redis-url to run against a real
Redis (the queue and worker code are the same, only the helper is fake).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import statistics
import sys
import time
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from pleskmcp.config import Settings  # noqa: E402
from pleskmcp.queue import JobQueue, Worker  # noqa: E402


class SleepingPool:
    """Stands in for the SSH pool: every helper call takes `delay` seconds."""

    def __init__(self, delay: float):
        self.delay = delay
        self.busy = 0
        self.max_busy = 0

    async def run(self, sysuser: str, request: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
        self.busy += 1
        self.max_busy = max(self.max_busy, self.busy)
        try:
            await asyncio.sleep(self.delay)
            return {"ok": True, "op": request.get("op")}
        finally:
            self.busy -= 1

    async def close(self) -> None:
        return None


def settings_for(args: argparse.Namespace) -> Settings:
    env = {
        "PUBLIC_BASE_URL": "https://mcp.example.com/plesk",
        "PLESK_URL": "https://plesk.example.com:8443",
        "PLESK_SSH_HOST": "plesk.example.com",
        "PLESK_SSH_USER": "pleskmcp",
        "PLESK_SSH_KEY_PATH": "/dev/null",
        "PLESK_SSH_HOST_KEY": "ssh-ed25519 AAAA",
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "REDIS_URL": args.redis_url or "redis://fake",
        "DATA_ENCRYPTION_KEY": "x",
        "SSH_MAX_CONCURRENCY": str(args.ssh_concurrency),
        "LOGIN_MAX_CONCURRENCY": str(args.login_concurrency),
        "TOOL_SYNC_WAIT": "30",
    }
    for key, value in env.items():
        os.environ.setdefault(key, value)
    return Settings.load()


async def main(args: argparse.Namespace) -> int:
    settings = settings_for(args)
    if args.redis_url:
        from pleskmcp.redis_io import make_redis

        redis = make_redis(args.redis_url)
        worker_redis = make_redis(args.redis_url)
    else:
        import fakeredis
        from fakeredis import aioredis

        server = fakeredis.FakeServer()
        redis = aioredis.FakeRedis(server=server, decode_responses=True)
        worker_redis = aioredis.FakeRedis(server=server, decode_responses=True)
    queue = JobQueue(settings, redis)
    pool = SleepingPool(args.helper_seconds)
    workers = [Worker(settings, JobQueue(settings, worker_redis), worker_redis, pool, worker_id=f"load-{i}") for i in range(args.workers)]
    tasks = [asyncio.create_task(w.run_forever()) for w in workers]

    request = {"v": 2, "op": "list_dir", "domain": "example.com", "docroot": "/var/www/vhosts/example.com/httpdocs", "limits": {"time_limit": 30}, "args": {}}
    heavy_lat: list[float] = []
    light_lat: dict[str, list[float]] = {f"light{i}": [] for i in range(args.light_logins)}
    deadline = time.monotonic() + args.seconds

    async def one(login: str, sink: list[float]) -> None:
        start = time.monotonic()
        job_id = await queue.submit(login=login, domain="example.com", sysuser="example_sys", request=request, write=False)
        info = await queue.wait(job_id, settings.tool_sync_wait)
        while info is None or info.status not in ("done", "failed"):
            info = await queue.wait(job_id, settings.tool_sync_wait)
        sink.append(time.monotonic() - start)

    async def heavy_loop() -> None:
        while time.monotonic() < deadline:
            await one("heavy", heavy_lat)

    async def light_loop(login: str) -> None:
        while time.monotonic() < deadline:
            await one(login, light_lat[login])
            await asyncio.sleep(args.light_pause)

    # baseline: one light login alone
    base: list[float] = []
    for _ in range(3):
        await one("baseline", base)
    baseline = statistics.mean(base)

    await asyncio.gather(*[heavy_loop() for _ in range(args.heavy_concurrency)], *[light_loop(name) for name in light_lat])

    for w in workers:
        w.stop()
    await asyncio.gather(*tasks, return_exceptions=True)
    await redis.aclose()
    await worker_redis.aclose()

    def pct(values: list[float], p: float) -> float:
        if not values:
            return float("nan")
        values = sorted(values)
        return values[min(len(values) - 1, int(len(values) * p))]

    lights = [v for values in light_lat.values() for v in values]
    print(f"helper time {args.helper_seconds:.2f}s, workers {args.workers} x {args.ssh_concurrency} slots, per-login limit {args.login_concurrency}")
    print(f"baseline light latency: {baseline:.3f}s")
    print(f"heavy login: {len(heavy_lat)} jobs, median {statistics.median(heavy_lat):.3f}s, p95 {pct(heavy_lat, 0.95):.3f}s")
    print(f"light logins: {len(lights)} jobs, median {statistics.median(lights):.3f}s, p95 {pct(lights, 0.95):.3f}s, max {max(lights):.3f}s")
    print(f"max parallel helper runs: {pool.max_busy}")
    ok = pct(lights, 0.95) <= baseline * 2 + args.helper_seconds
    print("fairness:", "OK" if ok else "VIOLATED", "(light p95 must stay within 2x baseline plus one helper run)")
    return 0 if ok else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=15)
    parser.add_argument("--helper-seconds", type=float, default=0.2)
    parser.add_argument("--heavy-concurrency", type=int, default=20, help="parallel requests of the heavy login")
    parser.add_argument("--light-logins", type=int, default=3)
    parser.add_argument("--light-pause", type=float, default=0.3)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--ssh-concurrency", type=int, default=8)
    parser.add_argument("--login-concurrency", type=int, default=2)
    parser.add_argument("--redis-url", default=None)
    sys.exit(asyncio.run(main(parser.parse_args())))
