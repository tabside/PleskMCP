"""Queue, worker and scheduler: fairness between logins, concurrency limits, job ownership, background jobs, requeue, leader lock, health."""

from __future__ import annotations

import asyncio
import time

import pytest

from conftest import Env, OAuthFlow, call_tool, structured, tool_text
from pleskmcp.queue import JobQueue
from pleskmcp.scheduler import Scheduler

pytestmark = pytest.mark.anyio


def request_for(env: Env, domain: str = "example.com") -> dict:
    home = env.vhosts / domain
    return {"v": 2, "op": "list_dir", "domain": domain, "docroot": str(home / "httpdocs"), "limits": {}, "args": {}, "tool": "list_dir"}


async def test_round_robin_and_per_login_concurrency(env: Env):
    queue: JobQueue = env.services.queue
    # keep the real worker away from these jobs: stop it first
    env.worker.stop()
    await asyncio.sleep(1.2)
    a_jobs = [await queue.submit(login="alice", domain="example.com", sysuser="example_sys", request=request_for(env), write=False) for _ in range(6)]
    for _ in range(2):
        await queue.submit(login="bob", domain="other.example", sysuser="other_sys", request=request_for(env, "other.example"), write=False)
    assert await queue.queue_length() == 8
    picked = []
    while True:
        job_id = await queue.pick("w1")
        if job_id is None:
            break
        picked.append(job_id)
    logins = ["alice" if j in a_jobs else "bob" for j in picked]
    # both logins get served although alice queued first and queued more; at most LOGIN_MAX_CONCURRENCY (2) per login run
    assert sorted(logins) == ["alice", "alice", "bob", "bob"]
    assert await queue.running_count() == 4
    # finishing one alice job frees one alice slot, bob stays at its limit
    await queue.finish(picked[logins.index("alice")], "alice", status="done", result={"ok": 1}, error=None)
    assert "alice" == ("alice" if (await queue.pick("w1")) in a_jobs else "bob")
    assert await queue.pick("w1") is None
    info = await queue.get(a_jobs[0]) or await queue.get(picked[logins.index("alice")])
    assert info is not None
    # results are only visible to their login
    done_id = picked[logins.index("alice")]
    assert (await queue.get_for_login("alice", done_id)).status == "done"
    assert await queue.get_for_login("bob", done_id) is None
    # the request (which may carry credentials) is dropped once the job finished
    assert "request" not in await env.redis.hgetall(f"jobs:{done_id}")


async def test_requeue_after_worker_loss(env: Env):
    queue: JobQueue = env.services.queue
    env.worker.stop()
    await asyncio.sleep(1.2)
    job_id = await queue.submit(login="carol", domain="example.com", sysuser="example_sys", request=request_for(env), write=True)
    assert await queue.pick("dead-worker") == job_id
    assert (await queue.get(job_id)).status == "running"
    # the worker is alive: nothing happens
    assert await queue.requeue_stale(older_than=0, alive_workers={"dead-worker"}) == 0
    # the worker vanished: the job goes back to the queue, running counter released
    assert await queue.requeue_stale(older_than=0, alive_workers=set()) == 1
    info = await queue.get(job_id)
    assert info.status == "queued" and info.retries == 1
    assert await queue.pick("w2") == job_id
    # a second loss gives up on the third attempt
    assert await queue.requeue_stale(older_than=0, alive_workers=set()) == 1
    assert await queue.pick("w3") == job_id
    assert await queue.requeue_stale(older_than=0, alive_workers=set()) == 0
    assert (await queue.get(job_id)).status == "failed" and (await queue.get(job_id)).error["code"] == "worker_lost"


async def test_fairness_end_to_end(env: Env, flow: OAuthFlow):
    """One login hammering the service does not noticeably slow another login down."""
    heavy = (await flow.full_login())["access_token"]
    other_flow = OAuthFlow(env)
    await other_flow.register(client_name="Other")
    light = (await other_flow.full_login("other", "geheim2"))["access_token"]
    env.pool.delay = 0.15

    async def timed(token: str, domain: str) -> float:
        start = time.monotonic()
        result = await call_tool(env.client, token, "list_dir", {"domain": domain, "path": ""})
        assert not result.get("isError"), tool_text(result)
        return time.monotonic() - start

    heavy_tasks = [asyncio.create_task(timed(heavy, "example.com")) for _ in range(8)]
    await asyncio.sleep(0.05)
    light_duration = await timed(light, "other.example")
    heavy_durations = await asyncio.gather(*heavy_tasks)
    # 8 jobs of 0.15 s at 2 per login need >= 0.6 s for the heavy login; the light login waits for at most one slot round
    assert max(heavy_durations) >= 0.55
    assert light_duration < 0.5, light_duration
    assert env.pool.max_busy <= env.settings.ssh_max_concurrency


async def test_background_job_and_job_status(env: Env, flow: OAuthFlow):
    access = (await flow.full_login())["access_token"]
    env.services.runner._settings = env.settings.__class__(**{**env.settings.__dict__, "tool_sync_wait": 1})
    env.pool.delay = 2.5
    pending = structured(await call_tool(env.client, access, "list_dir", {"domain": "example.com", "path": ""}))
    assert pending["job_id"] and pending["status"] in ("queued", "running")
    env.pool.delay = 0
    for _ in range(40):
        status = structured(await call_tool(env.client, access, "job_status", {"job_id": pending["job_id"]}))
        if status["status"] == "done":
            break
        await asyncio.sleep(0.2)
    assert status["status"] == "done" and {e["name"] for e in status["result"]["entries"]} >= {"index.php"}
    # another login cannot read the job
    other_flow = OAuthFlow(env)
    await other_flow.register()
    other = (await other_flow.full_login("other", "geheim2"))["access_token"]
    result = await call_tool(env.client, other, "job_status", {"job_id": pending["job_id"]})
    assert result["isError"] and "Unbekannte" in tool_text(result)
    result = await call_tool(env.client, access, "job_status", {"job_id": "nope"})
    assert result["isError"]


async def test_rate_limits_per_login(env: Env, flow: OAuthFlow):
    access = (await flow.full_login())["access_token"]
    env.services.runner._settings = env.settings.__class__(**{**env.settings.__dict__, "tool_calls_per_minute": 3, "tool_writes_per_minute": 1})
    # profile limits fall back to these defaults when the profile does not set them
    for _ in range(3):
        structured(await call_tool(env.client, access, "list_dir", {"domain": "example.com", "path": ""}))
    result = await call_tool(env.client, access, "list_dir", {"domain": "example.com", "path": ""})
    assert result["isError"] and "Limit erreicht (tool_calls)" in tool_text(result)
    # other logins are unaffected
    other_flow = OAuthFlow(env)
    await other_flow.register()
    other = (await other_flow.full_login("other", "geheim2"))["access_token"]
    structured(await call_tool(env.client, other, "list_dir", {"domain": "other.example", "path": ""}))
    await env.redis.delete("rl:tool:calls:kunde")
    structured(await call_tool(env.client, access, "write_file", {"domain": "example.com", "path": "w1.txt", "content": "1"}))
    result = await call_tool(env.client, access, "write_file", {"domain": "example.com", "path": "w2.txt", "content": "2"})
    assert result["isError"] and "tool_writes" in tool_text(result)
    audit = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert '"event": "rate_limited"' in audit


async def test_scheduler_leader_lock_and_tasks(env: Env, flow: OAuthFlow):
    await flow.full_login()  # one active account with its domains
    services = env.services
    s1 = Scheduler(env.settings, services.store, env.redis, services.queue, services.accounts)
    s2 = Scheduler(env.settings, services.store, env.redis, services.queue, services.accounts)
    assert await s1.acquire_leadership() is True
    assert await s2.acquire_leadership() is False
    assert await s1.acquire_leadership() is True  # renews its own lock
    ran = await s1.run_due_tasks()
    assert set(ran) == {"requeue_stale", "prune_db", "refresh_caches", "retention"}
    assert await s1.run_due_tasks() == []  # nothing due again right away
    # retention jobs were queued with low priority for every webspace with hosting and run by the worker
    for _ in range(50):
        if await services.queue.queue_length() == 0 and await services.queue.running_count() == 0:
            break
        await asyncio.sleep(0.1)
    metrics = await services.queue.metrics()
    assert metrics.get("retention:ok", 0) >= 2
    assert await env.redis.get("quota:kunde:100") is not None
    await s1.release_leadership()
    assert await s2.acquire_leadership() is True


async def test_health_and_metrics(env: Env, flow: OAuthFlow):
    r = await env.client.get("/plesk/healthz")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    r = await env.client.get("/plesk/readyz")
    assert r.status_code == 200 and r.json()["checks"]["database"] and r.json()["checks"]["redis"] and r.json()["checks"]["workers"] == 1
    access = (await flow.full_login())["access_token"]
    structured(await call_tool(env.client, access, "list_dir", {"domain": "example.com", "path": ""}))
    r = await env.client.get("/plesk/metrics")
    assert r.status_code == 200
    assert 'pleskmcp_jobs_total{op="list_dir",status="ok"} 1' in r.text and "pleskmcp_workers_alive 1" in r.text
    assert "kunde" not in r.text and "example.com" not in r.text
    r = await env.client.get("/plesk/")
    assert r.json()["account_page"] == "https://mcp.example.com/plesk/account"
