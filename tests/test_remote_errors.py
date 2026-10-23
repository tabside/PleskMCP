"""Failures between api, worker, SSH and helper reach the client as distinct, safe messages.

A job that fails must never surface as a bare "job failed [internal]" when the
cause is a configuration problem (unusable key, wrong host key, missing sudoers
rule, outdated helper) or a transport problem; and an unexpected exception in
the worker must at least carry the job id so the operator finds it in the log
(type and message are not shown to the client).
"""

from __future__ import annotations

import asyncio
import json

import httpx
import os
from pathlib import Path

import pytest

from conftest import Env, OAuthFlow, call_tool, structured, tool_text
from pleskmcp.config import Settings
from pleskmcp.remote import HelperError, RemoteError, SSHPool, parse_helper_output
from pleskmcp.tools import ToolRunner

pytestmark = pytest.mark.anyio


def test_parse_helper_output_codes():
    with pytest.raises(RemoteError) as info:
        parse_helper_output("", "sudo: a password is required\n", 1)
    assert info.value.code == "sudo_refused"
    with pytest.raises(RemoteError) as info:
        parse_helper_output("", "Sorry, user pleskmcp is not allowed to execute '/usr/local/bin/pleskmcp-helper' as x.\n", 1)
    assert info.value.code == "sudo_refused"
    with pytest.raises(RemoteError) as info:
        parse_helper_output("", "Traceback (most recent call last): ...\n", 1)
    assert info.value.code == "helper_crash"
    with pytest.raises(RemoteError) as info:
        parse_helper_output("not json", "", 0)
    assert info.value.code == "helper_crash"
    with pytest.raises(HelperError) as herr:
        parse_helper_output(json.dumps({"ok": False, "error": "not_found", "message": "no such file", "details": {"path": "x"}}), "", 1)
    assert herr.value.code == "not_found" and herr.value.details == {"path": "x"}
    assert parse_helper_output(json.dumps({"ok": True, "result": {"a": 1}}), "", 0) == {"a": 1}


def _settings(tmp_path: Path, **overrides: str) -> Settings:
    env = {
        "PUBLIC_BASE_URL": "https://mcp.example.com/plesk",
        "PLESK_URL": "https://plesk.example.com:8443",
        "PLESK_SSH_HOST": "127.0.0.1",
        "PLESK_SSH_PORT": "1",
        "PLESK_SSH_USER": "pleskmcp",
        "PLESK_SSH_KEY_PATH": str(tmp_path / "key"),
        "PLESK_SSH_HOST_KEY": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO1ZKq0yTd+8Z6lHj3GQ8hfQJd5n5Q2qg0Ck1h1vW8pr",
        "PLESK_SSH_TIMEOUT": "2",
        "DATABASE_URL": "sqlite+aiosqlite:///:memory:",
        "REDIS_URL": "redis://fake",
        "DATA_ENCRYPTION_KEY": "x",
    }
    env.update(overrides)
    old = {k: os.environ.get(k) for k in env}
    for k, v in env.items():
        os.environ[k] = v
    try:
        return Settings.load()
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


async def test_ssh_pool_reports_configuration_problems(tmp_path: Path):
    import asyncssh

    # missing key file
    pool = SSHPool(_settings(tmp_path))
    ok, message = await pool.preflight()
    assert not ok and "[ssh_config]" in message and "PLESK_SSH_KEY_PATH" in message
    with pytest.raises(RemoteError) as info:
        await pool.run("example_sys", {"op": "ping"})
    assert info.value.code == "ssh_config"

    # key with a passphrase cannot be used unattended (export needs bcrypt; skip the sub-case without it)
    key = asyncssh.generate_private_key("ssh-ed25519")
    try:
        encrypted = key.export_private_key("openssh", passphrase="secret")
    except asyncssh.KeyExportError:
        encrypted = None
    if encrypted:
        (tmp_path / "key").write_bytes(encrypted)
        ok, message = await pool.preflight()
        assert not ok and "[ssh_config]" in message and "secret" not in message

    # a file that is not a key at all
    (tmp_path / "key").write_text("-----BEGIN NOTHING-----\n")
    ok, message = await pool.preflight()
    assert not ok and "[ssh_config]" in message

    # usable key, but a host key that is not a key
    (tmp_path / "key").write_bytes(key.export_private_key("openssh"))
    bad = SSHPool(_settings(tmp_path, PLESK_SSH_HOST_KEY="ssh-ed25519 not-base64!!"))
    ok, message = await bad.preflight()
    assert not ok and "[ssh_config]" in message and "PLESK_SSH_HOST_KEY" in message

    # everything loadable, nothing listening: ssh_unreachable, not internal
    good = SSHPool(_settings(tmp_path))
    ok, message = await good.preflight()
    assert ok, message
    with pytest.raises(RemoteError) as info:
        await good.run("example_sys", {"op": "ping"}, timeout=2)
    assert info.value.code == "ssh_unreachable"
    assert "example_sys" not in str(info.value.code)


async def test_pool_works_without_local_passwd_entry(tmp_path: Path, monkeypatch):
    """Inside the container uid 1000 has no passwd entry and no USER variable; asyncssh must still get a local user name."""
    import getpass
    import pwd

    import asyncssh

    for name in ("LOGNAME", "USER", "LNAME", "USERNAME"):
        monkeypatch.delenv(name, raising=False)

    def no_entry(uid):
        raise KeyError(uid)

    monkeypatch.setattr(pwd, "getpwuid", no_entry)
    with pytest.raises((KeyError, OSError)):  # KeyError up to Python 3.12, OSError from 3.13
        getpass.getuser()
    key = asyncssh.generate_private_key("ssh-ed25519")
    (tmp_path / "key").write_bytes(key.export_private_key("openssh"))
    pool = SSHPool(_settings(tmp_path))
    assert getpass.getuser() == "pleskmcp"
    with pytest.raises(RemoteError) as info:
        await pool.run("example_sys", {"op": "ping"}, timeout=2)
    assert info.value.code == "ssh_unreachable"  # the option check passed; only the port is closed


def test_explain_error_messages():
    explain = ToolRunner.explain_error
    assert "[ssh_config]" in explain({"code": "ssh_config", "message": "helper not reachable"})
    assert "SSH-Schlüssel" in explain({"code": "ssh_config"})
    assert "[ssh_auth]" in explain({"code": "ssh_auth"})
    assert "sudoers" in explain({"code": "sudo_refused"})
    assert "install.sh" in explain({"code": "helper_crash"})
    assert "nicht erreichbar" in explain({"code": "ssh_unreachable"})
    assert explain({"code": "internal", "message": "job failed", "details": {"job_id": "j1"}}) == "Interner Fehler im Dateidienst (Auftrag j1). Der Hoster muss das beheben; der Fehler steht im Worker-Log. [internal]"
    assert explain({"code": "internal", "message": "job failed", "details": {"error": "KeyImportError"}}) == "Interner Fehler im Dateidienst. Der Hoster muss das beheben; der Fehler steht im Worker-Log. [internal]"
    assert "Zeitlimit" in explain({"code": "helper_timeout", "message": ""})
    assert explain({"code": "not_found", "message": "no such file"}) == "no such file [not_found]"


async def test_worker_failures_reach_the_client(env: Env, flow: OAuthFlow):
    access = (await flow.full_login())["access_token"]
    # a configuration problem in the worker
    env.pool.fail_with = RemoteError("SSH private key at PLESK_SSH_KEY_PATH cannot be used: KeyImportError: Passphrase must be specified", "ssh_config")
    result = await call_tool(env.client, access, "list_dir", {"domain": "example.com", "path": ""})
    text = tool_text(result)
    assert result["isError"] and "[ssh_config]" in text and "SSH-Schlüssel" in text
    assert "PLESK_SSH_KEY_PATH" not in text and "KeyImportError" not in text  # operator detail stays in the log
    # the unexpected: a bug or an unmapped exception gives the client the job id only, type and message stay in the log
    env.pool.fail_with = RuntimeError("secret path /var/www/vhosts/other/x")
    result = await call_tool(env.client, access, "storage_status", {"domain": "example.com"})
    text = tool_text(result)
    assert result["isError"] and "[internal]" in text and "(Auftrag " in text and "RuntimeError" not in text and "/var/www" not in text
    # job_status shows the same message for a job fetched later
    env.pool.fail_with = RemoteError("sudo refused", "sudo_refused")
    env.services.runner._settings = env.settings.__class__(**{**env.settings.__dict__, "tool_sync_wait": 0})
    env.pool.delay = 0.3
    pending = structured(await call_tool(env.client, access, "list_dir", {"domain": "example.com", "path": ""}))
    for _ in range(30):
        status = structured(await call_tool(env.client, access, "job_status", {"job_id": pending["job_id"]}))
        if status["status"] == "failed":
            break
        await asyncio.sleep(0.1)
    assert status["status"] == "failed" and "[sudo_refused]" in status["message"]
    # failed jobs are counted
    env.pool.fail_with = None
    env.pool.delay = 0
    metrics = await env.services.queue.metrics()
    assert metrics.get("list_dir:failed", 0) >= 2 and metrics.get("storage_status:failed", 0) >= 1
    # the audit log carries the error code of a failed write, never the operator message
    env.services.runner._settings = env.settings
    env.pool.fail_with = RemoteError("ssh down", "ssh_unreachable")
    result = await call_tool(env.client, access, "write_file", {"domain": "example.com", "path": "x.txt", "content": "x"})
    assert result["isError"] and "[ssh_unreachable]" in tool_text(result)
    audit = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert '"event": "tool_write_failed"' in audit and '"error": "ssh_unreachable"' in audit


async def test_readyz_reports_preflight(env: Env):
    r = await env.client.get("/plesk/readyz")
    assert r.status_code == 200 and r.json()["checks"]["ssh_preflight"] == "ok"
    await env.redis.set("preflight:broken-worker", json.dumps({"ok": False, "message": "[ssh_config] SSH private key at PLESK_SSH_KEY_PATH cannot be used: KeyImportError: Invalid private key", "ts": 0}))
    r = await env.client.get("/plesk/readyz")
    checks = r.json()["checks"]
    assert checks["ssh_preflight"] == "failed" and any("ssh_config" in m for m in checks["ssh_preflight_errors"])
    # the error texts are operator detail: from a non-local address they need ADMIN_API_TOKEN, otherwise the field is left out
    token = "admin-test-token-with-enough-length"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=env.app, client=("203.0.113.9", 4711)), base_url="https://mcp.example.com", headers={"host": "mcp.example.com"}) as remote:
        r = await remote.get("/plesk/readyz")
        checks = r.json()["checks"]
        assert r.status_code == 200 and checks["ssh_preflight"] == "failed" and "ssh_preflight_errors" not in checks
        assert "ssh_preflight_errors" not in (await remote.get("/plesk/readyz", headers={"authorization": f"Bearer {token}"})).json()["checks"]  # no token configured
        object.__setattr__(env.settings, "admin_api_token", token)  # Settings is frozen
        assert "ssh_preflight_errors" not in (await remote.get("/plesk/readyz", headers={"authorization": "Bearer wrong"})).json()["checks"]
        checks = (await remote.get("/plesk/readyz", headers={"authorization": f"Bearer {token}"})).json()["checks"]
        assert any("ssh_config" in m for m in checks["ssh_preflight_errors"])
