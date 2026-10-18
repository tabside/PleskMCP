"""/admin/usage: token protection, rate limit, report contents (connections, usage counters)."""

from __future__ import annotations

import base64

import pytest

from conftest import Env, OAuthFlow, call_tool, structured

pytestmark = pytest.mark.anyio

TOKEN = "admin-test-token-with-enough-length"


def enable(env: Env) -> None:
    object.__setattr__(env.settings, "admin_api_token", TOKEN)  # Settings is frozen


def basic(password: str) -> dict[str, str]:
    return {"authorization": "Basic " + base64.b64encode(f"kim:{password}".encode()).decode()}


async def test_admin_usage_off_without_token(env: Env):
    assert env.settings.admin_api_token is None
    response = await env.client.get("/plesk/admin/usage", headers={"authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 404


async def test_admin_usage_auth_and_report(env: Env, flow: OAuthFlow):
    enable(env)

    # no credentials, wrong bearer, wrong basic password: 401 with a Basic challenge
    response = await env.client.get("/plesk/admin/usage")
    assert response.status_code == 401 and response.headers["www-authenticate"].startswith("Basic")
    assert (await env.client.get("/plesk/admin/usage", headers={"authorization": "Bearer wrong"})).status_code == 401
    assert (await env.client.get("/plesk/admin/usage", headers=basic("wrong"))).status_code == 401

    # empty report before anyone connected
    response = await env.client.get("/plesk/admin/usage", headers={"authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
    data = response.json()
    assert data["totals"] == {"accounts": 0, "connected": 0, "active_30d": 0, "calls_7d": 0, "calls_30d": 0}

    # one customer connects and calls a read tool twice and a write tool once
    tokens = await flow.full_login()
    structured(await call_tool(env.client, tokens["access_token"], "list_domains", {}))
    structured(await call_tool(env.client, tokens["access_token"], "list_dir", {"domain": "example.com", "path": ""}))
    structured(await call_tool(env.client, tokens["access_token"], "write_file", {"domain": "example.com", "path": "neu.txt", "content": "hallo"}))

    data = (await env.client.get("/plesk/admin/usage", headers={"authorization": f"Bearer {TOKEN}"})).json()
    assert data["totals"]["accounts"] == 1 and data["totals"]["connected"] == 1 and data["totals"]["active_30d"] == 1
    assert data["totals"]["calls_7d"] == 3 and data["totals"]["calls_30d"] == 3
    (row,) = data["accounts"]
    assert row["login"] == "kunde" and row["status"] == "active"
    assert {d["name"] for d in row["domains"]} >= {"example.com", "data.example"}
    (conn,) = row["connections"]
    assert conn["client_id"] == flow.client_id and conn["client_name"] == "Test Client" and conn["families"] == 1
    assert conn["since"] and conn["last_used"]
    usage = row["usage"]
    assert usage["calls"] == 3 and usage["writes"] == 1 and usage["calls_7d"] == 3
    assert usage["last_client"] == flow.client_id and usage["last_write_tool"] == "write_file"
    assert usage["first_call_at"] <= usage["last_call_at"] and usage["last_write_at"]
    # never tokens or secrets in the report
    text = response.text + str(data)
    assert tokens["access_token"] not in text and tokens["refresh_token"] not in text and "secret_key" not in text

    # basic auth with the token as password renders the HTML table for a browser
    response = await env.client.get("/plesk/admin/usage", headers={**basic(TOKEN), "accept": "text/html,*/*"})
    assert response.status_code == 200 and response.headers["content-type"].startswith("text/html")
    assert "kunde" in response.text and "Test Client" in response.text and "write_file" in response.text
    # ?format=json wins over the accept header
    response = await env.client.get("/plesk/admin/usage?format=json", headers={**basic(TOKEN), "accept": "text/html"})
    assert response.headers["content-type"].startswith("application/json")

    # after disconnecting, the account stays listed with its counters but without connections
    await env.services.store.revoke_login("kunde")
    data = (await env.client.get("/plesk/admin/usage", headers={"authorization": f"Bearer {TOKEN}"})).json()
    assert data["totals"]["connected"] == 0 and data["accounts"][0]["connections"] == [] and data["accounts"][0]["usage"]["calls"] == 3


async def test_admin_usage_rate_limit(env: Env):
    enable(env)
    for _ in range(20):
        assert (await env.client.get("/plesk/admin/usage", headers={"authorization": "Bearer wrong"})).status_code == 401
    # the 21st attempt in the window is refused even with the right token
    response = await env.client.get("/plesk/admin/usage", headers={"authorization": f"Bearer {TOKEN}"})
    assert response.status_code == 429 and response.headers["retry-after"] == "300"


def test_admin_token_too_short(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from conftest import base_env

    for key, value in base_env(tmp_path).items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("ADMIN_API_TOKEN", "short")
    from pleskmcp.config import ConfigError, Settings

    with pytest.raises(ConfigError, match="ADMIN_API_TOKEN"):
        Settings.load()
    monkeypatch.setenv("ADMIN_API_TOKEN", TOKEN)
    assert Settings.load().admin_api_token == TOKEN
