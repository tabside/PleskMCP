"""End-to-end OAuth flow and MCP tool calls against the fake Plesk API and in-process helper."""

from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from conftest import OAuthFlow, Env, call_tool, mcp_call, tool_text

pytestmark = pytest.mark.anyio


async def test_discovery_documents(env: Env):
    r = await env.client.get("/.well-known/oauth-protected-resource/plesk/mcp")
    assert r.status_code == 200
    prm = r.json()
    assert prm["resource"] == "https://mcp.example.com/plesk/mcp"
    assert prm["authorization_servers"] == ["https://mcp.example.com/plesk"]
    r = await env.client.get("/.well-known/oauth-authorization-server/plesk")
    meta = r.json()
    assert meta["issuer"] == "https://mcp.example.com/plesk"
    assert meta["token_endpoint"] == "https://mcp.example.com/plesk/token"
    assert meta["registration_endpoint"] == "https://mcp.example.com/plesk/register"
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["client_id_metadata_document_supported"] is True
    assert meta["authorization_response_iss_parameter_supported"] is True
    r = await env.client.get("/.well-known/openid-configuration/plesk")
    assert r.json()["issuer"] == meta["issuer"]
    r = await mcp_call(env.client, None, "initialize")
    assert r.status_code == 401
    assert 'resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/plesk/mcp"' in r.headers["www-authenticate"]


async def test_full_flow_and_tools(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    assert tokens["token_type"] == "Bearer" and tokens["refresh_token"]
    access = tokens["access_token"]

    result = await call_tool(env.client, access, "list_domains", {})
    names = [d["name"] for d in result["structuredContent"]["domains"]]
    # plain.example has no plan or add-on with an access profile and is not listed
    assert names == ["example.com", "data.example", "shop.example.com"]
    assert all("files:read" in d["scopes"] for d in result["structuredContent"]["domains"])

    listing = await call_tool(env.client, access, "list_dir", {"domain": "example.com", "path": ""})
    assert {e["name"] for e in listing["structuredContent"]["entries"]} == {"index.php", "wp-config.php", "assets"}

    read = await call_tool(env.client, access, "read_file", {"domain": "example.com", "path": "index.php"})
    assert "echo 'hi'" in read["structuredContent"]["content"]

    written = await call_tool(env.client, access, "write_file", {"domain": "example.com", "path": "index.php", "content": "<?php echo 'new';"})
    assert written["structuredContent"]["backup"]
    assert (env.vhosts / "example.com" / "httpdocs" / "index.php").read_text() == "<?php echo 'new';"

    deleted = await call_tool(env.client, access, "delete_file", {"domain": "example.com", "path": "wp-config.php"})
    trash_id = deleted["structuredContent"]["trash_id"]
    assert not (env.vhosts / "example.com" / "httpdocs" / "wp-config.php").exists()
    restored = await call_tool(env.client, access, "restore_file", {"domain": "example.com", "trash_id": trash_id})
    assert restored["structuredContent"]["path"] == "wp-config.php"

    log = await call_tool(env.client, access, "search_log", {"domain": "example.com", "log": "error_log", "pattern": "broken"})
    assert log["structuredContent"]["lines"] == ["error: broken thing"]

    # every helper call ran as the subscription's system user
    assert {c["sysuser"] for c in env.executor.calls} == {"example_sys"}
    # the customer key was created and stored encrypted, not in clear
    row = await env.services.store.get_account("kunde")
    assert row.secret_key_enc and not row.secret_key_enc.startswith("key-")


async def test_foreign_domain_rejected(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    result = await call_tool(env.client, tokens["access_token"], "read_file", {"domain": "other.example", "path": "secret.txt"})
    assert result["isError"] is True
    assert "gehört nicht zu diesem Konto" in tool_text(result)
    assert env.executor.calls == []
    # the domain name is matched exactly, not as a prefix
    result = await call_tool(env.client, tokens["access_token"], "list_dir", {"domain": "example.com.evil", "path": ""})
    assert result["isError"] is True


async def test_traversal_via_tool_rejected(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    result = await call_tool(env.client, tokens["access_token"], "read_file", {"domain": "example.com", "path": "../../other.example/httpdocs/secret.txt"})
    assert result["isError"] is True and "'..'" in tool_text(result)


async def test_expired_and_revoked_tokens(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    assert (await mcp_call(env.client, access, "tools/list")).status_code == 200

    # expired
    from sqlalchemy import text

    async with env.services.store.engine.begin() as conn:
        await conn.execute(text("UPDATE tokens SET expires_at=:t WHERE kind='access'").bindparams(t=int(time.time()) - 1))
    r = await mcp_call(env.client, access, "tools/list")
    assert r.status_code == 401

    # fresh token, then revoked through the CLI path
    tokens = await flow.full_login()
    assert (await mcp_call(env.client, tokens["access_token"], "tools/list")).status_code == 200
    await env.services.accounts.revoke_login("kunde")
    assert (await mcp_call(env.client, tokens["access_token"], "tools/list")).status_code == 401
    r = await flow.refresh(tokens["refresh_token"])
    assert r.status_code == 400 and r.json()["error"] == "invalid_grant"

    # garbage token
    assert (await mcp_call(env.client, "nope", "tools/list")).status_code == 401


async def test_refresh_rotation_and_reuse_detection(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    r = await flow.refresh(tokens["refresh_token"])
    assert r.status_code == 200
    second = r.json()
    assert second["access_token"] != tokens["access_token"] and second["refresh_token"] != tokens["refresh_token"]
    assert (await mcp_call(env.client, second["access_token"], "tools/list")).status_code == 200
    # replaying the old refresh token revokes the whole family
    r = await flow.refresh(tokens["refresh_token"])
    assert r.status_code == 400
    assert (await mcp_call(env.client, second["access_token"], "tools/list")).status_code == 401
    r = await flow.refresh(second["refresh_token"])
    assert r.status_code == 400


async def test_admin_reseller_additional_user_rejected(env: Env, flow: OAuthFlow):
    await flow.register()
    for login, password, text in [
        ("admin", "adminpw", "Nur Kunden-Hauptlogins"),
        ("reseller1", "resellerpw", "Nur Kunden-Hauptlogins"),
        ("zusatz", "zusatzpw", "Nur Kunden-Hauptlogins"),
        ("gesperrt", "pw", "gesperrt"),
        ("kunde", "falsch", "falsch"),
        ("niemand", "x", "falsch"),
    ]:
        location, _ = await flow.authorize()
        response = await flow.login(location, login, password)
        assert response.status_code == 401, (login, response.status_code)
        assert text in response.text
    assert await env.services.store.get_account("admin") is None
    assert await env.services.store.token_summary() == []


async def test_deny_redirects_with_error(env: Env, flow: OAuthFlow):
    await flow.register()
    location, _ = await flow.authorize()
    response = await flow.login(location, "", "", action="deny")
    assert response.status_code == 302
    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["error"] == ["access_denied"] and query["state"] == ["xyz"]


async def test_csrf_and_expired_request(env: Env, flow: OAuthFlow):
    await flow.register()
    location, _ = await flow.authorize()
    req = parse_qs(urlparse(location).query)["req"][0]
    response = await env.client.post("/plesk/login", data={"req": req, "csrf": "wrong", "login": "kunde", "password": "geheim", "action": "allow"})
    assert response.status_code == 400
    response = await env.client.post("/plesk/login", data={"req": "missing", "csrf": "x", "login": "kunde", "password": "geheim"})
    assert response.status_code == 400
    assert env.plesk.calls == []


async def test_login_rate_limit(env: Env, flow: OAuthFlow):
    await flow.register()
    for _ in range(3):
        location, _ = await flow.authorize()
        assert (await flow.login(location, "kunde", "falsch")).status_code == 401
    location, _ = await flow.authorize()
    response = await flow.login(location, "kunde", "geheim")
    assert response.status_code == 429
    assert "Zu viele" in response.text
    # the correct password was not even sent to Plesk
    assert all(call[0] != "kunde" or call[1] != "webspace" for call in env.plesk.calls)


async def test_plesk_failure_budget(env: Env, flow: OAuthFlow, monkeypatch):
    env.services.limiter._settings = env.settings.__class__(**{**env.settings.__dict__, "plesk_fail_budget": 2})
    await flow.register()
    for login in ("a1", "a2"):
        location, _ = await flow.authorize()
        assert (await flow.login(location, login, "x")).status_code == 401
    location, _ = await flow.authorize()
    assert (await flow.login(location, "a3", "x")).status_code == 429


async def test_resource_parameter(env: Env, flow: OAuthFlow):
    await flow.register()
    # wrong resource -> invalid_target redirect
    verifier_unused = None
    response = await env.client.get(
        "/plesk/authorize",
        params={
            "response_type": "code",
            "client_id": flow.client_id,
            "redirect_uri": flow.redirect_uri,
            "code_challenge": "a" * 43,
            "code_challenge_method": "S256",
            "resource": "https://evil.example/mcp",
        },
    )
    assert response.status_code == 302
    assert parse_qs(urlparse(response.headers["location"]).query)["error"] == ["invalid_target"]
    # no resource at all -> token is bound to this server anyway
    location, verifier = await flow.authorize(resource=None)
    response = await flow.login(location, "kunde", "geheim")
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    token_response = await flow.token(code, verifier, resource=None)
    assert token_response.status_code == 200
    assert (await mcp_call(env.client, token_response.json()["access_token"], "tools/list")).status_code == 200
    del verifier_unused


async def test_scope_enforced_for_writes(env: Env, flow: OAuthFlow):
    await flow.register(scope="files:read")
    location, verifier = await flow.authorize(scope="files:read")
    response = await flow.login(location, "kunde", "geheim")
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    tokens = (await flow.token(code, verifier)).json()
    assert tokens["scope"] == "files:read"
    result = await call_tool(env.client, tokens["access_token"], "write_file", {"domain": "example.com", "path": "x.txt", "content": "x"})
    assert result["isError"] and "files:write" in tool_text(result)
    result = await call_tool(env.client, tokens["access_token"], "list_dir", {"domain": "example.com"})
    assert not result.get("isError")


async def test_account_deactivated_after_plesk_rejects_key(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    env.plesk.users["kunde"].status = 16  # customer suspended in Plesk
    result = await call_tool(env.client, tokens["access_token"], "list_dir", {"domain": "example.com"})
    assert result["isError"] and "nicht mehr aktiv" in tool_text(result)
    assert (await env.services.store.get_account("kunde")).status == "inactive"
    assert (await mcp_call(env.client, tokens["access_token"], "tools/list")).status_code == 401


async def test_suspended_subscription_disappears(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    env.plesk.users["kunde"].domains[0]["suspended"] = True
    result = await call_tool(env.client, tokens["access_token"], "list_domains", {})
    assert [d["name"] for d in result["structuredContent"]["domains"]] == ["data.example"]


async def test_customer_key_creation_not_permitted(env: Env, flow: OAuthFlow):
    env.plesk.users["kunde"].can_create_key = False
    await flow.register()
    location, _ = await flow.authorize()
    response = await flow.login(location, "kunde", "geheim")
    assert response.status_code == 503
    assert "Serverkonfiguration" in response.text


async def test_cimd_client(env: Env, flow: OAuthFlow):
    client_id = "https://client.example/oauth/client.json"
    document = {
        "client_id": client_id,
        "client_name": "Metadata Client",
        "redirect_uris": ["https://client.example/callback"],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    }
    fetched = []

    def handler(request: httpx.Request) -> httpx.Response:
        fetched.append(str(request.url))
        if str(request.url) == client_id:
            return httpx.Response(200, json=document)
        return httpx.Response(404)

    env.services.provider._cimd_transport = httpx.MockTransport(handler)
    flow.client_id = client_id
    flow.redirect_uri = "https://client.example/callback"
    location, verifier = await flow.authorize()
    page = await env.client.get(location)
    assert "Metadata Client" in page.text
    response = await flow.login(location, "kunde", "geheim")
    assert response.status_code == 302
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    token_response = await flow.token(code, verifier)
    assert token_response.status_code == 200, token_response.text
    assert fetched == [client_id]  # cached afterwards
    assert (await mcp_call(env.client, token_response.json()["access_token"], "tools/list")).status_code == 200

    # a document whose client_id does not match its URL is refused
    document["client_id"] = "https://client.example/other.json"
    from sqlalchemy import text

    async with env.services.store.engine.begin() as conn:
        await conn.execute(text("DELETE FROM clients"))
    response = await env.client.get(
        "/plesk/authorize",
        params={"response_type": "code", "client_id": client_id, "redirect_uri": flow.redirect_uri, "code_challenge": "a" * 43, "code_challenge_method": "S256"},
    )
    assert response.status_code == 400


async def test_registration_rejects_bad_redirect(env: Env):
    response = await env.client.post(
        "/plesk/register",
        json={"client_name": "x", "redirect_uris": ["http://attacker.example/cb"], "token_endpoint_auth_method": "none"},
    )
    assert response.status_code == 400


async def test_write_limit_enforced_server_side(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    result = await call_tool(env.client, tokens["access_token"], "write_file", {"domain": "example.com", "path": "big.txt", "content": "x" * (env.settings.write_max_bytes + 1)})
    assert result["isError"] and "Schreiblimit" in tool_text(result)
    assert all(c["op"] != "write_file" for c in env.executor.calls)


async def test_audit_log_has_no_secrets(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    await call_tool(env.client, tokens["access_token"], "write_file", {"domain": "example.com", "path": "note.txt", "content": "TOP-SECRET-CONTENT"})
    log = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert "TOP-SECRET-CONTENT" not in log and "geheim" not in log and tokens["access_token"] not in log
    events = [json.loads(line)["event"] for line in log.splitlines()]
    assert "login_success" in events and "tool_write" in events and "token_issued" in events
