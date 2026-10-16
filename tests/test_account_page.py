"""/account page: login, connections, disconnect, stored DB credentials; login checkbox revoking other connections."""

from __future__ import annotations

import re

import pytest

from conftest import Env, OAuthFlow, call_tool, mcp_call, structured

pytestmark = pytest.mark.anyio


def csrf_of(html: str) -> str:
    return re.search(r'name="csrf" value="([^"]+)"', html).group(1)


async def account_login(env: Env, login: str = "kunde", password: str = "geheim"):
    page = await env.client.get("/plesk/account")
    assert page.status_code == 200 and "Plesk-Benutzername" in page.text
    cookie = page.cookies.get("pleskmcp_account")
    assert cookie
    assert "secure" in page.headers["set-cookie"].lower() and "httponly" in page.headers["set-cookie"].lower() and "samesite=strict" in page.headers["set-cookie"].lower()
    response = await env.client.post("/plesk/account/login", data={"csrf": csrf_of(page.text), "login": login, "password": password})
    return response


async def test_login_connections_and_disconnect(env: Env, flow: OAuthFlow):
    first = await flow.full_login()
    second_flow = OAuthFlow(env)
    await second_flow.register(client_name="Second App")
    second = await second_flow.full_login()
    assert (await mcp_call(env.client, first["access_token"], "tools/list")).status_code == 200

    # wrong password counts against the same limits as the OAuth login
    response = await account_login(env, password="falsch")
    assert response.status_code == 401 and "falsch" in response.text
    response = await account_login(env)
    assert response.status_code == 303
    page = await env.client.get("/plesk/account")
    assert "Konto kunde" in page.text and "Test Client" in page.text and "Second App" in page.text
    csrf = csrf_of(page.text)
    client_ids = re.findall(r'name="client_id" value="([^"]+)"', page.text)
    assert flow.client_id in client_ids and second_flow.client_id in client_ids

    # CSRF protection
    response = await env.client.post("/plesk/account/disconnect", data={"csrf": "wrong", "client_id": flow.client_id})
    assert response.status_code == 400
    assert (await mcp_call(env.client, first["access_token"], "tools/list")).status_code == 200

    # disconnect one client
    response = await env.client.post("/plesk/account/disconnect", data={"csrf": csrf, "client_id": flow.client_id})
    assert response.status_code == 200 and "getrennt" in response.text
    assert (await mcp_call(env.client, first["access_token"], "tools/list")).status_code == 401
    assert (await mcp_call(env.client, second["access_token"], "tools/list")).status_code == 200
    assert (await flow.refresh(first["refresh_token"])).status_code == 400

    # disconnect all: tokens gone, Plesk secret key deleted, account inactive until the next login
    response = await env.client.post("/plesk/account/disconnect", data={"csrf": csrf, "client_id": "*"})
    assert response.status_code == 200 and "API-Schlüssel" in response.text
    assert (await mcp_call(env.client, second["access_token"], "tools/list")).status_code == 401
    row = await env.services.store.get_account("kunde")
    assert row.secret_key_enc is None
    assert any(call == ("kunde", "secret_key") for call in env.plesk.calls[-5:])

    # logout drops the session
    response = await env.client.post("/plesk/account/logout", data={"csrf": csrf})
    assert response.status_code == 303
    page = await env.client.get("/plesk/account")
    assert "Plesk-Benutzername" in page.text

    # a new OAuth login works again and recreates the key
    again = await flow.full_login()
    assert (await mcp_call(env.client, again["access_token"], "tools/list")).status_code == 200


async def test_stored_db_credentials(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    response = await account_login(env)
    assert response.status_code == 303
    page = await env.client.get("/plesk/account")
    csrf = csrf_of(page.text)
    assert "<option value=\"legacy_db\">" in page.text  # databases Plesk lists for the account
    # a database Plesk does not know for this login is refused
    response = await env.client.post("/plesk/account/db", data={"csrf": csrf, "action": "save", "database": "someone_elses", "db_user": "u", "db_password": "p"})
    assert "gehört laut Plesk nicht" in response.text
    response = await env.client.post("/plesk/account/db", data={"csrf": csrf, "action": "save", "database": "legacy_db", "db_user": "legacy_user", "db_password": "legacy-pw"})
    assert response.status_code == 200 and "gespeichert" in response.text and "legacy-pw" not in response.text
    rows = await env.services.store.list_db_credentials("kunde", with_secret=True)
    assert rows[0]["database"] == "legacy_db" and "legacy-pw" not in rows[0]["password_enc"]

    listed = structured(await call_tool(env.client, access, "db_list", {"domain": "data.example"}))
    assert {d["database"]: d["credentials"] for d in listed["databases"]}["legacy_db"] == "stored"
    env.mysql.connect("legacy_db").executescript("CREATE TABLE t (a INT); INSERT INTO t VALUES (7);")
    rows = structured(await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "legacy_db", "sql": "SELECT a FROM t"}))
    assert rows["rows"] == [["7"]] and rows["credentials"] == "stored"
    # wrong stored password surfaces as a database error, never as the value
    response = await env.client.post("/plesk/account/db", data={"csrf": csrf, "action": "save", "database": "legacy_db", "db_user": "legacy_user", "db_password": "wrong"})
    result = await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "legacy_db", "sql": "SELECT a FROM t"})
    assert result["isError"] and "Access denied" in str(result) and "wrong" not in str(result)
    # delete
    response = await env.client.post("/plesk/account/db", data={"csrf": csrf, "action": "delete", "database": "legacy_db"})
    assert "gelöscht" in response.text
    assert await env.services.store.list_db_credentials("kunde") == []
    audit = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert "legacy-pw" not in audit and "db_credentials_saved" in audit


async def test_login_checkbox_revokes_other_connections(env: Env, flow: OAuthFlow):
    first = await flow.full_login()
    second = await flow.full_login(revoke_others=False)
    assert (await mcp_call(env.client, first["access_token"], "tools/list")).status_code == 200
    third = await flow.full_login(revoke_others=True)
    assert (await mcp_call(env.client, first["access_token"], "tools/list")).status_code == 401
    assert (await mcp_call(env.client, second["access_token"], "tools/list")).status_code == 401
    assert (await mcp_call(env.client, third["access_token"], "tools/list")).status_code == 200
    assert (await flow.refresh(first["refresh_token"])).status_code == 400
    page = await env.client.get("/plesk/login?req=nothing")
    assert page.status_code == 400
    location, _ = await flow.authorize()
    page = await env.client.get(location)
    assert 'name="revoke_others" value="1" checked' in page.text
