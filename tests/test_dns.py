"""DNS tools: own zone only, SOA/NS locked, confirm required, zone backup before changes."""

from __future__ import annotations

import json

import pytest

from conftest import Env, OAuthFlow, call_tool, tool_text
from pleskmcp.dns import fqdn, relative_name

pytestmark = pytest.mark.anyio


def test_name_helpers():
    assert relative_name("www.example.com.", "example.com") == "www"
    assert relative_name("example.com.", "example.com") == "@"
    assert relative_name("_sip._tcp.example.com.", "example.com") == "_sip._tcp"
    assert fqdn("www", "example.com") == "www.example.com."
    assert fqdn("@", "example.com") == "example.com."
    assert fqdn("", "example.com") == "example.com."
    assert fqdn("www.example.com", "example.com") == "www.example.com."
    assert fqdn("www.example.com.", "example.com") == "www.example.com."
    from mcp.server.mcpserver.exceptions import ToolError

    with pytest.raises(ToolError):
        fqdn("www.other.example.", "example.com")
    with pytest.raises(ToolError):
        fqdn("bad host", "example.com")


async def test_list_and_locked(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    result = await call_tool(env.client, access, "dns_list_records", {"domain": "example.com"})
    records = result["structuredContent"]["records"]
    by_type = {r["type"]: r for r in records}
    assert by_type["A"]["name"] == "@" and by_type["CNAME"]["name"] == "www"
    assert by_type["NS"]["locked"] is True and by_type["A"]["locked"] is False
    assert by_type["MX"]["priority"] == 10
    # foreign zone and subdomain-less check
    result = await call_tool(env.client, access, "dns_list_records", {"domain": "other.example"})
    assert result["isError"] and "gehört nicht" in tool_text(result)


async def test_add_update_delete_with_backup(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    # preview without confirm changes nothing
    preview = await call_tool(env.client, access, "dns_add_record", {"domain": "example.com", "type": "A", "name": "test", "value": "192.0.2.50"})
    assert preview["structuredContent"]["preview"] is True
    assert not any(r["host"] == "test.example.com." for r in env.plesk.dns.values())

    added = await call_tool(env.client, access, "dns_add_record", {"domain": "example.com", "type": "A", "name": "test", "value": "192.0.2.50", "confirm": True})
    sc = added["structuredContent"]
    assert sc["host"] == "test.example.com." and sc["value"] == "192.0.2.50" and sc["backup"]
    new_id = sc["id"]
    assert env.plesk.dns[new_id] == {"site_id": 100, "type": "A", "host": "test.example.com.", "value": "192.0.2.50", "opt": ""}
    backups = list((env.vhosts / "example.com" / ".pleskmcp" / "dns" / "example.com").iterdir())
    assert len(backups) == 1
    exported = json.loads(backups[0].read_text())
    assert exported["domain"] == "example.com" and any(r["type"] == "NS" for r in exported["records"])

    mx = await call_tool(env.client, access, "dns_add_record", {"domain": "example.com", "type": "MX", "name": "@", "value": "mail2.example.com", "priority": 20, "confirm": True})
    assert mx["structuredContent"]["opt"] == "20" and mx["structuredContent"]["value"] == "mail2.example.com."
    srv = await call_tool(env.client, access, "dns_add_record", {"domain": "example.com", "type": "SRV", "name": "_sip._tcp", "value": "sip.example.com", "priority": 5, "weight": 1, "port": 5060, "confirm": True})
    assert srv["structuredContent"]["opt"] == "5 1 5060"

    updated = await call_tool(env.client, access, "dns_update_record", {"domain": "example.com", "record_id": new_id, "value": "192.0.2.51", "confirm": True})
    usc = updated["structuredContent"]
    assert usc["old_id"] == new_id and usc["id"] != new_id and env.plesk.dns[usc["id"]]["value"] == "192.0.2.51"
    assert new_id not in env.plesk.dns

    deleted = await call_tool(env.client, access, "dns_delete_record", {"domain": "example.com", "record_id": usc["id"], "confirm": True})
    assert deleted["structuredContent"]["deleted"]["value"] == "192.0.2.51"
    assert usc["id"] not in env.plesk.dns
    assert len(list((env.vhosts / "example.com" / ".pleskmcp" / "dns" / "example.com").iterdir())) == 5

    log = open(env.settings.audit_log_file, encoding="utf-8").read()
    events = [json.loads(line)["event"] for line in log.splitlines()]
    assert events.count("dns_add") == 3 and "dns_update" in events and "dns_delete" in events


async def test_locked_types_and_validation(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    ns_id = next(i for i, r in env.plesk.dns.items() if r["type"] == "NS")
    for args in [
        {"domain": "example.com", "type": "NS", "name": "sub", "value": "ns.example.net", "confirm": True},
        {"domain": "example.com", "type": "SOA", "name": "@", "value": "x", "confirm": True},
    ]:
        result = await call_tool(env.client, access, "dns_add_record", args)
        assert result["isError"]  # rejected by the type schema (Literal) before any API call
    assert not any(r["host"] == "sub.example.com." for r in env.plesk.dns.values())
    result = await call_tool(env.client, access, "dns_delete_record", {"domain": "example.com", "record_id": ns_id, "confirm": True})
    assert result["isError"] and "gesperrt" in tool_text(result)
    result = await call_tool(env.client, access, "dns_update_record", {"domain": "example.com", "record_id": ns_id, "value": "ns2.example.net", "confirm": True})
    assert result["isError"] and "gesperrt" in tool_text(result) or "nicht geändert" in tool_text(result)
    assert env.plesk.dns[ns_id]["value"] == "ns1.example.net."

    result = await call_tool(env.client, access, "dns_add_record", {"domain": "example.com", "type": "A", "name": "bad", "value": "not-an-ip", "confirm": True})
    assert result["isError"] and "IPv4" in tool_text(result)
    result = await call_tool(env.client, access, "dns_add_record", {"domain": "example.com", "type": "CNAME", "name": "www", "value": "elsewhere.example.net", "confirm": True})
    assert result["isError"] and "CNAME" in tool_text(result)
    result = await call_tool(env.client, access, "dns_add_record", {"domain": "example.com", "type": "A", "name": "x.other.example.", "value": "192.0.2.9", "confirm": True})
    assert result["isError"] and "Zone" in tool_text(result)


async def test_foreign_record_id_rejected(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    foreign_id = next(i for i, r in env.plesk.dns.items() if r["site_id"] == env.plesk.webspace_id("other.example"))
    for tool, args in [
        ("dns_delete_record", {"domain": "example.com", "record_id": foreign_id, "confirm": True}),
        ("dns_update_record", {"domain": "example.com", "record_id": foreign_id, "value": "192.0.2.3", "confirm": True}),
    ]:
        result = await call_tool(env.client, access, tool, args)
        assert result["isError"]
    assert env.plesk.dns[foreign_id]["value"] == "192.0.2.2"


async def test_dns_scope_required(env: Env, flow: OAuthFlow):
    await flow.register(scope="files:read dns:read")
    from urllib.parse import parse_qs, urlparse

    location, verifier = await flow.authorize(scope="files:read dns:read")
    response = await flow.login(location, "kunde", "geheim")
    code = parse_qs(urlparse(response.headers["location"]).query)["code"][0]
    tokens = (await flow.token(code, verifier)).json()
    result = await call_tool(env.client, tokens["access_token"], "dns_list_records", {"domain": "example.com"})
    assert not result.get("isError")
    result = await call_tool(env.client, tokens["access_token"], "dns_add_record", {"domain": "example.com", "type": "A", "name": "t", "value": "192.0.2.4", "confirm": True})
    assert result["isError"] and "dns:write" in tool_text(result)


async def test_dns_unavailable_in_login_only_mode(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    env.services.accounts._settings = env.settings.__class__(**{**env.settings.__dict__, "account_check_mode": "login_only"})
    result = await call_tool(env.client, tokens["access_token"], "dns_list_records", {"domain": "example.com"})
    assert result["isError"] and "login_only" in tool_text(result)


async def test_dns_restore_zone(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    # a change creates the export we restore to
    added = await call_tool(env.client, access, "dns_add_record", {"domain": "example.com", "type": "A", "name": "tmp", "value": "192.0.2.77", "confirm": True})
    export_id = added["structuredContent"]["backup"].rsplit("/", 1)[-1].replace(".json", "")
    exports = await call_tool(env.client, access, "dns_restore_zone", {"domain": "example.com"})
    assert export_id in [e["id"] for e in exports["structuredContent"]["exports"]]
    preview = await call_tool(env.client, access, "dns_restore_zone", {"domain": "example.com", "export_id": export_id})
    sc = preview["structuredContent"]
    assert sc["preview"] is True and [d["host"] for d in sc["delete"]] == ["tmp.example.com."] and sc["add"] == []
    assert any(r["host"] == "tmp.example.com." for r in env.plesk.dns.values())
    # the restore also re-creates records that were deleted since the export (the MX), and leaves NS alone
    mx_id = next(i for i, r in env.plesk.dns.items() if r["type"] == "MX")
    del env.plesk.dns[mx_id]
    ns_id = next(i for i, r in env.plesk.dns.items() if r["type"] == "NS")
    env.plesk.dns[ns_id]["value"] = "ns9.example.net."
    done = await call_tool(env.client, access, "dns_restore_zone", {"domain": "example.com", "export_id": export_id, "confirm": True})
    sc = done["structuredContent"]
    assert sc["preview"] is False and sc["deleted"] == 1 and sc["added"] == 1 and sc["errors"] == [] and sc["backup"]
    assert not any(r["host"] == "tmp.example.com." for r in env.plesk.dns.values())
    assert any(r["type"] == "MX" and r["value"] == "mail.example.com." for r in env.plesk.dns.values())
    assert env.plesk.dns[ns_id]["value"] == "ns9.example.net."
    result = await call_tool(env.client, access, "dns_restore_zone", {"domain": "example.com", "export_id": "20250101000000-nope00", "confirm": True})
    assert result["isError"]
    log = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert '"event": "dns_restore"' in log
