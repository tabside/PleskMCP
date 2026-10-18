"""SSL tools: status probe, Let's Encrypt via the REST CLI gateway, guards (DNS, valid cert, cooldown, scope)."""

from __future__ import annotations

import dataclasses
import datetime as dt
import ipaddress

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

import pleskmcp.certs as certs
from conftest import Env, OAuthFlow, call_tool, tool_text

pytestmark = pytest.mark.anyio

DOC_NET = ipaddress.ip_network("192.0.2.0/24")  # documentation range, treated as "public" in these tests


def make_der(names: list[str], *, issuer_org: str = "Let's Encrypt", days: int = 60) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0])])
    issuer = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, issuer_org), x509.NameAttribute(NameOID.COMMON_NAME, "R10")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


@pytest.fixture
def net(monkeypatch: pytest.MonkeyPatch):
    """Fake DNS and TLS: dns maps host -> addresses, served maps host -> probe result."""
    state = {"dns": {"example.com": ["192.0.2.1"], "www.example.com": ["192.0.2.1"]}, "served": {}, "probes": []}

    async def resolve(host: str) -> list[str]:
        return list(state["dns"].get(host, []))

    async def probe(host: str, address: str):
        state["probes"].append((host, address))
        return state["served"].get(host, {"reachable": False, "error": "ConnectionRefusedError"})

    def public(address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return ip in DOC_NET or ip.is_global

    monkeypatch.setattr(certs, "resolve_host", resolve)
    monkeypatch.setattr(certs, "probe_certificate", probe)
    monkeypatch.setattr(certs, "is_public", public)
    return state


def valid(names: list[str], days: int = 60) -> dict:
    return {"reachable": True, **certs.describe_certificate(make_der(names, days=days)), "trusted": True}


def test_describe_and_covers():
    info = certs.describe_certificate(make_der(["example.com", "www.example.com"], days=45))
    assert info["names"] == ["example.com", "www.example.com"]
    assert info["lets_encrypt"] is True and info["expired"] is False and 43 <= info["days_left"] <= 45
    assert certs.covers(["*.example.com"], "www.example.com")
    assert not certs.covers(["*.example.com"], "example.com")
    assert not certs.covers(["*.example.com"], "a.b.example.com")


async def test_status_reports_certificate(env: Env, flow: OAuthFlow, net):
    net["served"]["example.com"] = valid(["example.com", "www.example.com"])
    access = (await flow.full_login())["access_token"]
    result = await call_tool(env.client, access, "ssl_status", {"domain": "example.com"})
    sc = result["structuredContent"]
    assert sc["domain"] == "example.com" and all(d["ok"] for d in sc["dns"])
    first = sc["certificates"][0]
    assert first["host"] == "example.com" and first["trusted"] and "Gültiges Zertifikat" in first["summary"]
    assert sc["issue_available"] is True
    # www serves nothing in the fake
    assert "nicht erreichbar" in sc["certificates"][1]["summary"]


async def test_status_never_probes_private_addresses(env: Env, flow: OAuthFlow, net):
    net["dns"]["example.com"] = ["10.0.0.5"]
    net["dns"]["www.example.com"] = ["127.0.0.1"]
    access = (await flow.full_login())["access_token"]
    result = await call_tool(env.client, access, "ssl_status", {"domain": "example.com"})
    sc = result["structuredContent"]
    assert net["probes"] == []
    assert all(not d["ok"] and "nicht öffentliche" in d["problem"] for d in sc["dns"])


async def test_foreign_domain_refused(env: Env, flow: OAuthFlow, net):
    access = (await flow.full_login())["access_token"]
    result = await call_tool(env.client, access, "ssl_issue", {"domain": "other.example", "confirm": True})
    assert result["isError"] and "gehört nicht" in tool_text(result)
    assert env.plesk.cli_calls == []


async def test_issue_preview_then_confirm(env: Env, flow: OAuthFlow, net):
    access = (await flow.full_login())["access_token"]
    preview = await call_tool(env.client, access, "ssl_issue", {"domain": "example.com"})
    sc = preview["structuredContent"]
    assert sc["preview"] is True and sc["names"] == ["example.com", "www.example.com"] and "blocked" not in sc
    assert env.plesk.cli_calls == []

    done = await call_tool(env.client, access, "ssl_issue", {"domain": "example.com", "confirm": True})
    assert done["structuredContent"]["issued"] is True, tool_text(done)
    call = env.plesk.cli_calls[-1]
    assert call["utility"] == "extension"
    assert call["params"] == ["--exec", "letsencrypt", "cli.php", "-d", "example.com", "-d", "www.example.com", "-m", "ssl@example.com"]

    # second attempt within the cooldown is refused before Plesk is called
    again = await call_tool(env.client, access, "ssl_issue", {"domain": "example.com", "confirm": True})
    assert again["isError"] and "kürzlich" in tool_text(again)
    assert len(env.plesk.cli_calls) == 1


async def test_www_left_out_when_not_pointing_here(env: Env, flow: OAuthFlow, net):
    net["dns"]["www.example.com"] = ["192.0.2.99"]
    access = (await flow.full_login())["access_token"]
    sc = (await call_tool(env.client, access, "ssl_issue", {"domain": "example.com"}))["structuredContent"]
    assert sc["names"] == ["example.com"] and "www.example.com" in sc["notes"][0]
    # explicitly requested www that does not point here blocks
    forced = await call_tool(env.client, access, "ssl_issue", {"domain": "example.com", "include_www": True, "confirm": True})
    assert forced["isError"] and "nicht (nur) auf diesen Server" in tool_text(forced)
    assert env.plesk.cli_calls == []


async def test_no_reissue_of_valid_certificate(env: Env, flow: OAuthFlow, net):
    net["served"]["example.com"] = valid(["example.com", "www.example.com"], days=80)
    access = (await flow.full_login())["access_token"]
    result = await call_tool(env.client, access, "ssl_issue", {"domain": "example.com", "confirm": True})
    assert result["isError"] and "bereits ein gültiges Zertifikat" in tool_text(result)
    assert env.plesk.cli_calls == []
    # close to expiry: allowed
    net["served"]["example.com"] = valid(["example.com", "www.example.com"], days=10)
    result = await call_tool(env.client, access, "ssl_issue", {"domain": "example.com", "confirm": True})
    assert result["structuredContent"]["issued"] is True


async def test_plesk_failure_is_explained(env: Env, flow: OAuthFlow, net):
    env.plesk.cli_fail = True
    access = (await flow.full_login())["access_token"]
    result = await call_tool(env.client, access, "ssl_issue", {"domain": "example.com", "confirm": True})
    assert result["isError"] and "kein Zertifikat ausstellen" in tool_text(result) and "acme-challenge" in tool_text(result)


async def test_scope_required(env: Env, flow: OAuthFlow, net):
    tokens = await flow.full_login(scope="files:read files:write dns:read")
    result = await call_tool(env.client, tokens["access_token"], "ssl_issue", {"domain": "example.com", "confirm": True})
    assert result["isError"] and "ssl:write" in tool_text(result)
    # data.example's profile (KI-Zugang) has no ssl:write at all
    tokens = await flow.full_login()
    result = await call_tool(env.client, tokens["access_token"], "ssl_issue", {"domain": "data.example"})
    assert result["isError"] and "erlaubt ssl:write nicht" in tool_text(result)


async def test_disabled(env: Env, flow: OAuthFlow, net, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(env.services.runner, "_settings", dataclasses.replace(env.settings, ssl_issue_enabled=False))
    access = (await flow.full_login())["access_token"]
    result = await call_tool(env.client, access, "ssl_issue", {"domain": "example.com"})
    assert result["isError"] and "nicht eingeschaltet" in tool_text(result)
