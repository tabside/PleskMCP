"""Test fixtures: a fake Plesk XML API, an in-process helper executor and the app.

The helper refuses to run as root and checks file ownership, so run the test
suite as an unprivileged user (CI does, see .github/workflows).
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import secrets
import xml.etree.ElementTree as ET
from collections import namedtuple
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from cryptography.fernet import Fernet

ROOT = Path(__file__).resolve().parent.parent
HELPER_PATH = ROOT / "helper" / "pleskmcp_helper.py"


def load_helper_module():
    spec = importlib.util.spec_from_file_location("pleskmcp_helper", HELPER_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def anyio_backend():
    return "asyncio"


# --------------------------------------------------------------------- fake Plesk
@dataclass
class FakeUser:
    password: str
    type: str = "customer"  # customer | admin | reseller | smbuser
    status: int = 0
    name: str = "Test Customer"
    domains: list[dict[str, Any]] = field(default_factory=list)
    can_create_key: bool = True


class FakePlesk:
    """Imitates the subset of agent.php used by the service."""

    def __init__(self):
        self.users: dict[str, FakeUser] = {}
        self.keys: dict[str, str] = {}  # key -> login
        self.calls: list[tuple[str | None, str]] = []
        self.dns: dict[int, dict[str, Any]] = {}  # record id -> {site_id, type, host, value, opt}
        self.next_dns_id = 1000

    def add_dns(self, site_id: int, rtype: str, host: str, value: str, opt: str = "") -> int:
        self.next_dns_id += 1
        self.dns[self.next_dns_id] = {"site_id": site_id, "type": rtype, "host": host, "value": value, "opt": opt}
        return self.next_dns_id

    def _owned_site_ids(self, user: FakeUser) -> set[int]:
        return {100 + i for i, d in enumerate(user.domains) if d.get("kind", "webspace") == "webspace"} | {
            200 + i for i, d in enumerate(user.domains) if d.get("kind") == "site"
        }

    def _handle_dns(self, root: ET.Element, user: FakeUser) -> httpx.Response:
        owned = self._owned_site_ids(user)
        op = list(root.find("./dns"))[0]
        denied = "<result><status>error</status><errcode>1006</errcode><errtext>Permission denied</errtext></result>"

        def rec_xml(rid: int, r: dict[str, Any]) -> str:
            return (
                f"<result><status>ok</status><id>{rid}</id><data><site-id>{r['site_id']}</site-id><type>{r['type']}</type>"
                f"<host>{r['host']}</host><value>{r['value']}</value><opt>{r['opt']}</opt></data></result>"
            )

        if op.tag == "get_rec":
            site_id = op.find("./filter/site-id")
            rec_id = op.find("./filter/id")
            if site_id is not None:
                sid = int(site_id.text)
                if sid not in owned:
                    return self._ok(f"<dns><get_rec>{denied}</get_rec></dns>")
                body = "".join(rec_xml(i, r) for i, r in self.dns.items() if r["site_id"] == sid)
                return self._ok(f"<dns><get_rec>{body}</get_rec></dns>")
            if rec_id is not None:
                rid = int(rec_id.text)
                r = self.dns.get(rid)
                if r is None:
                    return self._ok("<dns><get_rec><result><status>error</status><errcode>1013</errcode><errtext>not found</errtext></result></get_rec></dns>")
                if r["site_id"] not in owned:
                    return self._ok(f"<dns><get_rec>{denied}</get_rec></dns>")
                return self._ok(f"<dns><get_rec>{rec_xml(rid, r)}</get_rec></dns>")
        if op.tag == "add_rec":
            sid = int(op.find("site-id").text)
            if sid not in owned:
                return self._ok(f"<dns><add_rec>{denied}</add_rec></dns>")
            rid = self.add_dns(sid, op.find("type").text, op.find("host").text or "", op.find("value").text or "", op.find("opt").text or "")
            return self._ok(f"<dns><add_rec><result><status>ok</status><id>{rid}</id></result></add_rec></dns>")
        if op.tag == "del_rec":
            rid = int(op.find("./filter/id").text)
            r = self.dns.get(rid)
            if r is None or r["site_id"] not in owned:
                return self._ok(f"<dns><del_rec>{denied}</del_rec></dns>")
            del self.dns[rid]
            return self._ok(f"<dns><del_rec><result><status>ok</status><id>{rid}</id></result></del_rec></dns>")
        return self._system_error(1014, "unsupported dns op")

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    @staticmethod
    def _system_error(code: int, text: str) -> httpx.Response:
        body = f'<?xml version="1.0"?><packet version="1.6.9.1"><system><status>error</status><errcode>{code}</errcode><errtext>{text}</errtext></system></packet>'
        return httpx.Response(200, content=body.encode(), headers={"content-type": "text/xml"})

    @staticmethod
    def _ok(inner: str) -> httpx.Response:
        body = f'<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1">{inner}</packet>'
        return httpx.Response(200, content=body.encode(), headers={"content-type": "text/xml"})

    def _handle(self, request: httpx.Request) -> httpx.Response:
        login = request.headers.get("HTTP_AUTH_LOGIN")
        password = request.headers.get("HTTP_AUTH_PASSWD")
        key = request.headers.get("KEY")
        if key:
            login = self.keys.get(key)
            if login is None:
                return self._system_error(1001, "wrong key")
        elif login is None or password is None:
            return self._system_error(1029, "Authentication method is not specified")
        user = self.users.get(login or "")
        if user is None or (not key and user.password != password):
            return self._system_error(1001, "Incorrect username or password.")
        if user.status != 0:
            return self._system_error(1011, "Access denied. Your account is locked.")
        root = ET.fromstring(request.content)
        operator = list(root)[0].tag
        self.calls.append((login, operator))
        if user.type == "smbuser":
            return self._ok(f"<{operator}><get><result><status>error</status><errcode>1006</errcode><errtext>Permission denied.</errtext></result></get></{operator}>")
        if operator == "customer":
            filt = root.find("./customer/get/filter/login")
            wanted = filt.text if filt is not None else login
            if user.type != "customer" or wanted != login:
                return self._ok("<customer><get><result><status>error</status><errcode>1013</errcode><errtext>Customer does not exist.</errtext></result></get></customer>")
            return self._ok(
                f"<customer><get><result><status>ok</status><filter-id>{login}</filter-id><id>96</id><data><gen_info>"
                f"<pname>{user.name}</pname><login>{login}</login><status>{user.status}</status></gen_info></data></result></get></customer>"
            )
        if operator == "webspace":
            results = []
            for i, d in enumerate(user.domains):
                if d.get("kind", "webspace") != "webspace":
                    continue
                if d.get("suspended"):
                    results.append(f"<result><status>error</status><errcode>1006</errcode><errtext>Permission denied.</errtext><filter-id>{100 + i}</filter-id><id>{100 + i}</id></result>")
                    continue
                results.append(
                    f"<result><status>ok</status><filter-id>{100 + i}</filter-id><id>{100 + i}</id><data><gen_info><name>{d['name']}</name>"
                    f"<status>0</status><guid>guid-{i}</guid></gen_info><hosting><vrt_hst>"
                    f"<property><name>ftp_login</name><value>{d['sysuser']}</value></property>"
                    f"<property><name>www_root</name><value>{d['docroot']}</value></property>"
                    f"</vrt_hst></hosting></data></result>"
                )
            return self._ok(f"<webspace><get>{''.join(results)}</get></webspace>")
        if operator == "site":
            results = []
            for i, d in enumerate(user.domains):
                if d.get("kind") != "site":
                    continue
                parent_index = next(j for j, p in enumerate(user.domains) if p["name"] == d["webspace"])
                results.append(
                    f"<result><status>ok</status><filter-id>{200 + i}</filter-id><id>{200 + i}</id><data><gen_info><name>{d['name']}</name>"
                    f"<status>0</status><webspace-id>{100 + parent_index}</webspace-id></gen_info><hosting><vrt_hst>"
                    f"<property><name>www_root</name><value>{d['docroot']}</value></property>"
                    f"</vrt_hst></hosting></data></result>"
                )
            return self._ok(f"<site><get>{''.join(results)}</get></site>")
        if operator == "subdomain":
            return self._ok("<subdomain><get></get></subdomain>")
        if operator == "secret_key":
            if root.find("./secret_key/create") is not None:
                if not user.can_create_key:
                    return self._ok("<secret_key><create><result><status>error</status><errcode>1006</errcode><errtext>Permission denied.</errtext></result></create></secret_key>")
                new_key = "key-" + secrets.token_hex(8)
                self.keys[new_key] = login
                return self._ok(f"<secret_key><create><result><status>ok</status><key>{new_key}</key></result></create></secret_key>")
            if root.find("./secret_key/delete") is not None:
                return self._ok("<secret_key><delete><result><status>ok</status></result></delete></secret_key>")
        if operator == "dns":
            return self._handle_dns(root, user)
        if operator == "server":
            return self._ok("<server><get><result><status>ok</status><gen_info><server_name>fake</server_name></gen_info></result></get></server>")
        return self._system_error(1014, f"Parser error: unexpected element {operator}")


# ------------------------------------------------------------------ fake executor
class FakeExecutor:
    """Runs the helper in-process. `homes` maps system users to subscription directories."""

    def __init__(self, vhosts_base: Path, homes: dict[str, Path]):
        self.module = load_helper_module()
        self.module.VHOSTS_BASE = str(vhosts_base)
        self.homes = homes
        self.calls: list[dict[str, Any]] = []
        self.fail_with: Exception | None = None

    async def run(self, sysuser: str, request: dict[str, Any]) -> dict[str, Any]:
        from pleskmcp.remote import HelperError, RemoteError, validate_sysuser

        validate_sysuser(sysuser)
        if self.fail_with is not None:
            raise self.fail_with
        self.calls.append({"sysuser": sysuser, **request})
        home = self.homes.get(sysuser)
        if home is None:
            raise RemoteError("unknown system user")
        Passwd = namedtuple("Passwd", "pw_dir")
        original = self.module.pwd.getpwuid
        self.module.pwd.getpwuid = lambda uid: Passwd(str(home))
        try:
            result = self.module.handle(request)
        except self.module.HelperError as exc:
            raise HelperError(exc.code, exc.message)
        finally:
            self.module.pwd.getpwuid = original
        return json.loads(json.dumps(result))

    async def close(self) -> None:
        return None


# ------------------------------------------------------------------- app fixture
@dataclass
class Env:
    settings: Any
    services: Any
    app: Any
    plesk: FakePlesk
    executor: FakeExecutor
    vhosts: Path
    client: httpx.AsyncClient


def make_vhost(vhosts: Path, name: str) -> Path:
    home = vhosts / name
    (home / "httpdocs").mkdir(parents=True)
    (home / "logs").mkdir()
    return home


@pytest.fixture
async def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    if os.getuid() == 0:
        pytest.skip("the helper refuses to run as root; run the tests as an unprivileged user")
    vhosts = tmp_path / "vhosts"
    vhosts.mkdir()
    home = make_vhost(vhosts, "example.com")
    other_home = make_vhost(vhosts, "other.example")
    (home / "httpdocs" / "index.php").write_text("<?php echo 'hi';\n")
    (home / "httpdocs" / "wp-config.php").write_text("define('DB_NAME', 'wp');\n")
    (home / "httpdocs" / "assets").mkdir()
    (home / "httpdocs" / "assets" / "style.css").write_text("body{}\n")
    (home / "logs" / "error_log").write_text("line one\nerror: broken thing\nline three\n")
    (other_home / "httpdocs" / "secret.txt").write_text("other customer data\n")

    env_vars = {
        "PUBLIC_BASE_URL": "https://mcp.example.com/plesk",
        "PLESK_URL": "https://plesk.example.com:8443",
        "PLESK_SSH_HOST": "plesk.example.com",
        "PLESK_SSH_USER": "pleskmcp",
        "PLESK_SSH_KEY_PATH": str(tmp_path / "key"),
        "PLESK_SSH_HOST_KEY": "ssh-ed25519 AAAA",
        "DATA_DIR": str(tmp_path / "data"),
        "DATA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "ACCOUNT_CHECK_MODE": "customer_key",
        "ACCOUNT_CHECK_TTL": "0",
        "ACCESS_TOKEN_TTL": "600",
        "LOGIN_FAIL_LIMIT_LOGIN": "3",
        "LOGIN_FAIL_LIMIT_IP": "6",
        "PLESK_FAIL_BUDGET": "100",
        "WRITE_MAX_BYTES": "100000",
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)

    from pleskmcp.config import Settings
    from pleskmcp.server import build_app, build_services

    plesk = FakePlesk()
    plesk.users["kunde"] = FakeUser(
        password="geheim",
        domains=[
            {"name": "example.com", "sysuser": "example_sys", "docroot": str(home / "httpdocs")},
            {"name": "shop.example.com", "kind": "site", "webspace": "example.com", "sysuser": "example_sys", "docroot": str(home / "shop")},
        ],
    )
    (home / "shop").mkdir()
    plesk.users["other"] = FakeUser(
        password="geheim2",
        domains=[{"name": "other.example", "sysuser": "other_sys", "docroot": str(other_home / "httpdocs")}],
    )
    plesk.users["admin"] = FakeUser(password="adminpw", type="admin")
    plesk.users["reseller1"] = FakeUser(password="resellerpw", type="reseller")
    plesk.users["zusatz"] = FakeUser(password="zusatzpw", type="smbuser")
    plesk.users["gesperrt"] = FakeUser(password="pw", status=16)

    plesk.add_dns(100, "A", "example.com.", "192.0.2.1")
    plesk.add_dns(100, "NS", "example.com.", "ns1.example.net.")
    plesk.add_dns(100, "MX", "example.com.", "mail.example.com.", "10")
    plesk.add_dns(100, "CNAME", "www.example.com.", "example.com.")
    plesk.add_dns(102, "A", "other.example.", "192.0.2.2")
    executor = FakeExecutor(vhosts, {"example_sys": home, "other_sys": other_home})
    settings = Settings.load()
    services = build_services(settings, plesk_transport=plesk.transport(), executor=executor)
    app = build_app(services)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.com", headers={"host": "mcp.example.com"}) as client:
            yield Env(settings, services, app, plesk, executor, vhosts, client)
    services.store.close()


# -------------------------------------------------------------------- oauth helper
def pkce_pair() -> tuple[str, str]:
    import hashlib

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


class OAuthFlow:
    def __init__(self, env: Env):
        self.env = env
        self.client = env.client
        self.redirect_uri = "http://127.0.0.1:43110/callback"
        self.client_id: str | None = None
        self.client_secret: str | None = None

    async def register(self, **extra: Any) -> dict[str, Any]:
        body = {
            "client_name": "Test Client",
            "redirect_uris": [self.redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }
        body.update(extra)
        response = await self.client.post("/plesk/register", json=body)
        assert response.status_code == 201, response.text
        data = response.json()
        self.client_id = data["client_id"]
        self.client_secret = data.get("client_secret")
        return data

    async def authorize(self, *, scope: str | None = "files:read files:write dns:read dns:write", resource: str | None = "https://mcp.example.com/plesk/mcp", state: str = "xyz") -> tuple[str, str]:
        verifier, challenge = pkce_pair()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        }
        if scope is not None:
            params["scope"] = scope
        if resource is not None:
            params["resource"] = resource
        response = await self.client.get("/plesk/authorize", params=params)
        assert response.status_code == 302, response.text
        return response.headers["location"], verifier

    async def login(self, location: str, login: str, password: str, *, action: str = "allow") -> httpx.Response:
        assert location.startswith("https://mcp.example.com/plesk/login?req=")
        page = await self.client.get(location)
        assert page.status_code == 200, page.text
        import re

        req = re.search(r'name="req" value="([^"]+)"', page.text).group(1)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        return await self.client.post(
            "/plesk/login",
            data={"req": req, "csrf": csrf, "login": login, "password": password, "action": action},
        )

    async def token(self, code: str, verifier: str, *, resource: str | None = "https://mcp.example.com/plesk/mcp") -> httpx.Response:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
            "code_verifier": verifier,
        }
        if self.client_secret:
            data["client_secret"] = self.client_secret
        if resource:
            data["resource"] = resource
        return await self.client.post("/plesk/token", data=data)

    async def refresh(self, refresh_token: str) -> httpx.Response:
        data = {"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": self.client_id}
        if self.client_secret:
            data["client_secret"] = self.client_secret
        return await self.client.post("/plesk/token", data=data)

    async def full_login(self, login: str = "kunde", password: str = "geheim") -> dict[str, Any]:
        if self.client_id is None:
            await self.register()
        location, verifier = await self.authorize()
        response = await self.login(location, login, password)
        assert response.status_code == 302, response.text
        callback = response.headers["location"]
        query = parse_qs(urlparse(callback).query)
        assert query["state"] == ["xyz"]
        assert query["iss"] == ["https://mcp.example.com/plesk"]
        token_response = await self.token(query["code"][0], verifier)
        assert token_response.status_code == 200, token_response.text
        return token_response.json()


@pytest.fixture
def flow(env: Env) -> OAuthFlow:
    return OAuthFlow(env)


async def mcp_call(client: httpx.AsyncClient, token: str | None, method: str, params: dict[str, Any] | None = None, *, request_id: int = 1) -> httpx.Response:
    headers = {"accept": "application/json, text/event-stream", "content-type": "application/json", "mcp-protocol-version": "2025-06-18"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params or {}}
    return await client.post("/plesk/mcp", json=body, headers=headers)


async def call_tool(client: httpx.AsyncClient, token: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    response = await mcp_call(client, token, "tools/call", {"name": name, "arguments": arguments})
    assert response.status_code == 200, response.text
    return response.json()["result"]


def tool_text(result: dict[str, Any]) -> str:
    return "\n".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
