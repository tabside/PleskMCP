"""Test fixtures: fake Plesk XML API, fake Redis, SQLite store, in-process worker and the app.

No external service is needed: Redis is fakeredis (with Lua), the database is
SQLite through aiosqlite (the same SQLAlchemy models as Postgres), the worker
runs in-process and calls the helper module directly, MariaDB is replaced by
a small SQLite-backed stand-in for the mysql/mysqldump command line.

The helper refuses to run as root and checks file ownership, so run the test
suite as an unprivileged user (CI does, see .github/workflows).
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import importlib.util
import json
import os
import re
import secrets
import sqlite3
import xml.etree.ElementTree as ET
from collections import namedtuple
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

import fakeredis
import httpx
import pytest
from cryptography.fernet import Fernet
from fakeredis import aioredis as fakeaioredis

ROOT = Path(__file__).resolve().parent.parent
HELPER_PATH = ROOT / "helper" / "pleskmcp_helper.py"

GB = 1024 * 1024 * 1024

# plan guid -> name, as the administrator key would resolve them
PLAN_NAMES = {"guid-plan-ai": "AI Hosting", "guid-plan-standard": "Standard Hosting", "guid-addon-ki": "KI-Zugang"}

TEST_PROFILES = {
    "AI Hosting": {
        "scopes": ["files:read", "files:write", "dns:read", "dns:write"],
        "store_max_bytes": 64 * 1024 * 1024,
        "store_max_percent": 10,
        "backup_retention_days": 14,
        "trash_retention_days": 14,
    },
    "KI-Zugang": {
        "scopes": ["files:read", "files:write", "dns:read", "db:read", "db:write", "db:admin"],
        "max_databases_created": 2,
    },
    # keyed by GUID: works without the administrator key
    "guid-plan-standard": {"scopes": ["files:read"]},
}


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
    can_manage_db: bool = True
    base: int = 100  # webspace ids = base + index, site ids = base + 100 + index


class FakePlesk:
    """Imitates the subset of agent.php used by the service.

    Domain dicts: name, sysuser, docroot, kind (webspace|site), webspace (for
    sites), suspended, plan_guids (webspaces), quota (bytes, -1 unlimited),
    used (bytes), max_db.
    """

    def __init__(self):
        self.users: dict[str, FakeUser] = {}
        self.keys: dict[str, str] = {"admin-key": "admin"}  # key -> login
        self.calls: list[tuple[str | None, str]] = []
        self.dns: dict[int, dict[str, Any]] = {}
        self.next_dns_id = 1000
        self.databases: dict[int, dict[str, Any]] = {}  # id -> {name, webspace_id, type}
        self.db_users: dict[int, dict[str, Any]] = {}  # id -> {db_id, login, password}
        self.next_db_id = 500
        self.next_db_user_id = 700
        self.plan_names = dict(PLAN_NAMES)
        self.aliases: set[str] = set()
        self.created_customers: list[dict[str, Any]] = []  # signup: customer add calls (passwords are not kept)
        self.created_webspaces: list[dict[str, Any]] = []
        self.sessions: list[str] = []
        self.next_customer_id = 900
        self.next_webspace_id = 300

    # ---- helpers for tests
    def add_dns(self, site_id: int, rtype: str, host: str, value: str, opt: str = "") -> int:
        self.next_dns_id += 1
        self.dns[self.next_dns_id] = {"site_id": site_id, "type": rtype, "host": host, "value": value, "opt": opt}
        return self.next_dns_id

    def add_database(self, webspace_id: int, name: str) -> int:
        self.next_db_id += 1
        self.databases[self.next_db_id] = {"name": name, "webspace_id": webspace_id, "type": "mysql"}
        return self.next_db_id

    def webspace_id(self, name: str) -> int:
        for user in self.users.values():
            for i, d in enumerate(user.domains):
                if d["name"] == name and d.get("kind", "webspace") == "webspace":
                    return user.base + i
        raise KeyError(name)

    def _owned_ws(self, user: FakeUser) -> dict[int, dict[str, Any]]:
        return {user.base + i: d for i, d in enumerate(user.domains) if d.get("kind", "webspace") == "webspace"}

    def _owned_site_ids(self, user: FakeUser) -> set[int]:
        return set(self._owned_ws(user)) | {user.base + 100 + i for i, d in enumerate(user.domains) if d.get("kind") == "site"}

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

    @staticmethod
    def _err(op_path: str, code: int, text: str) -> str:
        return f"<result><status>error</status><errcode>{code}</errcode><errtext>{text}</errtext></result>"

    # ---- operators
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

    def _handle_database(self, root: ET.Element, user: FakeUser) -> httpx.Response:
        owned = self._owned_ws(user)
        op = list(root.find("./database"))[0]
        tag = op.tag
        denied = self._err(tag, 1006, "Permission denied.")
        if tag == "get-db":
            ws_name = op.find("./filter/webspace-name")
            if ws_name is None:
                return self._system_error(1014, "Parser error: webspace-name expected")
            ws_id = next((i for i, d in owned.items() if d["name"] == ws_name.text), None)
            if ws_id is None:
                return self._ok(f"<database><get-db>{denied}</get-db></database>")
            results = [
                f"<result><status>ok</status><filter-id>{ws_name.text}</filter-id><id>{dbid}</id><data><name>{db['name']}</name><type>{db['type']}</type><webspace-id>{ws_id}</webspace-id></data></result>"
                for dbid, db in self.databases.items()
                if db["webspace_id"] == ws_id
            ]
            if not results:
                results = [f"<result><status>ok</status><filter-id>{ws_name.text}</filter-id></result>"]
            return self._ok(f"<database><get-db>{''.join(results)}</get-db></database>")
        if tag == "add-db":
            if not user.can_manage_db:
                return self._ok(f"<database><add-db>{denied}</add-db></database>")
            ws_id = int(op.find("webspace-id").text)
            name = op.find("name").text or ""
            if ws_id not in owned:
                return self._ok(f"<database><add-db>{denied}</add-db></database>")
            if any(db["name"] == name for db in self.databases.values()):
                return self._ok(f"<database><add-db>{self._err(tag, 1007, 'Database with this name already exists.')}</add-db></database>")
            limit = owned[ws_id].get("max_db", 10)
            if limit >= 0 and sum(1 for db in self.databases.values() if db["webspace_id"] == ws_id) >= limit:
                return self._ok(f"<database><add-db>{self._err(tag, 1023, 'Databases limit is reached.')}</add-db></database>")
            dbid = self.add_database(ws_id, name)
            return self._ok(f"<database><add-db><result><status>ok</status><id>{dbid}</id></result></add-db></database>")
        if tag == "add-db-user":
            dbid = int(op.find("db-id").text)
            db = self.databases.get(dbid)
            if db is None or db["webspace_id"] not in owned or not user.can_manage_db:
                return self._ok(f"<database><add-db-user>{denied}</add-db-user></database>")
            self.next_db_user_id += 1
            self.db_users[self.next_db_user_id] = {"db_id": dbid, "login": op.find("login").text, "password": op.find("password").text}
            return self._ok(f"<database><add-db-user><result><status>ok</status><id>{self.next_db_user_id}</id></result></add-db-user></database>")
        if tag == "del-db":
            dbid = int(op.find("./filter/id").text)
            db = self.databases.get(dbid)
            if db is None or db["webspace_id"] not in owned or not user.can_manage_db:
                return self._ok(f"<database><del-db>{denied}</del-db></database>")
            del self.databases[dbid]
            for uid in [u for u, du in self.db_users.items() if du["db_id"] == dbid]:
                del self.db_users[uid]
            return self._ok(f"<database><del-db><result><status>ok</status><id>{dbid}</id></result></del-db></database>")
        if tag == "del-db-user":
            uid = int(op.find("./filter/id").text)
            du = self.db_users.get(uid)
            if du is None or self.databases.get(du["db_id"], {}).get("webspace_id") not in owned:
                return self._ok(f"<database><del-db-user>{denied}</del-db-user></database>")
            del self.db_users[uid]
            return self._ok(f"<database><del-db-user><result><status>ok</status><id>{uid}</id></result></del-db-user></database>")
        if tag == "get-db-users":
            dbid = int(op.find("./filter/db-id").text)
            db = self.databases.get(dbid)
            if db is None or db["webspace_id"] not in owned:
                return self._ok(f"<database><get-db-users>{denied}</get-db-users></database>")
            results = "".join(f"<result><status>ok</status><id>{uid}</id><login>{du['login']}</login></result>" for uid, du in self.db_users.items() if du["db_id"] == dbid)
            return self._ok(f"<database><get-db-users>{results}</get-db-users></database>")
        return self._system_error(1014, "unsupported database op")

    def _webspace_result(self, i: int, d: dict[str, Any], datasets: set[str], base: int = 100) -> str:
        parts = [f"<gen_info><name>{d['name']}</name><status>0</status><guid>guid-{i}</guid><real_size>{d.get('used', 0)}</real_size></gen_info>"]
        if "hosting" in datasets or not datasets:
            parts.append(
                "<hosting><vrt_hst>"
                f"<property><name>ftp_login</name><value>{d['sysuser']}</value></property>"
                f"<property><name>www_root</name><value>{d['docroot']}</value></property>"
                "</vrt_hst></hosting>"
            )
        if "limits" in datasets:
            parts.append(
                "<limits><overuse>not_suspend_notify</overuse>"
                f"<limit><name>disk_space</name><value>{d.get('quota', 5 * GB)}</value></limit>"
                f"<limit><name>max_db</name><value>{d.get('max_db', 10)}</value></limit></limits>"
            )
        if "subscriptions" in datasets:
            plans = "".join(f"<plan><plan-guid>{g}</plan-guid></plan>" for g in d.get("plan_guids", ["guid-plan-ai"]))
            parts.append(f"<subscriptions><subscription><locked>false</locked>{plans}</subscription></subscriptions>")
        return f"<result><status>ok</status><filter-id>{base + i}</filter-id><id>{base + i}</id><data>{''.join(parts)}</data></result>"

    # ---- administration (signup service): customer add/set/del, webspace add/del/get-by-name
    def _handle_customer_admin(self, root: ET.Element) -> httpx.Response:
        op = list(root.find("./customer"))[0]
        if op.tag == "get":
            name = op.find("./filter/login").text
            u = self.users.get(name)
            if u is None or u.type != "customer":
                return self._ok("<customer><get><result><status>error</status><errcode>1013</errcode><errtext>Customer does not exist.</errtext></result></get></customer>")
            return self._ok(f"<customer><get><result><status>ok</status><filter-id>{name}</filter-id><id>{u.base}</id><data><gen_info><pname>{u.name}</pname><login>{name}</login><status>{u.status}</status></gen_info></data></result></get></customer>")
        if op.tag == "add":
            gen = op.find("gen_info")
            name = gen.find("login").text
            if name in self.users:
                return self._ok("<customer><add><result><status>error</status><errcode>1007</errcode><errtext>Customer already exists.</errtext></result></add></customer>")
            self.next_customer_id += 1
            self.users[name] = FakeUser(password=gen.find("passwd").text, name=gen.find("pname").text, base=self.next_customer_id * 10)
            self.created_customers.append({k: (gen.find(k).text if gen.find(k) is not None else None) for k in ("cname", "pname", "login", "email", "phone", "address", "city", "pcode", "country", "external-id")})
            return self._ok(f"<customer><add><result><status>ok</status><id>{self.next_customer_id}</id></result></add></customer>")
        if op.tag == "set":
            name = op.find("./filter/login").text
            u = self.users.get(name)
            if u is None:
                return self._ok("<customer><set><result><status>error</status><errcode>1013</errcode><errtext>Customer does not exist.</errtext></result></set></customer>")
            u.status = int(op.find("./values/gen_info/status").text)
            return self._ok(f"<customer><set><result><status>ok</status><filter-id>{name}</filter-id><id>{u.base}</id></result></set></customer>")
        if op.tag == "del":
            name = op.find("./filter/login").text
            if name not in self.users:
                return self._ok("<customer><del><result><status>error</status><errcode>1013</errcode><errtext>Customer does not exist.</errtext></result></del></customer>")
            del self.users[name]
            return self._ok(f"<customer><del><result><status>ok</status><filter-id>{name}</filter-id></result></del></customer>")
        return self._system_error(1014, "unsupported customer op")

    def _handle_webspace_admin(self, root: ET.Element) -> httpx.Response | None:
        op = list(root.find("./webspace"))[0]
        if op.tag == "get" and op.find("./filter/name") is not None:
            name = op.find("./filter/name").text
            for u in self.users.values():
                for i, d in enumerate(u.domains):
                    if d.get("kind", "webspace") == "webspace" and d["name"] == name:
                        return self._ok(f"<webspace><get>{self._webspace_result(i, d, {'gen_info'}, u.base)}</get></webspace>")
            return self._ok("<webspace><get><result><status>error</status><errcode>1013</errcode><errtext>Webspace does not exist.</errtext></result></get></webspace>")
        if op.tag == "add":
            gen = op.find("gen_setup")
            name = gen.find("name").text
            owner = gen.find("owner-login").text
            u = self.users.get(owner)
            if u is None:
                return self._ok("<webspace><add><result><status>error</status><errcode>1013</errcode><errtext>Owner does not exist.</errtext></result></add></webspace>")
            if any(d["name"] == name for x in self.users.values() for d in x.domains):
                return self._ok("<webspace><add><result><status>error</status><errcode>1007</errcode><errtext>Domain already exists.</errtext></result></add></webspace>")
            props = {p.find("name").text: p.find("value").text for p in op.iterfind("./hosting/vrt_hst/property")}
            plan = op.find("plan-name").text if op.find("plan-name") is not None else None
            u.domains.append({"name": name, "sysuser": props.get("ftp_login", ""), "docroot": f"/var/www/vhosts/{name}/httpdocs", "plan_guids": ["guid-plan-ai"], "quota": 5 * GB})
            self.next_webspace_id += 1
            self.created_webspaces.append({"name": name, "owner": owner, "plan": plan, "ftp_login": props.get("ftp_login"), "ip": gen.find("ip_address").text, "id": self.next_webspace_id})
            return self._ok(f"<webspace><add><result><status>ok</status><id>{self.next_webspace_id}</id></result></add></webspace>")
        if op.tag == "del":
            name = op.find("./filter/name").text
            for u in self.users.values():
                for d in list(u.domains):
                    if d["name"] == name:
                        u.domains.remove(d)
                        return self._ok(f"<webspace><del><result><status>ok</status><filter-id>{name}</filter-id></result></del></webspace>")
            return self._ok("<webspace><del><result><status>error</status><errcode>1013</errcode><errtext>Webspace does not exist.</errtext></result></del></webspace>")
        return None

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
        if operator == "customer" and user.type == "admin":
            return self._handle_customer_admin(root)
        if operator == "customer":
            filt = root.find("./customer/get/filter/login")
            wanted = filt.text if filt is not None else login
            if user.type != "customer" or wanted != login:
                return self._ok("<customer><get><result><status>error</status><errcode>1013</errcode><errtext>Customer does not exist.</errtext></result></get></customer>")
            return self._ok(
                f"<customer><get><result><status>ok</status><filter-id>{login}</filter-id><id>96</id><data><gen_info>"
                f"<pname>{user.name}</pname><login>{login}</login><status>{user.status}</status></gen_info></data></result></get></customer>"
            )
        if operator == "server" and root.find("./server/create_session") is not None:
            if user.type != "admin":
                return self._ok("<server><create_session><result><status>error</status><errcode>1006</errcode><errtext>Permission denied.</errtext></result></create_session></server>")
            target = root.find("./server/create_session/login").text
            if target not in self.users:
                return self._ok("<server><create_session><result><status>error</status><errcode>1013</errcode><errtext>User does not exist.</errtext></result></create_session></server>")
            token = "sess-" + secrets.token_hex(6)
            self.sessions.append(token)
            return self._ok(f"<server><create_session><result><status>ok</status><id>{token}</id></result></create_session></server>")
        if operator == "site-alias":
            name = root.find("./site-alias/get/filter/name").text
            if name in self.aliases:
                return self._ok(f"<site-alias><get><result><status>ok</status><id>1</id><info><name>{name}</name></info></result></get></site-alias>")
            return self._ok("<site-alias><get><result><status>error</status><errcode>1013</errcode><errtext>Site alias does not exist.</errtext></result></get></site-alias>")
        if operator == "webspace" and user.type == "admin":
            handled = self._handle_webspace_admin(root)
            if handled is not None:
                return handled
        if operator == "site" and user.type == "admin" and root.find("./site/get/filter/name") is not None:
            name = root.find("./site/get/filter/name").text
            for u in self.users.values():
                for i, d in enumerate(u.domains):
                    if d.get("kind") == "site" and d["name"] == name:
                        return self._ok(f"<site><get><result><status>ok</status><filter-id>{name}</filter-id><id>{u.base + 100 + i}</id><data><gen_info><name>{name}</name></gen_info></data></result></get></site>")
            return self._ok("<site><get><result><status>error</status><errcode>1013</errcode><errtext>Site does not exist.</errtext></result></get></site>")
        if operator == "webspace":
            get = root.find("./webspace/get")
            dataset_el = get.find("dataset")
            datasets = {child.tag for child in dataset_el} if dataset_el is not None else set()
            wanted_id = get.find("./filter/id")
            results = []
            for i, d in enumerate(user.domains):
                if d.get("kind", "webspace") != "webspace":
                    continue
                if wanted_id is not None and int(wanted_id.text) != user.base + i:
                    continue
                if d.get("suspended"):
                    results.append(f"<result><status>error</status><errcode>1006</errcode><errtext>Permission denied.</errtext><filter-id>{user.base + i}</filter-id><id>{user.base + i}</id></result>")
                    continue
                results.append(self._webspace_result(i, d, datasets, user.base))
            return self._ok(f"<webspace><get>{''.join(results)}</get></webspace>")
        if operator == "site":
            results = []
            for i, d in enumerate(user.domains):
                if d.get("kind") != "site":
                    continue
                parent_index = next(j for j, p in enumerate(user.domains) if p["name"] == d["webspace"])
                results.append(
                    f"<result><status>ok</status><filter-id>{user.base + 100 + i}</filter-id><id>{user.base + 100 + i}</id><data><gen_info><name>{d['name']}</name>"
                    f"<status>0</status><webspace-id>{user.base + parent_index}</webspace-id></gen_info><hosting><vrt_hst>"
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
        if operator == "database":
            return self._handle_database(root, user)
        if operator in ("service-plan", "service-plan-addon"):
            if user.type != "admin":
                return self._ok(f"<{operator}><get><result><status>error</status><errcode>1006</errcode><errtext>Permission denied.</errtext></result></get></{operator}>")
            addon = operator == "service-plan-addon"
            results = "".join(
                f"<result><status>ok</status><id>{n}</id><name>{name}</name><guid>{guid}</guid></result>"
                for n, (guid, name) in enumerate(self.plan_names.items())
                if guid.startswith("guid-addon") == addon
            )
            return self._ok(f"<{operator}><get>{results}</get></{operator}>")
        if operator == "server":
            return self._ok("<server><get><result><status>ok</status><gen_info><server_name>fake</server_name></gen_info></result></get></server>")
        return self._system_error(1014, f"Parser error: unexpected element {operator}")


# ------------------------------------------------------------------ fake MariaDB
class FakeMysqlRegistry:
    """Databases the fake mysql CLI knows: name -> (user, password, sqlite file)."""

    def __init__(self, base: Path):
        self.base = base
        self.creds: dict[str, tuple[str, str]] = {}

    def add(self, database: str, user: str, password: str) -> None:
        self.creds[database] = (user, password)

    def path(self, database: str) -> Path:
        self.base.mkdir(parents=True, exist_ok=True)
        return self.base / f"{database}.sqlite"

    def connect(self, database: str) -> sqlite3.Connection:
        return sqlite3.connect(str(self.path(database)))


def make_fake_mysql_session(module, registry: FakeMysqlRegistry):
    HelperError = module.HelperError

    class FakeMysqlSession:
        """Stand-in for MysqlSession: executes the helper's SQL scripts on SQLite.

        Translates the MariaDB specific statements the helper emits (SET SESSION,
        START TRANSACTION, SHOW TABLES/COLUMNS/TABLE STATUS, ROW_COUNT()) and
        enforces user/password like the real server would.
        """

        def __init__(self, ws, database, user, password):
            self.ws = ws
            self.database = database
            self.user = user
            expected = registry.creds.get(database)
            if expected is None or expected != (user, password):
                raise HelperError("db_error", "Access denied for user")
            self.conn = registry.connect(database)
            self.conn.isolation_level = None

        def close(self):
            self.conn.close()

        def run(self, sql, time_limit, max_lines=None, database=None):
            lines: list[str] = []
            truncated = False
            statements = [s.strip() for s in _split_statements(sql) if s.strip()]
            read_only = False
            try:
                for stmt in statements:
                    up = stmt.upper()
                    if up.startswith("SET SESSION"):
                        continue
                    if up == "SELECT VERSION()":
                        lines += ["VERSION()", "10.6.0-MariaDB-fake"]
                        continue
                    if up.startswith("START TRANSACTION"):
                        read_only = "READ ONLY" in up
                        self.conn.execute("BEGIN")
                        continue
                    if up in ("ROLLBACK", "COMMIT"):
                        self.conn.execute(up)
                        read_only = False
                        continue
                    if up == "SHOW TABLES":
                        rows = self.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
                        lines += [f"Tables_in_{self.database}"] + [r[0] for r in rows]
                        continue
                    if up == "SHOW TABLE STATUS":
                        rows = self.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").fetchall()
                        lines.append("Name\tEngine\tRows\tData_length\tCollation")
                        for r in rows:
                            n = self.conn.execute(f'SELECT COUNT(*) FROM "{r[0]}"').fetchone()[0]
                            lines.append(f"{r[0]}\tInnoDB\t{n}\t{n * 100}\tutf8mb4_general_ci")
                        continue
                    m = re.match(r"SHOW (?:FULL )?COLUMNS FROM `?([A-Za-z0-9_$]+)`?", stmt, re.I)
                    if m:
                        rows = self.conn.execute(f'PRAGMA table_info("{m.group(1)}")').fetchall()
                        if not rows:
                            raise HelperError("db_error", f"Table '{m.group(1)}' doesn't exist")
                        lines.append("Field\tType\tNull\tKey\tDefault\tExtra")
                        for r in rows:
                            lines.append(f"{r[1]}\t{r[2]}\t{'NO' if r[3] else 'YES'}\t{'PRI' if r[5] else ''}\t{r[4] if r[4] is not None else 'NULL'}\t")
                        continue
                    if up.startswith("SELECT ROW_COUNT()"):
                        lines += ["affected", str(self._last_changes)]
                        continue
                    if "INFORMATION_SCHEMA.TABLES" in up:
                        page = self.conn.execute("PRAGMA page_count").fetchone()[0] * self.conn.execute("PRAGMA page_size").fetchone()[0]
                        lines += ["size", str(page)]
                        continue
                    if read_only and not up.startswith(("SELECT", "EXPLAIN", "PRAGMA", "WITH")):
                        raise HelperError("db_error", "Cannot execute statement in a READ ONLY transaction.")
                    cur = self.conn.execute(stmt)
                    self._last_changes = cur.rowcount if cur.rowcount is not None and cur.rowcount >= 0 else 0
                    if cur.description:
                        cols = [d[0] for d in cur.description]
                        lines.append("\t".join(cols))
                        for row in cur:
                            if max_lines is not None and len(lines) >= max_lines:
                                truncated = True
                                break
                            lines.append("\t".join("NULL" if v is None else str(v) for v in row))
            except sqlite3.Error as exc:
                try:
                    self.conn.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise HelperError("db_error", str(exc))
            return lines, truncated

        _last_changes = 0

        def dump(self, tables, target_gz):
            names = list(tables) or [r[0] for r in self.conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
            out = []
            for t in names:
                create = self.conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (t,)).fetchone()
                if create is None:
                    continue
                out.append(f'DROP TABLE IF EXISTS "{t}";')
                out.append(create[0] + ";")
                for row in self.conn.execute(f'SELECT * FROM "{t}"'):
                    values = ", ".join("NULL" if v is None else ("'" + str(v).replace("'", "''") + "'") for v in row)
                    out.append(f'INSERT INTO "{t}" VALUES ({values});')
            with gzip.open(target_gz, "wb") as fh:
                fh.write("\n".join(out).encode("utf-8") + b"\n")
            os.chmod(target_gz, 0o600)

        def restore(self, source_gz, time_limit):
            with gzip.open(source_gz, "rb") as fh:
                script = fh.read().decode("utf-8")
            self.conn.executescript(script)

    return FakeMysqlSession


def _split_statements(sql: str) -> list[str]:
    out, buf, quote = [], [], None
    for ch in sql:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"', "`"):
            quote = ch
            buf.append(ch)
        elif ch == ";":
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    out.append("".join(buf))
    return out


# ------------------------------------------------------------------ fake SSH pool
class FakePool:
    """Runs the helper in-process (the worker's SSHPool replacement). `homes` maps system users to subscription directories."""

    def __init__(self, vhosts_base: Path, homes: dict[str, Path], mysql: FakeMysqlRegistry):
        self.module = load_helper_module()
        self.module.VHOSTS_BASE = str(vhosts_base)
        self.module.MysqlSession = make_fake_mysql_session(self.module, mysql)
        self.homes = homes
        self.calls: list[dict[str, Any]] = []
        self.fail_with: Exception | None = None
        self.delay: float = 0.0
        self.busy: int = 0
        self.max_busy: int = 0

    async def run(self, sysuser: str, request: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
        from pleskmcp.remote import HelperError, RemoteError, validate_sysuser

        validate_sysuser(sysuser)
        if self.fail_with is not None:
            raise self.fail_with
        self.calls.append({"sysuser": sysuser, **request})
        home = self.homes.get(sysuser)
        if home is None:
            raise RemoteError("unknown system user")
        self.busy += 1
        self.max_busy = max(self.max_busy, self.busy)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            Passwd = namedtuple("Passwd", "pw_dir pw_name")
            original = self.module.pwd.getpwuid
            self.module.pwd.getpwuid = lambda uid: Passwd(str(home), sysuser)
            try:
                result = self.module.handle(request)
            except self.module.HelperError as exc:
                raise HelperError(exc.code, exc.message, getattr(exc, "details", None))
            finally:
                self.module.pwd.getpwuid = original
        finally:
            self.busy -= 1
        return json.loads(json.dumps(result))

    async def preflight(self) -> tuple[bool, str]:
        return True, "fake pool"

    async def close(self) -> None:
        return None


# ------------------------------------------------------------------- app fixture
@dataclass
class Env:
    settings: Any
    services: Any
    app: Any
    plesk: FakePlesk
    pool: FakePool
    worker: Any
    mysql: FakeMysqlRegistry
    vhosts: Path
    client: httpx.AsyncClient
    redis: Any

    @property
    def executor(self) -> FakePool:  # backwards compatible name used by older tests
        return self.pool


def make_vhost(vhosts: Path, name: str) -> Path:
    home = vhosts / name
    (home / "httpdocs").mkdir(parents=True)
    (home / "logs").mkdir()
    return home


def base_env(tmp_path: Path) -> dict[str, str]:
    return {
        "PUBLIC_BASE_URL": "https://mcp.example.com/plesk",
        "PLESK_URL": "https://plesk.example.com:8443",
        "PLESK_SSH_HOST": "plesk.example.com",
        "PLESK_SSH_USER": "pleskmcp",
        "PLESK_SSH_KEY_PATH": str(tmp_path / "key"),
        "PLESK_SSH_HOST_KEY": "ssh-ed25519 AAAA",
        "DATABASE_URL": f"sqlite+aiosqlite:///{tmp_path / 'pleskmcp.sqlite'}",
        "REDIS_URL": "redis://:unused@fake:6379/0",
        "DATA_DIR": str(tmp_path / "data"),
        "AUDIT_LOG_FILE": str(tmp_path / "data" / "audit.log"),
        "DATA_ENCRYPTION_KEY": Fernet.generate_key().decode(),
        "ACCOUNT_CHECK_MODE": "customer_key",
        "ACCOUNT_CHECK_TTL": "0",
        "PLESK_ADMIN_API_KEY": "admin-key",
        "ACCESS_PROFILES": json.dumps(TEST_PROFILES),
        "ACCESS_TOKEN_TTL": "600",
        "LOGIN_FAIL_LIMIT_LOGIN": "3",
        "LOGIN_FAIL_LIMIT_IP": "6",
        "PLESK_FAIL_BUDGET": "100",
        "WRITE_MAX_BYTES": "100000",
        "TOOL_SYNC_WAIT": "5",
        "HELPER_TIME_LIMIT": "10",
        "JOB_TIME_LIMIT": "20",
        "DB_MANAGEMENT_ENABLED": "true",
        "LOG_FORMAT": "text",
    }


@pytest.fixture
async def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    if os.getuid() == 0:
        pytest.skip("the helper refuses to run as root; run the tests as an unprivileged user")
    vhosts = tmp_path / "vhosts"
    vhosts.mkdir()
    home = make_vhost(vhosts, "example.com")
    data_home = make_vhost(vhosts, "data.example")
    plain_home = make_vhost(vhosts, "plain.example")
    other_home = make_vhost(vhosts, "other.example")
    (home / "httpdocs" / "index.php").write_text("<?php echo 'hi';\n")
    (home / "httpdocs" / "wp-config.php").write_text(
        "<?php\ndefine('DB_NAME', 'wp_db');\ndefine('DB_USER', 'wp_user');\ndefine('DB_PASSWORD', 'wp-secret-pw');\ndefine('DB_HOST', 'localhost');\ndefine('AUTH_KEY', 'long-random-key');\n$table_prefix = 'wp_';\n"
    )
    (home / "httpdocs" / "assets").mkdir()
    (home / "httpdocs" / "assets" / "style.css").write_text("body{}\n")
    (home / "logs" / "error_log").write_text("line one\nerror: broken thing\nline three\nlogin password=hunter2 failed\n")
    (home / "shop").mkdir()
    (data_home / "httpdocs" / ".env").write_text("APP_NAME=Demo\nDB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=app_db\nDB_USERNAME=app_user\nDB_PASSWORD=app-secret-pw\nAPP_KEY=base64:abc\n")
    (data_home / "httpdocs" / "index.php").write_text("<?php\n")
    (plain_home / "httpdocs" / "index.html").write_text("plain\n")
    (other_home / "httpdocs" / "secret.txt").write_text("other customer data\n")

    for key, value in base_env(tmp_path).items():
        monkeypatch.setenv(key, value)

    from pleskmcp.config import Settings
    from pleskmcp.db import Store, make_engine
    from pleskmcp.queue import Worker
    from pleskmcp.server import build_app, build_services

    plesk = FakePlesk()
    plesk.users["kunde"] = FakeUser(
        password="geheim",
        domains=[
            # 0: cheap "AI Hosting" plan, 5 GB, files + dns
            {"name": "example.com", "sysuser": "example_sys", "docroot": str(home / "httpdocs"), "plan_guids": ["guid-plan-ai"], "quota": 5 * GB, "used": 1 * GB, "max_db": 0},
            # 1: addon domain of example.com
            {"name": "shop.example.com", "kind": "site", "webspace": "example.com", "sysuser": "example_sys", "docroot": str(home / "shop")},
            # 2: standard plan with the "KI-Zugang" add-on: files + db
            {"name": "data.example", "sysuser": "data_sys", "docroot": str(data_home / "httpdocs"), "plan_guids": ["guid-plan-standard", "guid-addon-ki"], "quota": 20 * GB, "used": 2 * GB, "max_db": 10},
            # 3: plan without any profile match (GUID profile exists for the plan "guid-plan-standard" only in combination above)
            {"name": "plain.example", "sysuser": "plain_sys", "docroot": str(plain_home / "httpdocs"), "plan_guids": ["guid-plan-none"], "quota": -1},
        ],
    )
    plesk.users["other"] = FakeUser(
        password="geheim2",
        base=150,
        domains=[{"name": "other.example", "sysuser": "other_sys", "docroot": str(other_home / "httpdocs"), "plan_guids": ["guid-plan-ai"]}],
    )
    plesk.users["admin"] = FakeUser(password="adminpw", type="admin")
    plesk.users["reseller1"] = FakeUser(password="resellerpw", type="reseller")
    plesk.users["zusatz"] = FakeUser(password="zusatzpw", type="smbuser")
    plesk.users["gesperrt"] = FakeUser(password="pw", status=16)

    plesk.add_dns(100, "A", "example.com.", "192.0.2.1")
    plesk.add_dns(100, "NS", "example.com.", "ns1.example.net.")
    plesk.add_dns(100, "MX", "example.com.", "mail.example.com.", "10")
    plesk.add_dns(100, "CNAME", "www.example.com.", "example.com.")
    plesk.add_dns(plesk.webspace_id("other.example"), "A", "other.example.", "192.0.2.2")

    # databases Plesk knows for data.example; wp_db belongs to example.com but its plan has no db scope
    plesk.add_database(plesk.webspace_id("data.example"), "app_db")
    plesk.add_database(plesk.webspace_id("data.example"), "legacy_db")
    plesk.add_database(plesk.webspace_id("example.com"), "wp_db")

    mysql = FakeMysqlRegistry(tmp_path / "fakedb")
    mysql.add("app_db", "app_user", "app-secret-pw")
    mysql.add("legacy_db", "legacy_user", "legacy-pw")
    conn = mysql.connect("app_db")
    conn.executescript(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT, api_token TEXT);"
        "INSERT INTO users VALUES (1, 'a@example.com', 'hash-a', 'tok-a'), (2, 'b@example.com', 'hash-b', 'tok-b'), (3, 'c@example.com', 'hash-c', NULL);"
        "CREATE TABLE posts (id INTEGER PRIMARY KEY, title TEXT);"
        "INSERT INTO posts VALUES (1, 'hello'), (2, 'world');"
    )
    conn.close()

    homes = {"example_sys": home, "data_sys": data_home, "plain_sys": plain_home, "other_sys": other_home}
    pool = FakePool(vhosts, homes, mysql)

    settings = Settings.load()
    server = fakeredis.FakeServer()
    redis = fakeaioredis.FakeRedis(server=server, decode_responses=True)
    worker_redis = fakeaioredis.FakeRedis(server=server, decode_responses=True)
    store = Store(make_engine(settings.database_url))
    await store.create_all()
    services = build_services(settings, store=store, redis=redis, plesk_transport=plesk.transport())
    app = build_app(services)

    worker = Worker(settings, services.queue.__class__(settings, worker_redis), worker_redis, pool, worker_id="test-worker")
    worker_task = asyncio.create_task(worker.run_forever())
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.com", headers={"host": "mcp.example.com"}) as client:
                yield Env(settings, services, app, plesk, pool, worker, mysql, vhosts, client, redis)
    finally:
        worker.stop()
        try:
            await asyncio.wait_for(worker_task, timeout=5)
        except (asyncio.TimeoutError, Exception):  # noqa: BLE001
            worker_task.cancel()
        await services.plesk.aclose()
        await store.close()
        await redis.aclose()
        await worker_redis.aclose()


# -------------------------------------------------------------------- oauth helper
def pkce_pair() -> tuple[str, str]:
    import hashlib

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    return verifier, challenge


ALL_TEST_SCOPES = "files:read files:write dns:read dns:write db:read db:write db:admin"


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

    async def authorize(self, *, scope: str | None = ALL_TEST_SCOPES, resource: str | None = "https://mcp.example.com/plesk/mcp", state: str = "xyz") -> tuple[str, str]:
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

    async def login(self, location: str, login: str, password: str, *, action: str = "allow", revoke_others: bool = False) -> httpx.Response:
        assert location.startswith("https://mcp.example.com/plesk/login?req=")
        page = await self.client.get(location)
        assert page.status_code == 200, page.text
        req = re.search(r'name="req" value="([^"]+)"', page.text).group(1)
        csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
        data = {"req": req, "csrf": csrf, "login": login, "password": password, "action": action}
        if revoke_others:
            data["revoke_others"] = "1"
        return await self.client.post("/plesk/login", data=data)

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

    async def full_login(self, login: str = "kunde", password: str = "geheim", *, scope: str | None = ALL_TEST_SCOPES, revoke_others: bool = False) -> dict[str, Any]:
        if self.client_id is None:
            await self.register()
        location, verifier = await self.authorize(scope=scope)
        response = await self.login(location, login, password, revoke_others=revoke_others)
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


def structured(result: dict[str, Any]) -> dict[str, Any]:
    assert not result.get("isError"), tool_text(result)
    return result["structuredContent"]
