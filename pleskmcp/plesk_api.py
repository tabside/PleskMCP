"""Minimal Plesk XML API (agent.php) client.

Only read operations plus secret_key create/delete are used. Credentials are
passed per call and never stored by this module.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any
from xml.sax.saxutils import escape

import httpx

logger = logging.getLogger(__name__)

# Plesk XML API system error codes
ERR_WRONG_CREDENTIALS = 1001
ERR_PERMISSION_DENIED = 1006
ERR_ACCOUNT_SUSPENDED = 1011
ERR_NOT_FOUND = 1013
ERR_NO_AUTH_METHOD = 1029


class PleskError(Exception):
    """Transport or protocol failure (network, bad XML, HTTP error)."""


class PleskSystemError(PleskError):
    """`<system>` level error: authentication rejected, account suspended, ..."""

    def __init__(self, code: int, text: str):
        super().__init__(f"Plesk system error {code}: {text}")
        self.code = code
        self.text = text


class PleskResultError(PleskError):
    """Operator level `<result><status>error</status>` (e.g. 1006 permission denied)."""

    def __init__(self, code: int, text: str):
        super().__init__(f"Plesk result error {code}: {text}")
        self.code = code
        self.text = text


@dataclass(frozen=True)
class PasswordAuth:
    login: str
    password: str

    def headers(self) -> dict[str, str]:
        return {"HTTP_AUTH_LOGIN": self.login, "HTTP_AUTH_PASSWD": self.password}


@dataclass(frozen=True)
class KeyAuth:
    key: str

    def headers(self) -> dict[str, str]:
        return {"KEY": self.key}


Auth = PasswordAuth | KeyAuth


@dataclass
class CustomerInfo:
    id: int
    login: str
    name: str
    status: int
    email: str | None = None


@dataclass
class DomainInfo:
    name: str
    kind: str  # webspace | site | subdomain
    sysuser: str
    docroot: str
    webspace: str  # name of the subscription the domain belongs to
    status: int = 0
    id: int | None = None
    webspace_id: int | None = None
    plan_guid: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "sysuser": self.sysuser,
            "docroot": self.docroot,
            "webspace": self.webspace,
            "status": self.status,
            "id": self.id,
            "webspace_id": self.webspace_id,
            "plan_guid": self.plan_guid,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> "DomainInfo":
        return DomainInfo(
            name=data["name"],
            kind=data.get("kind", "webspace"),
            sysuser=data["sysuser"],
            docroot=data["docroot"],
            webspace=data.get("webspace", data["name"]),
            status=int(data.get("status", 0)),
            id=data.get("id"),
            webspace_id=data.get("webspace_id"),
            plan_guid=data.get("plan_guid"),
        )


@dataclass
class DnsRecord:
    id: int
    site_id: int | None
    type: str
    host: str
    value: str
    opt: str

    def as_dict(self) -> dict[str, Any]:
        return {"id": self.id, "site_id": self.site_id, "type": self.type, "host": self.host, "value": self.value, "opt": self.opt}


@dataclass
class _Result:
    status: str
    id: int | None
    errcode: int | None
    errtext: str | None
    element: ET.Element
    properties: dict[str, str] = field(default_factory=dict)


def _text(el: ET.Element | None) -> str | None:
    if el is None or el.text is None:
        return None
    return el.text.strip()


def _int(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


class PleskClient:
    def __init__(
        self,
        base_url: str,
        *,
        verify_ssl: bool = True,
        timeout: float = 20.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self._url = base_url.rstrip("/") + "/enterprise/control/agent.php"
        self._client = httpx.AsyncClient(verify=verify_ssl, timeout=timeout, transport=transport, follow_redirects=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    # ------------------------------------------------------------------ low level
    async def call(self, packet_body: str, auth: Auth) -> ET.Element:
        packet = f'<?xml version="1.0" encoding="UTF-8"?><packet version="1.6.9.1">{packet_body}</packet>'
        headers = {"Content-Type": "text/xml", "Accept": "text/xml"}
        headers.update(auth.headers())
        try:
            response = await self._client.post(self._url, content=packet.encode("utf-8"), headers=headers)
        except httpx.HTTPError as exc:
            raise PleskError(f"Plesk API request failed: {exc.__class__.__name__}") from exc
        if response.status_code != 200:
            raise PleskError(f"Plesk API returned HTTP {response.status_code}")
        try:
            root = ET.fromstring(response.content)
        except ET.ParseError as exc:
            raise PleskError("Plesk API returned invalid XML") from exc
        system = root.find("system")
        if system is not None and _text(system.find("status")) == "error":
            code = _int(_text(system.find("errcode"))) or 0
            raise PleskSystemError(code, _text(system.find("errtext")) or "")
        return root

    @staticmethod
    def _results(root: ET.Element, path: str) -> list[_Result]:
        results: list[_Result] = []
        for el in root.iterfind(path):
            status = _text(el.find("status")) or "error"
            props: dict[str, str] = {}
            for prop in el.iter("property"):
                name = _text(prop.find("name"))
                value = _text(prop.find("value"))
                if name is not None:
                    props[name] = value or ""
            results.append(
                _Result(
                    status=status,
                    id=_int(_text(el.find("id"))),
                    errcode=_int(_text(el.find("errcode"))),
                    errtext=_text(el.find("errtext")),
                    element=el,
                    properties=props,
                )
            )
        return results

    # ----------------------------------------------------------------- customers
    async def get_customer(self, login: str, auth: Auth) -> CustomerInfo | None:
        """`customer get` filtered by login. Returns None if no such customer is visible."""
        body = (
            f"<customer><get><filter><login>{escape(login)}</login></filter>"
            "<dataset><gen_info/></dataset></get></customer>"
        )
        root = await self.call(body, auth)
        results = self._results(root, "./customer/get/result")
        if not results:
            raise PleskError("customer get returned no result")
        result = results[0]
        if result.status != "ok":
            if result.errcode == ERR_NOT_FOUND:
                return None
            raise PleskResultError(result.errcode or 0, result.errtext or "")
        gen = result.element.find("./data/gen_info")
        if gen is None:
            raise PleskError("customer get returned no gen_info")
        return CustomerInfo(
            id=result.id or 0,
            login=_text(gen.find("login")) or "",
            name=_text(gen.find("pname")) or _text(gen.find("cname")) or "",
            status=_int(_text(gen.find("status"))) or 0,
            email=_text(gen.find("email")),
        )

    async def verify_customer(self, login: str, password: str) -> CustomerInfo:
        """Authenticate as `login` and prove it is an active *customer* account.

        Raises PleskSystemError (wrong password 1001, suspended 1011, ...),
        PleskResultError (1006: the login is not a customer, e.g. an additional
        user) or PleskError. Admin and reseller logins see no customer with their
        own login and are rejected with PleskResultError(1013).
        """
        auth = PasswordAuth(login, password)
        info = await self.get_customer(login, auth)
        if info is None or info.login != login:
            raise PleskResultError(ERR_NOT_FOUND, "login is not a customer account")
        if info.status != 0:
            raise PleskSystemError(ERR_ACCOUNT_SUSPENDED, "account is not active")
        return info

    # ------------------------------------------------------------------- domains
    async def list_domains(self, auth: Auth, *, owner_login: str | None = None) -> list[DomainInfo]:
        """All hosted webspaces, addon domains and subdomains visible to `auth`.

        With `owner_login` (admin key), the webspaces are filtered by owner.
        """
        if owner_login:
            ws_filter = f"<filter><owner-login>{escape(owner_login)}</owner-login></filter>"
        else:
            ws_filter = "<filter/>"
        root = await self.call(
            f"<webspace><get>{ws_filter}<dataset><gen_info/><hosting/><subscriptions/></dataset></get></webspace>", auth
        )
        domains: list[DomainInfo] = []
        by_id: dict[int, DomainInfo] = {}
        by_guid: dict[str, DomainInfo] = {}
        for result in self._results(root, "./webspace/get/result"):
            if result.status != "ok":
                # A suspended subscription answers 1006 for its own entry; skip it.
                logger.info("webspace %s skipped: %s %s", result.id, result.errcode, result.errtext)
                continue
            gen = result.element.find("./data/gen_info")
            if gen is None or result.element.find("./data/hosting/vrt_hst") is None:
                continue
            name = _text(gen.find("name")) or ""
            sysuser = result.properties.get("ftp_login", "")
            docroot = result.properties.get("www_root", "")
            if not name or not sysuser or not docroot:
                continue
            info = DomainInfo(
                name=name,
                kind="webspace",
                sysuser=sysuser,
                docroot=docroot,
                webspace=name,
                status=_int(_text(gen.find("status"))) or 0,
                id=result.id,
                webspace_id=result.id,
                plan_guid=_text(result.element.find("./data/subscriptions/subscription/plan/plan-guid")),
            )
            domains.append(info)
            if result.id is not None:
                by_id[result.id] = info
            guid = _text(gen.find("guid"))
            if guid:
                by_guid[guid] = info
        if not domains:
            return domains

        # Addon domains (sites) of those webspaces
        if owner_login:
            site_body = "".join(
                f"<site><get><filter><webspace-id>{d.id}</webspace-id></filter>"
                "<dataset><gen_info/><hosting/></dataset></get></site>"
                for d in domains
                if d.id
            )
        else:
            site_body = "<site><get><filter/><dataset><gen_info/><hosting/></dataset></get></site>"
        try:
            root = await self.call(site_body, auth)
        except PleskResultError:
            root = None
        if root is not None:
            for result in self._results(root, "./site/get/result"):
                if result.status != "ok":
                    continue
                gen = result.element.find("./data/gen_info")
                if gen is None or result.element.find("./data/hosting/vrt_hst") is None:
                    continue
                name = _text(gen.find("name")) or ""
                parent = None
                ws_id = _int(_text(gen.find("webspace-id")))
                ws_guid = _text(gen.find("webspace-guid"))
                if ws_id is not None and ws_id in by_id:
                    parent = by_id[ws_id]
                elif ws_guid and ws_guid in by_guid:
                    parent = by_guid[ws_guid]
                sysuser = result.properties.get("ftp_login") or (parent.sysuser if parent else "")
                docroot = result.properties.get("www_root", "")
                if not name or not sysuser or not docroot or parent is None:
                    continue
                info = DomainInfo(
                    name=name,
                    kind="site",
                    sysuser=sysuser,
                    docroot=docroot,
                    webspace=parent.webspace,
                    status=_int(_text(gen.find("status"))) or 0,
                    id=result.id,
                    webspace_id=parent.id,
                    plan_guid=parent.plan_guid,
                )
                domains.append(info)
                if result.id is not None:
                    by_id[result.id] = info

        # Subdomains
        try:
            root = await self.call("<subdomain><get><filter/></get></subdomain>", auth)
        except PleskResultError:
            root = None
        if root is not None:
            for result in self._results(root, "./subdomain/get/result"):
                if result.status != "ok":
                    continue
                data = result.element.find("./data")
                if data is None:
                    continue
                name = _text(data.find("name")) or ""
                parent_id = _int(_text(data.find("parent-id")))
                parent = by_id.get(parent_id) if parent_id is not None else None
                sysuser = result.properties.get("ftp_login") or (parent.sysuser if parent else "")
                docroot = result.properties.get("www_root", "")
                if not name or not sysuser or not docroot or parent is None:
                    continue
                domains.append(
                    DomainInfo(
                        name=name,
                        kind="subdomain",
                        sysuser=sysuser,
                        docroot=docroot,
                        webspace=parent.webspace,
                        status=0,
                        id=result.id,
                        webspace_id=parent.webspace_id or parent.id,
                        plan_guid=parent.plan_guid,
                    )
                )
        return domains

    async def get_webspace_quota(self, auth: Auth, webspace_id: int) -> tuple[int | None, int | None, str | None]:
        """(disk quota bytes or None if unlimited, used bytes, service plan guid) of one webspace."""
        root = await self.call(
            f"<webspace><get><filter><id>{int(webspace_id)}</id></filter>"
            "<dataset><gen_info/><limits/><subscriptions/></dataset></get></webspace>",
            auth,
        )
        results = self._results(root, "./webspace/get/result")
        if not results or results[0].status != "ok":
            raise PleskResultError(results[0].errcode or 0 if results else 0, results[0].errtext or "" if results else "no result")
        el = results[0].element
        used = _int(_text(el.find("./data/gen_info/real_size")))
        quota: int | None = None
        for limit in el.iterfind("./data/limits/limit"):
            if _text(limit.find("name")) == "disk_space":
                value = _int(_text(limit.find("value")))
                quota = value if value is not None and value > 0 else None
        plan_guid = _text(el.find("./data/subscriptions/subscription/plan/plan-guid"))
        return quota, used, plan_guid

    async def get_subscription_plans(self, auth: Auth, webspace_id: int) -> list[str]:
        """GUIDs of the service plan and add-on plans of a webspace (first entry: main plan)."""
        root = await self.call(
            f"<webspace><get><filter><id>{int(webspace_id)}</id></filter><dataset><subscriptions/></dataset></get></webspace>", auth
        )
        results = self._results(root, "./webspace/get/result")
        if not results or results[0].status != "ok":
            raise PleskResultError(results[0].errcode or 0 if results else 0, results[0].errtext or "" if results else "no result")
        guids: list[str] = []
        for plan in results[0].element.iterfind("./data/subscriptions/subscription/plan"):
            guid = _text(plan.find("plan-guid"))
            if guid and guid not in guids:
                guids.append(guid)
        return guids

    async def get_databases(self, auth: Auth, webspace_name: str) -> list[dict[str, Any]]:
        """Databases of a subscription: [{id, name, type}] (customer context works)."""
        root = await self.call(
            f"<database><get-db><filter><webspace-name>{escape(webspace_name)}</webspace-name></filter></get-db></database>", auth
        )
        databases: list[dict[str, Any]] = []
        for result in self._results(root, "./database/get-db/result"):
            if result.status != "ok":
                raise PleskResultError(result.errcode or 0, result.errtext or "")
            data = result.element.find("./data")
            if data is None:
                continue
            name = _text(data.find("name"))
            if name:
                databases.append({"id": result.id, "name": name, "type": _text(data.find("type")) or "mysql"})
        return databases

    # --------------------------------------------------------------- databases
    # Management runs in the customer context (the customer's own secret key).
    # Whether Plesk permits that for a customer login is verified per
    # installation; see README "Verifizierte Plesk-Fakten" and
    # DB_MANAGEMENT_ENABLED.
    def _single(self, root: ET.Element, path: str) -> _Result:
        results = self._results(root, path)
        if not results:
            raise PleskError(f"{path} returned no result")
        result = results[0]
        if result.status != "ok":
            raise PleskResultError(result.errcode or 0, result.errtext or "")
        return result

    async def database_add(self, auth: Auth, webspace_id: int, name: str, db_type: str = "mysql") -> int:
        """database add-db: returns the new database id."""
        root = await self.call(
            f"<database><add-db><webspace-id>{int(webspace_id)}</webspace-id><name>{escape(name)}</name><type>{escape(db_type)}</type></add-db></database>",
            auth,
        )
        result = self._single(root, "./database/add-db/result")
        if result.id is None:
            raise PleskError("add-db returned no id")
        return result.id

    async def database_add_user(self, auth: Auth, db_id: int, login: str, password: str) -> int:
        """database add-db-user: returns the new user id. The password is sent once and never logged."""
        root = await self.call(
            f"<database><add-db-user><db-id>{int(db_id)}</db-id><login>{escape(login)}</login><password>{escape(password)}</password></add-db-user></database>",
            auth,
        )
        result = self._single(root, "./database/add-db-user/result")
        if result.id is None:
            raise PleskError("add-db-user returned no id")
        return result.id

    async def database_del(self, auth: Auth, db_id: int) -> None:
        root = await self.call(f"<database><del-db><filter><id>{int(db_id)}</id></filter></del-db></database>", auth)
        self._single(root, "./database/del-db/result")

    async def database_del_user(self, auth: Auth, user_id: int) -> None:
        root = await self.call(f"<database><del-db-user><filter><id>{int(user_id)}</id></filter></del-db-user></database>", auth)
        self._single(root, "./database/del-db-user/result")

    async def database_users(self, auth: Auth, db_id: int) -> list[dict[str, Any]]:
        root = await self.call(f"<database><get-db-users><filter><db-id>{int(db_id)}</db-id></filter></get-db-users></database>", auth)
        users: list[dict[str, Any]] = []
        for result in self._results(root, "./database/get-db-users/result"):
            if result.status != "ok":
                raise PleskResultError(result.errcode or 0, result.errtext or "")
            login = _text(result.element.find("login"))
            if login:
                users.append({"id": result.id, "login": login})
        return users

    async def get_service_plan_names(self, auth: Auth) -> dict[str, str]:
        """guid -> name of all service plans (administrator key only)."""
        names: dict[str, str] = {}
        for operator in ("service-plan", "service-plan-addon"):
            root = await self.call(f"<{operator}><get><filter/></get></{operator}>", auth)
            for result in self._results(root, f"./{operator}/get/result"):
                if result.status != "ok":
                    continue
                guid = _text(result.element.find("guid"))
                name = _text(result.element.find("name"))
                if guid and name:
                    names[guid] = name
        return names

    # --------------------------------------------------------------- secret keys
    async def create_secret_key(self, auth: Auth, *, ip_address: str | None, description: str, login: str | None = None) -> str:
        parts = []
        if ip_address:
            parts.append(f"<ip_address>{escape(ip_address)}</ip_address>")
        parts.append(f"<description>{escape(description)}</description>")
        if login:
            parts.append(f"<login>{escape(login)}</login>")
        root = await self.call(f"<secret_key><create>{''.join(parts)}</create></secret_key>", auth)
        results = self._results(root, "./secret_key/create/result")
        if not results:
            raise PleskError("secret_key create returned no result")
        result = results[0]
        if result.status != "ok":
            raise PleskResultError(result.errcode or 0, result.errtext or "")
        key = _text(result.element.find("key"))
        if not key:
            raise PleskError("secret_key create returned no key")
        return key

    async def delete_secret_key(self, auth: Auth, key: str) -> bool:
        root = await self.call(
            f"<secret_key><delete><filter><key>{escape(key)}</key></filter></delete></secret_key>", auth
        )
        results = self._results(root, "./secret_key/delete/result")
        return bool(results) and results[0].status == "ok"

    # ----------------------------------------------------------------------- dns
    def _dns_record(self, result: _Result) -> DnsRecord | None:
        data = result.element.find("./data")
        if data is None or result.id is None:
            return None
        return DnsRecord(
            id=result.id,
            site_id=_int(_text(data.find("site-id"))),
            type=(_text(data.find("type")) or "").upper(),
            host=_text(data.find("host")) or "",
            value=_text(data.find("value")) or "",
            opt=_text(data.find("opt")) or "",
        )

    async def dns_get_records(self, auth: Auth, site_id: int) -> list[DnsRecord]:
        root = await self.call(f"<dns><get_rec><filter><site-id>{int(site_id)}</site-id></filter></get_rec></dns>", auth)
        records: list[DnsRecord] = []
        for result in self._results(root, "./dns/get_rec/result"):
            if result.status != "ok":
                raise PleskResultError(result.errcode or 0, result.errtext or "")
            record = self._dns_record(result)
            if record is not None:
                records.append(record)
        return records

    async def dns_get_record(self, auth: Auth, record_id: int) -> DnsRecord | None:
        root = await self.call(f"<dns><get_rec><filter><id>{int(record_id)}</id></filter></get_rec></dns>", auth)
        results = self._results(root, "./dns/get_rec/result")
        if not results:
            return None
        result = results[0]
        if result.status != "ok":
            if result.errcode == ERR_NOT_FOUND:
                return None
            raise PleskResultError(result.errcode or 0, result.errtext or "")
        return self._dns_record(result)

    async def dns_add_record(self, auth: Auth, site_id: int, rtype: str, host: str, value: str, opt: str = "") -> int:
        body = (
            f"<dns><add_rec><site-id>{int(site_id)}</site-id><type>{escape(rtype)}</type>"
            f"<host>{escape(host)}</host><value>{escape(value)}</value><opt>{escape(opt)}</opt></add_rec></dns>"
        )
        root = await self.call(body, auth)
        results = self._results(root, "./dns/add_rec/result")
        if not results:
            raise PleskError("dns add_rec returned no result")
        result = results[0]
        if result.status != "ok" or result.id is None:
            raise PleskResultError(result.errcode or 0, result.errtext or "")
        return result.id

    async def dns_del_record(self, auth: Auth, record_id: int) -> None:
        root = await self.call(f"<dns><del_rec><filter><id>{int(record_id)}</id></filter></del_rec></dns>", auth)
        results = self._results(root, "./dns/del_rec/result")
        if not results:
            raise PleskError("dns del_rec returned no result")
        result = results[0]
        if result.status != "ok":
            raise PleskResultError(result.errcode or 0, result.errtext or "")

    # ------------------------------------------------------ administration (signup)
    # Used by the signup service with its own administrator key (PLESK_SIGNUP_API_KEY).
    # Status values: 0 active, 16 suspended by the administrator.
    STATUS_ACTIVE = 0
    STATUS_SUSPENDED_ADMIN = 16

    async def domain_exists(self, auth: Auth, name: str) -> str | None:
        """'webspace', 'site' or 'alias' when a domain with this name exists anywhere in Plesk, else None."""
        wanted = name.lower().rstrip(".")
        checks = (
            ("webspace", f"<webspace><get><filter><name>{escape(wanted)}</name></filter><dataset><gen_info/></dataset></get></webspace>", "./webspace/get/result"),
            ("site", f"<site><get><filter><name>{escape(wanted)}</name></filter><dataset><gen_info/></dataset></get></site>", "./site/get/result"),
            ("alias", f"<site-alias><get><filter><name>{escape(wanted)}</name></filter></get></site-alias>", "./site-alias/get/result"),
        )
        for kind, body, path in checks:
            root = await self.call(body, auth)
            for result in self._results(root, path):
                if result.status == "ok":
                    return kind
                if result.errcode not in (ERR_NOT_FOUND, None):
                    raise PleskResultError(result.errcode or 0, result.errtext or "")
        return None

    async def customer_exists(self, auth: Auth, login: str) -> bool:
        return await self.get_customer(login, auth) is not None

    async def customer_add(
        self,
        auth: Auth,
        *,
        login: str,
        password: str,
        pname: str,
        cname: str | None,
        email: str,
        phone: str | None,
        address: str,
        city: str,
        pcode: str,
        country: str,
        external_id: str | None = None,
    ) -> int:
        """`customer add`; returns the customer id. The password is sent once and never logged."""
        parts = []
        if cname:
            parts.append(f"<cname>{escape(cname)}</cname>")
        parts += [f"<pname>{escape(pname)}</pname>", f"<login>{escape(login)}</login>", f"<passwd>{escape(password)}</passwd>", "<status>0</status>"]
        if phone:
            parts.append(f"<phone>{escape(phone)}</phone>")
        parts += [f"<email>{escape(email)}</email>", f"<address>{escape(address)}</address>", f"<city>{escape(city)}</city>", f"<pcode>{escape(pcode)}</pcode>", f"<country>{escape(country)}</country>"]
        if external_id:
            parts.append(f"<external-id>{escape(external_id)}</external-id>")
        root = await self.call(f"<customer><add><gen_info>{''.join(parts)}</gen_info></add></customer>", auth)
        result = self._single(root, "./customer/add/result")
        if result.id is None:
            raise PleskError("customer add returned no id")
        return result.id

    async def customer_set_status(self, auth: Auth, login: str, status: int) -> None:
        root = await self.call(
            f"<customer><set><filter><login>{escape(login)}</login></filter><values><gen_info><status>{int(status)}</status></gen_info></values></set></customer>", auth
        )
        self._single(root, "./customer/set/result")

    async def customer_del(self, auth: Auth, login: str) -> bool:
        """`customer del` (removes the customer with all subscriptions). False when the customer no longer exists."""
        root = await self.call(f"<customer><del><filter><login>{escape(login)}</login></filter></del></customer>", auth)
        results = self._results(root, "./customer/del/result")
        if not results:
            raise PleskError("customer del returned no result")
        if results[0].status == "ok":
            return True
        if results[0].errcode == ERR_NOT_FOUND:
            return False
        raise PleskResultError(results[0].errcode or 0, results[0].errtext or "")

    async def webspace_add(self, auth: Auth, *, name: str, owner_login: str, ip_address: str, plan_name: str, ftp_login: str, ftp_password: str) -> int:
        """`webspace add` with hosting and a service plan; returns the webspace id."""
        body = (
            "<webspace><add><gen_setup>"
            f"<name>{escape(name)}</name><owner-login>{escape(owner_login)}</owner-login><htype>vrt_hst</htype>"
            f"<ip_address>{escape(ip_address)}</ip_address><status>0</status>"
            "</gen_setup><hosting><vrt_hst>"
            f"<property><name>ftp_login</name><value>{escape(ftp_login)}</value></property>"
            f"<property><name>ftp_password</name><value>{escape(ftp_password)}</value></property>"
            f"<ip_address>{escape(ip_address)}</ip_address>"
            f"</vrt_hst></hosting><plan-name>{escape(plan_name)}</plan-name></add></webspace>"
        )
        root = await self.call(body, auth)
        result = self._single(root, "./webspace/add/result")
        if result.id is None:
            raise PleskError("webspace add returned no id")
        return result.id

    async def webspace_del(self, auth: Auth, name: str) -> bool:
        root = await self.call(f"<webspace><del><filter><name>{escape(name)}</name></filter></del></webspace>", auth)
        results = self._results(root, "./webspace/del/result")
        if not results:
            raise PleskError("webspace del returned no result")
        if results[0].status == "ok":
            return True
        if results[0].errcode == ERR_NOT_FOUND:
            return False
        raise PleskResultError(results[0].errcode or 0, results[0].errtext or "")

    async def create_session(self, auth: Auth, *, login: str, user_ip: str, source_server: str | None = None) -> str:
        """`server create_session`: one-time session token for `login` (administrator key), used with rsession_init.php."""
        import base64

        data = f"<user_ip>{base64.b64encode(user_ip.encode()).decode()}</user_ip>"
        if source_server:
            data += f"<source_server>{base64.b64encode(source_server.encode()).decode()}</source_server>"
        root = await self.call(f"<server><create_session><login>{escape(login)}</login><data>{data}</data></create_session></server>", auth)
        result = self._single(root, "./server/create_session/result")
        token = _text(result.element.find("id"))
        if not token:
            raise PleskError("create_session returned no session id")
        return token
