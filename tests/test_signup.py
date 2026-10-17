"""Self-signup: order form protection, reBill/bexio/Netim/Zammad calls (faked), activation after payment,
suspension, unsuspension, cancellation, deletion, domain renewal, admin overview."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import fakeredis
import httpx
import pytest
from fakeredis import aioredis as fakeaioredis

from conftest import FakePlesk, FakeUser, base_env

pytestmark = pytest.mark.anyio

TODAY = date.today()


# ----------------------------------------------------------------------- fakes
STATUS_MAP = {7: "draft", 8: "pending", 9: "paid", 16: "partial", 19: "cancelled", 31: "unpaid"}


@dataclass
class FakeBexio:
    """What reBill would see in bexio: known contacts by e-mail and the status id of every invoice."""

    contacts: dict[str, int] = field(default_factory=dict)  # email -> bexio contact id
    invoices: dict[int, int] = field(default_factory=dict)  # invoice id -> kb_item_status_id
    created: list[dict[str, Any]] = field(default_factory=list)
    next_contact_id = 700


@dataclass
class FakeRebill:
    bexio: FakeBexio
    subscriptions: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, str, Any]] = field(default_factory=list)
    fail_create: bool = False
    next_invoice_id: int = 5000

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def add_invoice(self, ref: str, *, due_in_days: int = 30, kind: str = "recurring") -> int:
        self.next_invoice_id += 1
        self.subscriptions[ref]["invoices"].append(
            {"bexio_invoice_id": self.next_invoice_id, "created_at": time.strftime("%Y-%m-%d %H:%M:%S"), "due_date": (TODAY + timedelta(days=due_in_days)).isoformat(), "payment_status": "unknown", "overdue_days": 0, "kind": kind}
        )
        return self.next_invoice_id

    def _sync(self, sub: dict[str, Any]) -> dict[str, int]:
        """Same rules as reBill's PaymentStatusSync: terminal states are never downgraded, unknown invoices count as failed."""
        checked = updated = failed = 0
        for inv in sub["invoices"]:
            checked += 1
            status_id = self.bexio.invoices.get(inv["bexio_invoice_id"])
            if status_id is None:
                failed += 1
                continue
            status = STATUS_MAP.get(status_id, "unknown")
            if inv["payment_status"] in ("paid", "cancelled"):
                continue
            if inv["payment_status"] != status:
                updated += 1
            inv["payment_status"] = status
        return {"checked": checked, "updated": updated, "failed": failed}

    def _handle(self, request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == "Bearer rbl_test"
        path = request.url.path
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, path, body))
        if request.method == "POST" and path == "/api/v1/subscriptions":
            if self.fail_create:
                return httpx.Response(500, json={"message": "boom"})
            ref = body["external_ref"]
            if ref in self.subscriptions:
                return httpx.Response(409, json={"message": "exists", "subscription": self.subscriptions[ref]})
            contact = body["contact"]
            assert contact["email"] and contact["country_code"] and contact["type"] in ("company", "private")
            assert (contact["type"] == "company") == bool(contact.get("company_name"))
            assert body["interval"] == "yearly" and body["lead_months"] == 1 and body["mwst_type"] == 0 and body["run_now"] is True
            assert body["items"][0]["text"] == "AI Hosting {{year}}/{{nextYear}}" and body["items"][0]["unit_price"] == 60.0
            # reBill matches the bexio contact by e-mail, otherwise it creates one on the first run
            bexio_id = self.bexio.contacts.get(contact["email"])
            if bexio_id is None:
                FakeBexio.next_contact_id += 1
                bexio_id = FakeBexio.next_contact_id
                self.bexio.contacts[contact["email"]] = bexio_id
                self.bexio.created.append(contact)
            start = date.fromisoformat(body["start_date"])
            sub = {
                "external_ref": ref,
                "recurring_id": 100 + len(self.subscriptions),
                "is_active": True,
                "interval": "yearly",
                "lead_months": body["lead_months"],
                "start_date": start.isoformat(),
                "next_run_date": start.isoformat(),
                "next_period_start": start.replace(year=start.year + 1).isoformat(),
                "contact_email": contact["email"],
                "contact_bexio_id": bexio_id,
                "items": body["items"],
                "invoices": [],
            }
            self.subscriptions[ref] = sub
            # run_now queues the first invoice; the fake issues it right away like the queue worker would
            self.add_invoice(ref)
            return httpx.Response(201, json={"subscription": sub, "first_invoice_queued": True})
        m = re.match(r"^/api/v1/subscriptions/([^/]+)$", path)
        if m and request.method == "GET":
            sub = self.subscriptions.get(m.group(1))
            if sub is None:
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(200, json={"subscription": sub})
        m = re.match(r"^/api/v1/subscriptions/([^/]+)/sync-payments$", path)
        if m and request.method == "POST":
            sub = self.subscriptions.get(m.group(1))
            if sub is None:
                return httpx.Response(404, json={"message": "not found"})
            return httpx.Response(200, json={"synced": self._sync(sub), "subscription": sub})
        return httpx.Response(404, json={"message": f"unexpected {request.method} {path}"})


@dataclass
class FakeNetim:
    available: dict[str, bool] = field(default_factory=dict)
    contacts: list[dict[str, Any]] = field(default_factory=list)
    operations: dict[int, str] = field(default_factory=dict)
    domains: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, str, Any]] = field(default_factory=list)
    register_status: str = "Done"
    fail_register: bool = False
    next_op = 9000

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content else None
        if path == "/1.0/session/" and request.method == "POST":
            assert request.headers.get("authorization", "").startswith("Basic ")
            return httpx.Response(200, json={"access_token": "netim-token"})
        if path == "/1.0/session/" and request.method == "DELETE":
            return httpx.Response(200, json={})
        assert request.headers.get("authorization") == "Bearer netim-token"
        self.calls.append((request.method, path, body))
        m = re.match(r"^/1.0/domain/([^/]+)/check/$", path)
        if m:
            d = m.group(1)
            return httpx.Response(200, json=[{"domain": d, "result": "AVAILABLE" if self.available.get(d, True) else "NOT AVAILABLE", "reason": ""}])
        if path == "/1.0/contact/" and request.method == "POST":
            contact = body["contact"]
            assert contact["isOwner"] == 1 and contact["bodyForm"] in ("IND", "ORG") and contact["phone"].startswith("+")
            self.contacts.append(contact)
            return httpx.Response(200, json=f"OWN{len(self.contacts):04d}")
        m = re.match(r"^/1.0/domain/([^/]+)/$", path)
        if m and request.method == "POST":
            if self.fail_register:
                return httpx.Response(200, json={"ID_OPE": 0, "STATUS": "Failed", "MESSAGE": "registry refused", "TYPE": "domainCreate"})
            assert body["idOwner"].startswith("OWN") and body["idAdmin"] == "ADM1" and body["duration"] == 1 and body["ns1"] == "ns1.example.net"
            FakeNetim.next_op += 1
            self.operations[FakeNetim.next_op] = self.register_status
            self.domains[m.group(1)] = {"dateExpiration": (TODAY + timedelta(days=365)).isoformat(), "status": "ok"}
            return httpx.Response(200, json={"ID_OPE": FakeNetim.next_op, "STATUS": self.register_status, "MESSAGE": "", "TYPE": "domainCreate"})
        m = re.match(r"^/1.0/domain/([^/]+)/preference/$", path)
        if m:
            self.domains.setdefault(m.group(1), {})["autoRenew"] = body["value"]
            return httpx.Response(200, json={"ID_OPE": 1, "STATUS": "Done"})
        m = re.match(r"^/1.0/domain/([^/]+)/info/$", path)
        if m:
            return httpx.Response(200, json=self.domains.get(m.group(1), {}))
        m = re.match(r"^/1.0/domain/([^/]+)/renew/$", path)
        if m:
            d = self.domains[m.group(1)]
            exp = date.fromisoformat(d["dateExpiration"])
            d["dateExpiration"] = exp.replace(year=exp.year + 1).isoformat()
            return httpx.Response(200, json={"ID_OPE": 77, "STATUS": "Done"})
        m = re.match(r"^/1.0/operation/(\d+)$", path)
        if m:
            return httpx.Response(200, json={"ID_OPE": int(m.group(1)), "STATUS": self.operations.get(int(m.group(1)), "Pending")})
        return httpx.Response(404, json={"message": f"unexpected {request.method} {path}"})


@dataclass
class FakeZammad:
    tickets: dict[int, dict[str, Any]] = field(default_factory=dict)
    notes: list[tuple[int, str]] = field(default_factory=list)

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def _handle(self, request: httpx.Request) -> httpx.Response:
        assert request.headers.get("authorization") == "Token token=zammad_test"
        body = json.loads(request.content)
        if request.url.path == "/api/v1/tickets":
            assert body["group"] == "Web TAB" and body["customer_id"].startswith("guess:") and body["article"]["internal"] is True and body["article"]["type"] == "note"
            tid = 4000 + len(self.tickets)
            self.tickets[tid] = body
            return httpx.Response(201, json={"id": tid, "title": body["title"]})
        if request.url.path == "/api/v1/ticket_articles":
            assert body["internal"] is True and body["type"] == "note"
            self.notes.append((body["ticket_id"], body["body"]))
            return httpx.Response(201, json={"id": len(self.notes)})
        return httpx.Response(404, json={})


class FakeMailer:
    def __init__(self):
        self.sent: list[dict[str, str]] = []
        self.fail = False

    async def send(self, *, to: str, subject: str, text: str) -> None:
        from pleskmcp.signup.clients import ExternalError

        if self.fail:
            raise ExternalError("smtp", "send_failed", "ConnectionRefusedError")
        self.sent.append({"to": to, "subject": subject, "text": text})


@dataclass
class SignupEnv:
    client: httpx.AsyncClient
    services: Any
    plesk: FakePlesk
    rebill: FakeRebill
    bexio: FakeBexio
    netim: FakeNetim
    zammad: FakeZammad
    mailer: FakeMailer
    redis: Any
    tmp: Path

    @property
    def service(self):
        return self.services.signup


SIGNUP_ENV = {
    "SIGNUP_ENABLED": "true",
    "SIGNUP_ALLOWED_ORIGINS": "https://www.example.com",
    "SIGNUP_TERMS_VERSION": "2026-10",
    "SIGNUP_TERMS_URL": "https://www.example.com/agb/",
    "SIGNUP_MIN_FILL_SECONDS": "0",
    "SIGNUP_RATE_LIMIT_IP": "20",
    "SIGNUP_RATE_LIMIT_EMAIL": "4",
    "SIGNUP_ADMIN_USER": "admin",
    "SIGNUP_ADMIN_PASSWORD": "adminpw",
    "REBILL_API_URL": "https://rebill.example.com/api/v1",
    "REBILL_API_TOKEN": "rbl_test",
    "BEXIO_API_TOKEN": "bexio_test",
    "BEXIO_USER_ID": "3",
    "NETIM_LOGIN": "reseller",
    "NETIM_SECRET": "secret",
    "NETIM_CONTACT_ADMIN": "ADM1",
    "NETIM_CONTACT_TECH": "TEC1",
    "NETIM_CONTACT_BILLING": "BIL1",
    "NETIM_NAMESERVERS": "ns1.example.net,ns2.example.net",
    "PLESK_SIGNUP_API_KEY": "admin-key",
    "PLESK_SIGNUP_IP": "203.0.113.10",
    "PLESK_PANEL_URL": "https://plesk.example.com:8443",
    "ZAMMAD_URL": "https://support.example.com",
    "ZAMMAD_TOKEN": "zammad_test",
    "SMTP_HOST": "mail.example.com",
    "MAIL_FROM": "Example Hosting <hosting@example.com>",
}


@pytest.fixture
async def senv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    for key, value in {**base_env(tmp_path), **SIGNUP_ENV}.items():
        monkeypatch.setenv(key, value)
    from pleskmcp.config import Settings
    from pleskmcp.db import Store, make_engine
    from pleskmcp.server import build_app, build_services

    plesk = FakePlesk()
    plesk.users["admin"] = FakeUser(password="adminpw", type="admin")
    plesk.users["muster"] = FakeUser(password="x", name="Max Muster", base=400, domains=[{"name": "bestand.example", "sysuser": "bestand_sys", "docroot": "/var/www/vhosts/bestand.example/httpdocs"}])
    plesk.aliases.add("alias.example")
    bexio = FakeBexio(contacts={"bestand@example.com": 55})
    rebill, netim, zammad, mailer = FakeRebill(bexio), FakeNetim(), FakeZammad(), FakeMailer()
    settings = Settings.load()
    assert settings.signup is not None and settings.signup.new_domains_enabled
    server = fakeredis.FakeServer()
    redis = fakeaioredis.FakeRedis(server=server, decode_responses=True)
    store = Store(make_engine(settings.database_url))
    await store.create_all()
    services = build_services(
        settings,
        store=store,
        redis=redis,
        plesk_transport=plesk.transport(),
        signup_transports={"rebill": rebill.transport(), "netim": netim.transport(), "zammad": zammad.transport()},
        signup_mailer=mailer,
    )
    app = build_app(services)
    try:
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.com", headers={"host": "mcp.example.com"}) as client:
                yield SignupEnv(client, services, plesk, rebill, bexio, netim, zammad, mailer, redis, tmp_path)
    finally:
        await services.close()


FORM = {
    "company": "",
    "first_name": "Anna",
    "last_name": "Beispiel",
    "street": "Musterstrasse 1",
    "zip": "8000",
    "city": "Zürich",
    "country": "CH",
    "email": "anna@example.com",
    "phone": "+41 44 123 45 67",
    "domain_mode": "new",
    "domain": "anna-beispiel.ch",
    "terms": "1",
    "website": "",
}


async def token(senv: SignupEnv) -> str:
    r = await senv.client.get("/plesk/signup/token", headers={"origin": "https://www.example.com"})
    assert r.status_code == 200 and r.headers["access-control-allow-origin"] == "https://www.example.com"
    return r.json()["token"]


async def order(senv: SignupEnv, **overrides: Any) -> httpx.Response:
    form = {**FORM, **overrides}
    form.setdefault("token", await token(senv))
    return await senv.client.post("/plesk/signup", json=form, headers={"origin": "https://www.example.com", "accept": "application/json"})


def status_of(senv: SignupEnv, order_id: str):
    return senv.service.store.get(order_id)


# ----------------------------------------------------------------------- tests
async def test_config_and_price_list(senv: SignupEnv):
    r = await senv.client.get("/plesk/signup/config", headers={"origin": "https://www.example.com"})
    data = r.json()
    assert r.status_code == 200 and data["terms_version"] == "2026-10" and data["price_list"]["hosting"]["price_per_year"] == 60.0
    tlds = {t["tld"]: t for t in data["price_list"]["tlds"]}
    assert tlds["ch"]["orderable"] and tlds["ch"]["price_per_year"] == 13.5 and not tlds["swiss"]["orderable"]
    # other origins get no CORS header
    r = await senv.client.get("/plesk/signup/config", headers={"origin": "https://evil.example"})
    assert "access-control-allow-origin" not in r.headers


async def test_domain_check(senv: SignupEnv):
    senv.netim.available["taken.ch"] = False
    r = await senv.client.get("/plesk/signup/check-domain", params={"domain": "Frei.CH"})
    assert r.json() == {"ok": True, "domain": "frei.ch", "orderable": True, "available": True, "price_per_year": 13.5, "currency": "CHF", "owner_fields": ["phone"]}
    r = await senv.client.get("/plesk/signup/check-domain", params={"domain": "taken.ch"})
    assert r.json()["available"] is False
    r = await senv.client.get("/plesk/signup/check-domain", params={"domain": "firma.swiss"})
    assert r.json()["orderable"] is False and r.json()["available"] is None
    r = await senv.client.get("/plesk/signup/check-domain", params={"domain": "not a domain"})
    assert r.status_code == 400
    r = await senv.client.get("/plesk/signup/check-domain", params={"domain": "sub.frei.ch"})
    assert r.status_code == 400 and "Subdomain" in r.json()["message"]


async def test_form_abuse_is_rejected(senv: SignupEnv):
    # honeypot: looks like success, creates nothing
    r = await order(senv, website="http://spam.example")
    assert r.status_code == 200 and r.json()["ok"]
    assert await senv.service.store.list() == []
    # token missing / forged / replayed
    r = await order(senv, token="")
    assert r.status_code == 400 and r.json()["error"] == "token_invalid"
    t = await token(senv)
    r = await order(senv, token=t[:-3] + "xyz")
    assert r.status_code == 400 and r.json()["error"] == "token_invalid"
    r = await order(senv, token=t, domain="erste.ch")
    assert r.status_code == 200, r.text
    r = await order(senv, token=t, domain="zweite.ch")
    assert r.status_code == 400 and r.json()["error"] == "token_replayed"
    # too fast
    senv.service.cfg.__dict__["min_fill_seconds"] = 60
    r = await order(senv, domain="dritte.ch")
    assert r.status_code == 400 and r.json()["error"] == "token_too_fast"
    senv.service.cfg.__dict__["min_fill_seconds"] = 0
    # validation: missing terms, bad email, phone required for a new domain, TLD not orderable
    r = await order(senv, terms="", email="nope", phone="", domain="vierte.swiss")
    assert r.status_code == 422
    errors = r.json()["errors"]
    assert set(errors) >= {"terms", "email", "domain"}
    r = await order(senv, phone="", domain="vierte.ch")
    assert r.status_code == 422 and "Telefon" in r.json()["errors"]["phone"]
    # foreign origin
    r = await senv.client.post("/plesk/signup", json={**FORM, "token": await token(senv)}, headers={"origin": "https://evil.example"})
    assert r.status_code == 403
    # http is refused
    r = await senv.client.post("/plesk/signup", json={**FORM, "token": await token(senv)}, headers={"origin": "https://www.example.com", "x-forwarded-proto": "http"})
    assert r.status_code == 400 and r.json()["error"] == "https_required"
    # per e-mail limit (4 per day in this test): only orders that passed validation count (erste.ch so far)
    for d in ("fuenfte.ch", "sechste.ch", "siebte.ch"):
        r = await order(senv, domain=d)
        assert r.status_code == 200, r.text
    r = await order(senv, domain="achte.ch")
    assert r.status_code == 429 and r.json()["error"] == "rate_limited"


async def test_own_domain_duplicate_checks(senv: SignupEnv):
    r = await order(senv, domain_mode="own", domain="bestand.example")
    assert r.status_code == 422 and r.json()["error"] == "domain_exists"
    r = await order(senv, domain_mode="own", domain="alias.example")
    assert r.status_code == 422 and r.json()["error"] == "domain_exists"
    r = await order(senv, domain_mode="own", domain="www.Meine-Firma.example.", phone="")
    assert r.status_code == 200, r.text
    first = r.json()
    assert first["domain"] == "meine-firma.example" and first["created"]
    # same customer, same domain again: the existing order is returned, nothing new is created
    r = await order(senv, domain_mode="own", domain="meine-firma.example")
    assert r.status_code == 200 and r.json()["order_id"] == first["order_id"] and r.json()["created"] is False
    # someone else ordering the same domain is rejected without revealing anything about the first customer
    r = await order(senv, domain_mode="own", domain="meine-firma.example", email="other@example.com")
    assert r.status_code == 422 and r.json()["error"] == "domain_ordered" and "anna" not in r.text
    assert len(senv.rebill.subscriptions) == 1
    # the thanks page knows the order
    r = await senv.client.get(f"/plesk/signup/thanks/{first['order_id']}")
    assert r.status_code == 200 and "meine-firma.example" in r.text and "anna@example.com" in r.text


async def test_new_domain_unavailable(senv: SignupEnv):
    senv.netim.available["belegt.ch"] = False
    r = await order(senv, domain="belegt.ch")
    assert r.status_code == 422 and r.json()["error"] == "domain_unavailable"
    assert await senv.service.store.list() == []


async def test_order_billing_and_ticket(senv: SignupEnv):
    r = await order(senv, company="Beispiel AG")
    assert r.status_code == 200, r.text
    o = await status_of(senv, r.json()["order_id"])
    assert o.status == "awaiting_payment" and o.terms_version == "2026-10" and o.domain_price == 13.5
    # reBill: contact passed as company with ISO country, subscription with both items, invoice known, Zammad ticket with internal note
    assert senv.bexio.created[0] == {"type": "company", "company_name": "Beispiel AG", "email": "anna@example.com", "address": "Musterstrasse 1", "postcode": "8000", "city": "Zürich", "country_code": "CH"}
    assert o.bexio_contact_id == senv.bexio.contacts["anna@example.com"]
    sub = senv.rebill.subscriptions[f"aihosting-{o.id}"]
    assert o.rebill_recurring_id == sub["recurring_id"] and len(sub["items"]) == 2 and sub["items"][1] == {"text": "Domain anna-beispiel.ch", "amount": 1, "unit_price": 13.5}
    assert o.bexio_invoice_id == 5001 and o.period_end == (TODAY.replace(year=TODAY.year + 1) - timedelta(days=1)).isoformat()
    assert o.zammad_ticket_id in senv.zammad.tickets
    article = senv.zammad.tickets[o.zammad_ticket_id]["article"]["body"]
    assert "anna-beispiel.ch" in article and "5001" in article and f"aihosting-{o.id}" in article
    # an existing bexio contact (matched by reBill via e-mail) is reused, not duplicated
    r = await order(senv, email="bestand@example.com", domain="zweite.ch")
    o2 = await status_of(senv, r.json()["order_id"])
    assert o2.bexio_contact_id == 55 and len(senv.bexio.created) == 1
    # private customers are passed with first and last name
    assert senv.rebill.subscriptions[f"aihosting-{o2.id}"]["contact_email"] == "bestand@example.com"
    # audit events carry ids only
    events = await senv.service.store.events(o.id)
    assert {e["event"] for e in events} >= {"order_created", "rebill_subscription", "zammad_ticket"}
    assert "anna" not in json.dumps(events)
    audit = open(senv.services.settings.audit_log_file, encoding="utf-8").read()
    assert "signup_order_created" in audit and "anna@example.com" not in audit


async def test_unpaid_stays_waiting_then_paid_activates(senv: SignupEnv):
    r = await order(senv)
    o = await status_of(senv, r.json()["order_id"])
    senv.bexio.invoices[o.bexio_invoice_id] = 8  # pending
    assert await senv.service.run_payment_polls() == 1
    o = await status_of(senv, o.id)
    assert o.status == "awaiting_payment" and o.last_invoice_status == "open" and not senv.plesk.created_customers and not senv.mailer.sent

    senv.bexio.invoices[o.bexio_invoice_id] = 9  # paid
    await senv.service.run_payment_polls()
    o = await status_of(senv, o.id)
    assert o.status == "active", (o.status, o.last_error)
    # 1. Netim: owner contact from the form, registration with configured contacts and nameservers, auto renew off
    assert senv.netim.contacts[0]["lastName"] == "Beispiel" and senv.netim.contacts[0]["bodyForm"] == "IND" and senv.netim.contacts[0]["country"] == "CH"
    assert o.netim_owner_contact_id == "OWN0001" and o.domain_status == "registered" and o.domain_expires == (TODAY + timedelta(days=365)).isoformat()
    assert senv.netim.domains["anna-beispiel.ch"]["autoRenew"] == "0"
    # 2. Plesk: customer with a derived login, subscription with the plan; no password anywhere in the order or mail
    assert senv.plesk.created_customers[0]["login"] == "beispiel" and senv.plesk.created_customers[0]["pname"] == "Anna Beispiel" and senv.plesk.created_customers[0]["country"] == "CH"
    ws = senv.plesk.created_webspaces[0]
    assert ws == {"name": "anna-beispiel.ch", "owner": "beispiel", "plan": "AI Hosting", "ftp_login": o.sysuser, "ip": "203.0.113.10", "id": ws["id"]}
    assert o.plesk_login == "beispiel" and o.plesk_webspace_id == ws["id"] and o.sysuser.startswith("annabeispi_")
    assert "passwd" not in json.dumps(o.data) and senv.plesk.users["beispiel"].password not in json.dumps(o.data)
    # 3./4. welcome mail: password link, panel URL, nameservers, AI guide, account page, real umlauts
    mail = senv.mailer.sent[0]
    assert mail["to"] == "anna@example.com" and "anna-beispiel.ch" in mail["subject"]
    link = re.search(r"https://mcp\.example\.com/plesk/signup/welcome/([A-Za-z0-9_-]+)", mail["text"]).group(1)
    assert "https://plesk.example.com:8443/login_up.php" in mail["text"] and "Benutzername: beispiel" in mail["text"]
    assert "ns1.example.net, ns2.example.net" in mail["text"] and "https://mcp.example.com/plesk/mcp" in mail["text"] and "Entwicklermodus" in mail["text"]
    assert "https://mcp.example.com/plesk/account" in mail["text"] and "Grüsse" in mail["text"] and "Zürich" not in mail["text"]
    assert senv.plesk.users["beispiel"].password not in mail["text"]
    # 5. Zammad note "aktiviert" with the subscription id
    assert any("aktiviert" in n and str(ws["id"]) in n for _, n in senv.zammad.notes)
    # the welcome link logs in once via create_session and is then used up
    r = await senv.client.get(f"/plesk/signup/welcome/{link}")
    assert r.status_code == 303 and r.headers["location"].startswith("https://plesk.example.com:8443/enterprise/rsession_init.php?PLESKSESSID=sess-")
    assert len(senv.plesk.sessions) == 1
    r = await senv.client.get(f"/plesk/signup/welcome/{link}")
    assert r.status_code == 410 and "get_password.php" in r.text
    # a second poll changes nothing (idempotent)
    await senv.service.run_payment_polls()
    assert len(senv.plesk.created_customers) == 1 and len(senv.mailer.sent) == 1 and len(senv.netim.contacts) == 1


async def test_activation_retries_and_needs_attention(senv: SignupEnv):
    r = await order(senv, domain_mode="own", domain="eigene.example", phone="")
    o = await status_of(senv, r.json()["order_id"])
    senv.bexio.invoices[o.bexio_invoice_id] = 9
    senv.mailer.fail = True
    await senv.service.run_payment_polls()
    o = await status_of(senv, o.id)
    # Plesk objects exist, the mail failed: order waits for the next attempt, nothing is created twice
    assert o.status == "awaiting_payment" and o.paid_at and o.plesk_webspace_id and o.attempts == 1 and o.last_error.startswith("activation: smtp:send_failed")
    await senv.service.run_payment_polls()
    assert len(senv.plesk.created_customers) == 1 and len(senv.plesk.created_webspaces) == 1
    senv.mailer.fail = False
    await senv.service.run_payment_polls()
    o = await status_of(senv, o.id)
    assert o.status == "active" and len(senv.mailer.sent) == 1 and "A-Record" in senv.mailer.sent[0]["text"] and "203.0.113.10" in senv.mailer.sent[0]["text"]

    # a non-retryable failure (registry refuses the domain) goes to needs_attention with a Zammad note
    senv.netim.fail_register = True
    r = await order(senv, email="b@example.com", domain="abgelehnt.ch")
    o2 = await status_of(senv, r.json()["order_id"])
    senv.bexio.invoices[o2.bexio_invoice_id] = 9
    await senv.service.run_payment_polls()
    o2 = await status_of(senv, o2.id)
    assert o2.status == "needs_attention" and o2.attention_reason == "activation_failed" and o2.domain_status == "failed" and not o2.plesk_customer_id
    assert any("Aufmerksamkeit" in n for t, n in senv.zammad.notes if t == o2.zammad_ticket_id)
    # retry from the admin page after fixing the cause
    senv.netim.fail_register = False
    page = await senv.client.get("/plesk/signup/admin")
    assert page.status_code == 401
    auth = {"authorization": "Basic " + __import__("base64").b64encode(b"admin:adminpw").decode()}
    page = await senv.client.get("/plesk/signup/admin", headers=auth)
    assert page.status_code == 200 and "abgelehnt.ch" in page.text and "manuelle Prüfung" in page.text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = await senv.client.post("/plesk/signup/admin/action", data={"csrf": csrf, "order_id": o2.id, "action": "retry"}, headers=auth)
    assert r.status_code == 200 and "erneut" in r.text
    await senv.service.run_payment_polls()
    o2 = await status_of(senv, o2.id)
    assert o2.status == "active" and o2.domain_status == "registered"


async def activate(senv: SignupEnv, **overrides: Any):
    r = await order(senv, **overrides)
    assert r.status_code == 200, r.text
    o = await status_of(senv, r.json()["order_id"])
    senv.bexio.invoices[o.bexio_invoice_id] = 9
    await senv.service.run_payment_polls()
    o = await status_of(senv, o.id)
    assert o.status == "active", (o.status, o.last_error)
    return o


async def test_renewal_invoice_unpaid_suspends_and_payment_unsuspends(senv: SignupEnv):
    o = await activate(senv)
    ref = f"aihosting-{o.id}"
    # follow-up invoice one month before the next period, due in 30 days: nothing happens while it is open and not overdue
    inv = senv.rebill.add_invoice(ref, due_in_days=30)
    senv.bexio.invoices[inv] = 8
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert o.status == "active" and o.last_invoice_id == inv and o.last_invoice_status == "open"
    # overdue 10 days: still active; day 11: suspended in Plesk + note
    senv.rebill.subscriptions[ref]["invoices"][-1]["due_date"] = (TODAY - timedelta(days=10)).isoformat()
    await senv.service.run_lifecycle()
    assert (await status_of(senv, o.id)).status == "active"
    senv.rebill.subscriptions[ref]["invoices"][-1]["due_date"] = (TODAY - timedelta(days=11)).isoformat()
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert o.status == "suspended" and o.suspend_reason == "unpaid" and senv.plesk.users["beispiel"].status == 16
    assert any("gesperrt" in n and str(inv) in n for _, n in senv.zammad.notes)
    # payment after suspension: unsuspended + note
    senv.bexio.invoices[inv] = 9
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert o.status == "active" and senv.plesk.users["beispiel"].status == 0 and any("freigeschaltet" in n for _, n in senv.zammad.notes)


async def test_cancellation_and_deletion(senv: SignupEnv):
    o = await activate(senv, domain_mode="own", domain="kuendigung.example", phone="")
    ref = f"aihosting-{o.id}"
    sub = senv.rebill.subscriptions[ref]
    # the subscription is deactivated in reBill (cancellation); the paid term still runs: stays active
    sub["is_active"] = False
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert o.status == "active" and o.subscription_active is False and o.cancelled_at
    # term over: suspended with reason cancelled
    sub["next_period_start"] = (TODAY - timedelta(days=1)).isoformat()
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert o.status == "suspended" and o.suspend_reason == "cancelled" and o.delete_after
    # 60 days later (default mode plesk): pending_deletion, pleskbackup via the REST CLI gateway, deletion on the next pass
    await senv.service.store.update(o.id, delete_after=int(time.time()) - 1)
    await senv.service.run_lifecycle()
    await senv.service.wait_for_backups()
    o = await status_of(senv, o.id)
    assert o.status == "pending_deletion" and "beispiel" in senv.plesk.users and o.backup_done_at and "backup_info" in o.backup_result
    assert senv.plesk.cli_calls == [{"utility": "pleskbackup", "params": ["--domains-name", "kuendigung.example", "-prefix", "pleskmcp", "-description", f"PleskMCP signup {o.id}: Sicherung vor der Loeschung"], "fail_on_error": False}]
    assert any("Backup des Abos" in n for _, n in senv.zammad.notes)
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert o.status == "deleted" and "beispiel" not in senv.plesk.users and any("gelöscht" in n for _, n in senv.zammad.notes)

    # a failing backup goes to needs_attention and never deletes
    o3 = await activate(senv, email="d@example.com", domain_mode="own", domain="backupfehler.example", phone="")
    await senv.service.store.update(o3.id, status="suspended", suspend_reason="unpaid", suspended_at=int(time.time()) - 100, delete_after=int(time.time()) - 1)
    senv.bexio.invoices[senv.rebill.add_invoice(f"aihosting-{o3.id}", due_in_days=-20)] = 8  # a newer, open invoice (paid ones are never downgraded)
    senv.plesk.cli_fail = True
    await senv.service.run_lifecycle()
    await senv.service.wait_for_backups()
    o3 = await status_of(senv, o3.id)
    assert o3.status == "needs_attention" and o3.attention_reason == "backup_failed" and o3.plesk_login in senv.plesk.users
    senv.plesk.cli_fail = False

    # manual mode: pending_deletion with a note, nothing deleted until the admin confirms
    senv.service.cfg.__dict__["delete_backup_mode"] = "manual"
    o = await activate(senv, email="e@example.com", domain_mode="own", domain="manuell.example", phone="")
    await senv.service.store.update(o.id, status="suspended", suspend_reason="unpaid", suspended_at=int(time.time()) - 100, delete_after=int(time.time()) - 1)
    senv.bexio.invoices[senv.rebill.add_invoice(f"aihosting-{o.id}", due_in_days=-20)] = 8  # a newer, open invoice (paid ones are never downgraded)
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert o.status == "pending_deletion" and o.plesk_login in senv.plesk.users and any("Admin-Übersicht" in n for _, n in senv.zammad.notes)
    # admin confirms -> Plesk subscription and customer gone, status deleted, note
    auth = {"authorization": "Basic " + __import__("base64").b64encode(b"admin:adminpw").decode()}
    page = await senv.client.get("/plesk/signup/admin", headers=auth)
    csrf = re.search(r'name="csrf" value="([^"]+)"', page.text).group(1)
    r = await senv.client.post("/plesk/signup/admin/action", data={"csrf": csrf, "order_id": o.id, "action": "confirm_delete"}, headers=auth)
    assert r.status_code == 200
    o = await status_of(senv, o.id)
    assert o.status == "deleted" and o.plesk_login not in senv.plesk.users
    # mode none deletes without backup or confirmation
    senv.service.cfg.__dict__["delete_backup_mode"] = "none"
    o2 = await activate(senv, email="c@example.com", domain_mode="own", domain="auto.example", phone="")
    await senv.service.store.update(o2.id, status="suspended", suspend_reason="unpaid", suspended_at=int(time.time()) - 100, delete_after=int(time.time()) - 1)
    senv.bexio.invoices[senv.rebill.add_invoice(f"aihosting-{o2.id}", due_in_days=-20)] = 8  # a newer, open invoice (paid ones are never downgraded)
    await senv.service.run_lifecycle()
    assert (await status_of(senv, o2.id)).status == "deleted"


async def test_domain_renewal_only_when_paid(senv: SignupEnv):
    o = await activate(senv)
    ref = f"aihosting-{o.id}"
    # expiry is 365 days away: no renewal yet
    await senv.service.run_lifecycle()
    assert not any("renew" in c[1] for c in senv.netim.calls)
    # 20 days before expiry, current period invoice paid: renewed once, note written
    senv.netim.domains["anna-beispiel.ch"]["dateExpiration"] = (TODAY + timedelta(days=20)).isoformat()
    await senv.service.store.update(o.id, domain_expires=(TODAY + timedelta(days=20)).isoformat())
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert sum(1 for c in senv.netim.calls if c[1].endswith("/renew/")) == 1 and o.domain_renewed_until == (TODAY + timedelta(days=20)).isoformat()
    assert any("verlängert" in n for _, n in senv.zammad.notes)
    await senv.service.run_lifecycle()
    assert sum(1 for c in senv.netim.calls if c[1].endswith("/renew/")) == 1
    # next year: invoice unpaid -> not renewed, one note
    senv.netim.domains["anna-beispiel.ch"]["dateExpiration"] = (TODAY + timedelta(days=10)).isoformat()
    await senv.service.store.update(o.id, domain_expires=(TODAY + timedelta(days=10)).isoformat(), domain_renewed_until=None)
    inv = senv.rebill.add_invoice(ref, due_in_days=5)
    senv.bexio.invoices[inv] = 8
    await senv.service.run_lifecycle()
    await senv.service.run_lifecycle()
    assert sum(1 for c in senv.netim.calls if c[1].endswith("/renew/")) == 1
    assert sum(1 for _, n in senv.zammad.notes if "NICHT verlängert" in n) == 1


async def test_pending_registration_is_followed_up(senv: SignupEnv):
    senv.netim.register_status = "Pending"
    o = await activate(senv)
    assert o.domain_status == "pending" and o.netim_operation_id in senv.netim.operations
    await senv.service.run_lifecycle()
    assert (await status_of(senv, o.id)).domain_status == "pending"
    senv.netim.operations[o.netim_operation_id] = "Done"
    await senv.service.run_lifecycle()
    o = await status_of(senv, o.id)
    assert o.domain_status == "registered" and o.domain_expires and any("registriert" in n for _, n in senv.zammad.notes)


async def test_billing_failure_is_retried_by_the_scheduler(senv: SignupEnv):
    senv.rebill.fail_create = True
    r = await order(senv)
    assert r.status_code == 200
    o = await status_of(senv, r.json()["order_id"])
    assert o.status == "awaiting_payment" and not o.rebill_recurring_id and o.attempts == 1
    senv.rebill.fail_create = False
    await senv.service.run_payment_polls()
    o = await status_of(senv, o.id)
    assert o.rebill_recurring_id and o.zammad_ticket_id and o.bexio_invoice_id and o.bexio_contact_id and o.last_invoice_status == "unknown"
    assert len(senv.rebill.subscriptions) == 1 and len(senv.bexio.created) == 1


async def test_readyz_and_cli_listing(senv: SignupEnv):
    r = await senv.client.get("/plesk/readyz")
    assert r.json()["checks"]["signup"] == "enabled"
    await order(senv)
    from pleskmcp.signup.web import admin_json

    text = admin_json(await senv.service.store.list())
    assert "anna-beispiel.ch" in text and "welcome_token_hash" not in text
