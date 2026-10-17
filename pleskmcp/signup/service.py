"""Order, activation and lifecycle flows of the signup service.

Every external step is idempotent: the order row stores the external identifiers,
a step that already has its id is skipped, a failed step is retried by the
scheduler until SIGNUP_MAX_ATTEMPTS, then the order goes to needs_attention and
the Zammad ticket gets an internal note. A Redis lock per order keeps two
scheduler ticks (or a tick and an admin action) from working on the same order.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import secrets
import string
import time
from contextlib import asynccontextmanager
from datetime import date, timedelta
from typing import Any, AsyncIterator

from redis.asyncio import Redis

from ..audit import AuditLog
from ..config import Settings
from ..plesk_api import KeyAuth, PleskClient, PleskError, PleskResultError, PleskSystemError
from .clients import BexioClient, ExternalError, Mailer, NetimClient, PleskRestClient, RebillClient, ZammadClient
from .config import SignupSettings
from .forms import OrderInput, ascii_slug
from .pricelist import PriceList
from .store import (
    ACTIVATING,
    ACTIVE,
    AWAITING_PAYMENT,
    DELETED,
    NEEDS_ATTENTION,
    PENDING_DELETION,
    SUSPENDED,
    Order,
    SignupStore,
)
from .templates import render_welcome

logger = logging.getLogger(__name__)

LOCK_TTL = 600


class OrderRejected(Exception):
    """The order cannot be accepted; `field` names the form field, `message` is shown to the customer."""

    def __init__(self, code: str, field: str, message: str):
        super().__init__(code)
        self.code = code
        self.field = field
        self.message = message


class Busy(Exception):
    pass


def _today() -> date:
    return date.today()


def _iso(d: date) -> str:
    return d.isoformat()


def _parse(d: str | None) -> date | None:
    if not d:
        return None
    try:
        return date.fromisoformat(str(d)[:10])
    except ValueError:
        return None


def random_password(length: int = 20) -> str:
    """Random password that satisfies the usual Plesk strength policies (all four character classes)."""
    alphabet = string.ascii_letters + string.digits + "!$%&*+-=?@_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw) and any(c in "!$%&*+-=?@_" for c in pw):
            return pw


class SignupService:
    def __init__(
        self,
        settings: Settings,
        cfg: SignupSettings,
        store: SignupStore,
        redis: Redis,
        plesk: PleskClient,
        audit: AuditLog,
        price_list: PriceList,
        *,
        rebill: RebillClient,
        bexio: BexioClient,
        netim: NetimClient | None,
        zammad: ZammadClient,
        mailer: Mailer,
        plesk_rest: PleskRestClient,
    ):
        self._settings = settings
        self.cfg = cfg
        self.store = store
        self._redis = redis
        self._plesk = plesk
        self._audit = audit
        self.price_list = price_list
        self.rebill = rebill
        self.bexio = bexio
        self.netim = netim
        self.zammad = zammad
        self.mailer = mailer
        self.plesk_rest = plesk_rest
        self._plesk_auth = KeyAuth(cfg.plesk_api_key)
        self._backups: dict[str, asyncio.Task[None]] = {}

    # ------------------------------------------------------------------ helpers
    @asynccontextmanager
    async def lock(self, order_id: str) -> AsyncIterator[None]:
        key = f"signup:lock:{order_id}"
        token = secrets.token_hex(8)
        if not await self._redis.set(key, token, nx=True, ex=LOCK_TTL):
            raise Busy(order_id)
        try:
            yield
        finally:
            if await self._redis.get(key) == token:
                await self._redis.delete(key)

    async def event(self, order_id: str, event: str, **data: Any) -> None:
        """Audit trail: database event plus audit log line. Only ids and codes, never customer data."""
        await self.store.add_event(order_id, event, **data)
        self._audit.write(f"signup_{event}", order_id=order_id, **{k: v for k, v in data.items() if k not in ("message",)})

    async def note(self, order: Order, text: str, *, subject: str | None = None) -> None:
        """Internal Zammad note; failures are logged and never stop a flow."""
        if not order.zammad_ticket_id:
            return
        try:
            await self.zammad.add_note(int(order.zammad_ticket_id), text, subject=subject)
        except ExternalError as exc:
            logger.warning("zammad note for order %s failed: %s", order.id, exc)

    async def needs_attention(self, order: Order, reason: str, detail: str = "") -> None:
        current = await self.store.get(order.id)
        previous = current.status if current and current.status != NEEDS_ATTENTION else order.previous_status
        await self.store.set_status(order.id, NEEDS_ATTENTION, previous_status=previous, attention_reason=reason, last_error=(detail or reason)[:128])
        await self.event(order.id, "needs_attention", reason=reason, previous_status=previous)
        await self.note(order, f"Bestellung {order.id} braucht Aufmerksamkeit: {reason}. {detail}".strip(), subject="Bestellung: manuelle Prüfung nötig")

    async def _fail_step(self, order: Order, step: str, exc: Exception) -> None:
        code = f"{getattr(exc, 'service', 'internal')}:{getattr(exc, 'code', exc.__class__.__name__)}"
        attempts = int(order.attempts or 0) + 1
        await self.store.update(order.id, attempts=attempts, last_error=f"{step}: {code}"[:128])
        await self.event(order.id, "step_failed", step=step, error=code, attempts=attempts)
        logger.warning("order %s step %s failed (%d/%d): %s", order.id, step, attempts, self.cfg.max_attempts, exc)
        retryable = getattr(exc, "retryable", True)
        if attempts >= self.cfg.max_attempts or not retryable:
            refreshed = await self.store.get(order.id)
            await self.needs_attention(refreshed or order, f"{step}_failed", f"Fehler {code}, {attempts} Versuche. Details im Log der api/scheduler.")

    # ------------------------------------------------------------- order intake
    async def check_domain_available(self, domain: str) -> tuple[bool, str]:
        """Live availability of a new domain at Netim (cached briefly)."""
        if self.netim is None:
            return False, "new_domains_disabled"
        cache_key = f"signup:check:{domain}"
        cached = await self._redis.get(cache_key)
        if cached is not None:
            return cached == "1", "cached"
        available, reason = await self.netim.check(domain)
        await self._redis.set(cache_key, "1" if available else "0", ex=60)
        return available, reason

    async def submit(self, data: OrderInput, *, client_ip: str) -> tuple[Order, bool]:
        """Create the order (duplicate and domain checks first), then start billing. Returns (order, created)."""
        existing = await self.store.find_awaiting_duplicate(data.email, data.domain)
        if existing is not None:
            await self.event(existing.id, "duplicate_submission")
            return existing, False
        open_order = await self.store.find_open_by_domain(data.domain)
        if open_order is not None:
            raise OrderRejected("domain_ordered", "domain", "Für diese Domain liegt bereits eine Bestellung vor.")
        if data.domain_mode == "own":
            try:
                kind = await self._plesk.domain_exists(self._plesk_auth, data.domain)
            except (PleskError, PleskSystemError, PleskResultError) as exc:
                logger.error("plesk domain check failed: %s", exc)
                raise OrderRejected("plesk_unavailable", "domain", "Die Prüfung der Domain ist gerade nicht möglich. Bitte in einigen Minuten erneut versuchen.") from exc
            if kind is not None:
                raise OrderRejected("domain_exists", "domain", "Diese Domain ist auf unserem Server bereits eingerichtet. Bitte melden Sie sich bei uns, falls das Ihre Domain ist.")
        else:
            try:
                available, _ = await self.check_domain_available(data.domain)
            except ExternalError as exc:
                raise OrderRejected("netim_unavailable", "domain", "Die Verfügbarkeitsprüfung ist gerade nicht möglich. Bitte in einigen Minuten erneut versuchen.") from exc
            if not available:
                raise OrderRejected("domain_unavailable", "domain", "Diese Domain ist nicht verfügbar.")

        order = await self.store.create_order(
            status=AWAITING_PAYMENT,
            company=data.company,
            first_name=data.first_name,
            last_name=data.last_name,
            street=data.street,
            zip=data.zip,
            city=data.city,
            country=data.country,
            email=data.email,
            phone=data.phone,
            domain_mode=data.domain_mode,
            domain=data.domain,
            tld=data.tld.tld if data.tld else None,
            domain_price=data.tld.price_per_year if data.tld else None,
            hosting_price=self.price_list.hosting_price,
            terms_version=data.terms_version,
            terms_accepted_at=int(time.time()),
            ip_hash=hashlib.sha256(client_ip.encode()).hexdigest(),
            domain_status="none",
            attempts=0,
        )
        await self.event(order.id, "order_created", domain_mode=data.domain_mode, tld=order.tld, terms_version=data.terms_version)
        try:
            async with self.lock(order.id):
                await self.ensure_billing(order)
        except Busy:
            pass
        return (await self.store.get(order.id)) or order, True

    # ------------------------------------------------------------------ billing
    def external_ref(self, order: Order) -> str:
        return f"{self.cfg.external_ref_prefix}{order.id}"

    def _items(self, order: Order) -> list[dict[str, Any]]:
        items = [{"text": self.cfg.hosting_item_text, "amount": 1, "unit_price": round(float(order.hosting_price), 2)}]
        if order.domain_mode == "new" and order.domain_price:
            items.append({"text": self.cfg.domain_item_text.format(domain=order.domain), "amount": 1, "unit_price": round(float(order.domain_price), 2)})
        return items

    async def ensure_billing(self, order: Order) -> Order:
        """bexio contact, reBill subscription (first invoice now), Zammad ticket. Each step only once."""
        order = (await self.store.get(order.id)) or order
        if order.status not in (AWAITING_PAYMENT,):
            return order
        if not order.bexio_contact_id:
            try:
                contacts = await self.bexio.find_contacts_by_email(order.email)
                if len(contacts) > 1:
                    raise ExternalError("bexio", "ambiguous_contact", f"{len(contacts)} contacts", retryable=False)
                if contacts:
                    contact_id = int(contacts[0]["id"])
                    created = False
                else:
                    contact_id = await self.bexio.create_contact(
                        company=order.company,
                        first_name=order.first_name,
                        last_name=order.last_name,
                        email=order.email,
                        street=order.street,
                        zip_code=order.zip,
                        city=order.city,
                        country=order.country,
                        phone=order.phone,
                        user_id=self.cfg.bexio_user_id,
                    )
                    created = True
            except ExternalError as exc:
                await self._fail_step(order, "bexio_contact", exc)
                return (await self.store.get(order.id)) or order
            await self.store.update(order.id, bexio_contact_id=contact_id)
            await self.event(order.id, "bexio_contact", bexio_contact_id=contact_id, created=created)
            order = (await self.store.get(order.id)) or order

        if not order.rebill_recurring_id:
            payload = {
                "external_ref": self.external_ref(order),
                "contact": {"bexio_id": int(order.bexio_contact_id)},
                "interval": "yearly",
                "lead_months": self.cfg.lead_months,
                "currency_id": self.cfg.currency_id,
                "mwst_type": self.cfg.mwst_type,
                "title_in_bexio": self.cfg.product_title,
                "start_date": _iso(_today()),
                "language": self.cfg.language,
                "run_now": True,
                "items": self._items(order),
            }
            try:
                subscription, queued, existed = await self.rebill.create_subscription(payload)
            except ExternalError as exc:
                await self._fail_step(order, "rebill_subscription", exc)
                return (await self.store.get(order.id)) or order
            fields: dict[str, Any] = {"rebill_external_ref": self.external_ref(order), "rebill_recurring_id": subscription.get("recurring_id")}
            newest = RebillClient.newest_invoice(subscription)
            if newest:
                fields["bexio_invoice_id"] = int(newest["bexio_invoice_id"])
                fields["invoice_due_date"] = newest.get("due_date")
            if subscription.get("next_period_start"):
                fields["period_end"] = _iso(_parse(subscription["next_period_start"]) - timedelta(days=1)) if _parse(subscription["next_period_start"]) else None
            await self.store.update(order.id, **fields)
            await self.event(order.id, "rebill_subscription", recurring_id=subscription.get("recurring_id"), first_invoice_queued=queued, existed=existed)
            order = (await self.store.get(order.id)) or order

        if not order.zammad_ticket_id:
            lines = [
                f"Neue Bestellung {self.cfg.product_title} (Bestell-Nr. {order.id})",
                f"Domain: {order.domain} ({'neu registrieren' if order.domain_mode == 'new' else 'eigene Domain'})",
                f"Hosting: CHF {float(order.hosting_price):.2f} pro Jahr" + (f", Domain: CHF {float(order.domain_price):.2f} pro Jahr" if order.domain_price else ""),
                f"reBill: {order.rebill_external_ref or 'noch nicht angelegt'}",
                f"bexio-Rechnung: {order.bexio_invoice_id or 'wird erstellt'}",
                f"AGB-Version {order.terms_version} akzeptiert",
                "Status: Warten auf Zahlungseingang. Freischaltung erfolgt automatisch.",
            ]
            try:
                ticket_id = await self.zammad.create_ticket(title=f"{self.cfg.product_title} Bestellung {order.domain}", customer_email=order.email, body="\n".join(lines))
            except ExternalError as exc:
                logger.warning("zammad ticket for order %s failed: %s", order.id, exc)
                await self.event(order.id, "zammad_ticket_failed", error=exc.code)
            else:
                await self.store.update(order.id, zammad_ticket_id=ticket_id)
                await self.event(order.id, "zammad_ticket", ticket_id=ticket_id)
                order = (await self.store.get(order.id)) or order
        return order

    # ------------------------------------------------------------------ payment
    async def _invoice_status(self, invoice_id: int) -> str:
        """paid | cancelled | open | draft | unknown from the bexio invoice status id."""
        try:
            invoice = await self.bexio.invoice(invoice_id)
        except ExternalError as exc:
            if exc.status == 404:  # reBill knows the id but bexio has not finished creating it yet
                return "unknown"
            raise
        status_id = BexioClient.status_id(invoice)
        if status_id in self.cfg.bexio_paid_status_ids:
            return "paid"
        if status_id in self.cfg.bexio_cancelled_status_ids:
            return "cancelled"
        if status_id == 7:
            return "draft"
        return "open"

    async def _refresh_invoices(self, order: Order) -> tuple[Order, dict[str, Any] | None]:
        """Pull the subscription from reBill, remember the newest invoice and its bexio status."""
        subscription = await self.rebill.get_subscription(order.rebill_external_ref or self.external_ref(order))
        fields: dict[str, Any] = {"subscription_active": bool(subscription.get("is_active", True)), "last_invoice_checked_at": int(time.time())}
        if subscription.get("recurring_id") and not order.rebill_recurring_id:
            fields["rebill_recurring_id"] = subscription["recurring_id"]
        nps = _parse(subscription.get("next_period_start"))
        if nps:
            fields["period_end"] = _iso(nps - timedelta(days=1))
        newest = RebillClient.newest_invoice(subscription)
        if newest:
            invoice_id = int(newest["bexio_invoice_id"])
            fields["last_invoice_id"] = invoice_id
            fields["last_invoice_due"] = newest.get("due_date")
            if not order.bexio_invoice_id:
                fields["bexio_invoice_id"] = invoice_id
                fields["invoice_due_date"] = newest.get("due_date")
            fields["last_invoice_status"] = await self._invoice_status(invoice_id)
        if not fields["subscription_active"] and not order.cancelled_at:
            fields["cancelled_at"] = int(time.time())
        await self.store.update(order.id, **fields)
        return (await self.store.get(order.id)) or order, newest

    async def poll_payment(self, order: Order) -> Order:
        """Scheduler, every SIGNUP_PAYMENT_POLL_SECONDS, for orders awaiting payment."""
        async with self.lock(order.id):
            order = (await self.store.get(order.id)) or order
            if order.status != AWAITING_PAYMENT:
                return order
            if order.paid_at:
                return await self.activate(order)
            if not order.rebill_recurring_id or not order.zammad_ticket_id or not order.bexio_contact_id:
                order = await self.ensure_billing(order)
                if order.status != AWAITING_PAYMENT or not order.rebill_recurring_id:
                    return order
            try:
                order, newest = await self._refresh_invoices(order)
            except ExternalError as exc:
                logger.warning("payment poll for order %s failed: %s", order.id, exc)
                await self.event(order.id, "payment_poll_failed", error=exc.code)
                return order
            if newest is None:
                return order
            if order.last_invoice_status == "paid":
                await self.store.update(order.id, paid_at=int(time.time()))
                await self.event(order.id, "payment_received", bexio_invoice_id=order.last_invoice_id)
                order = (await self.store.get(order.id)) or order
                return await self.activate(order)
            if order.last_invoice_status == "cancelled":
                await self.needs_attention(order, "invoice_cancelled", f"Die bexio-Rechnung {order.last_invoice_id} wurde storniert.")
            return (await self.store.get(order.id)) or order

    # --------------------------------------------------------------- activation
    async def _unique_login(self, order: Order) -> str:
        base = ascii_slug(order.last_name)[:10] or ascii_slug(order.first_name)[:10] or "kunde"
        if not base[0].isalpha():
            base = "k" + base
        for n in range(0, 200):
            candidate = base if n == 0 else f"{base}{n + 1}"
            if await self.store.plesk_login_taken(candidate):
                continue
            if not await self._plesk.customer_exists(self._plesk_auth, candidate):
                return candidate
        raise ExternalError("plesk", "no_free_login", retryable=False)

    def _sysuser(self, order: Order) -> str:
        label = ascii_slug(order.domain.split(".")[0])[:10] or "web"
        if not label[0].isalpha():
            label = "w" + label
        return f"{label}_{secrets.token_hex(2)}"

    async def activate(self, order: Order) -> Order:
        """Called with the order lock held, after payment. Steps are skipped when their id is already stored."""
        await self.store.set_status(order.id, ACTIVATING)
        order = (await self.store.get(order.id)) or order
        try:
            # 1. new domain: owner contact and registration at Netim
            if order.domain_mode == "new" and order.domain_status in ("none", "failed"):
                if self.netim is None:
                    raise ExternalError("netim", "disabled", retryable=False)
                if not order.netim_owner_contact_id:
                    contact = {
                        "firstName": order.first_name,
                        "lastName": order.last_name,
                        "bodyForm": "ORG" if order.company else "IND",
                        "bodyName": order.company or "",
                        "address1": order.street,
                        "address2": "",
                        "zipCode": order.zip,
                        "area": "",
                        "city": order.city,
                        "country": order.country,
                        "phone": order.phone or "",
                        "fax": "",
                        "email": order.email,
                        "language": self.cfg.netim_owner_language,
                        "isOwner": 1,
                        "tmName": "",
                        "tmNumber": "",
                        "tmType": "",
                        "tmDate": "",
                        "companyNumber": "",
                        "vatNumber": "",
                        "birthDate": "",
                        "birthZipCode": "",
                        "birthCity": "",
                        "birthCountry": "",
                        "idNumber": "",
                        "additional": [],
                    }
                    contact_id = await self.netim.create_owner_contact(contact)
                    await self.store.update(order.id, netim_owner_contact_id=contact_id)
                    await self.event(order.id, "netim_owner_contact", contact_id=contact_id)
                    order = (await self.store.get(order.id)) or order
                op = await self.netim.register(
                    order.domain,
                    owner=str(order.netim_owner_contact_id),
                    admin=str(self.cfg.netim_contact_admin),
                    tech=str(self.cfg.netim_contact_tech),
                    billing=str(self.cfg.netim_contact_billing),
                    nameservers=self.cfg.netim_nameservers,
                    duration=1,
                )
                status = NetimClient.status_of(op)
                op_id = NetimClient.operation_id_of(op)
                if status == "failed" or status == "cancelled":
                    await self.store.update(order.id, domain_status="failed", netim_operation_id=op_id)
                    await self.event(order.id, "netim_register_failed", operation_id=op_id, status=status)
                    raise ExternalError("netim", "registration_failed", str(op.get("MESSAGE") or status), retryable=False)
                await self.store.update(order.id, domain_status="registered" if status == "done" else "pending", netim_operation_id=op_id, netim_operation_started=int(time.time()))
                await self.event(order.id, "netim_register", operation_id=op_id, status=status or "unknown")
                order = (await self.store.get(order.id)) or order
                try:
                    await self.netim.set_auto_renew(order.domain, False)
                except ExternalError as exc:  # the renewal decision is made here anyway; Netim may not expose the switch for every TLD
                    await self.event(order.id, "netim_autorenew_off_failed", error=exc.code)
                if order.domain_status == "registered":
                    await self._refresh_domain_expiry(order)
                    order = (await self.store.get(order.id)) or order

            # 2. Plesk customer and subscription
            if not order.plesk_customer_id:
                login = order.plesk_login or await self._unique_login(order)
                customer_id = await self._plesk.customer_add(
                    self._plesk_auth,
                    login=login,
                    password=random_password(),  # never stored, logged or mailed; the customer sets an own one via the welcome link
                    pname=order.display_name,
                    cname=order.company,
                    email=order.email,
                    phone=order.phone,
                    address=order.street,
                    city=order.city,
                    pcode=order.zip,
                    country=order.country,
                    external_id=f"signup:{order.id}",
                )
                await self.store.update(order.id, plesk_login=login, plesk_customer_id=customer_id)
                await self.event(order.id, "plesk_customer", customer_id=customer_id)
                order = (await self.store.get(order.id)) or order
            if not order.plesk_webspace_id:
                sysuser = order.sysuser or self._sysuser(order)
                webspace_id = await self._plesk.webspace_add(
                    self._plesk_auth,
                    name=order.domain,
                    owner_login=str(order.plesk_login),
                    ip_address=self.cfg.plesk_ip_address,
                    plan_name=self.cfg.plan_name,
                    ftp_login=sysuser,
                    ftp_password=random_password(),
                )
                await self.store.update(order.id, sysuser=sysuser, plesk_webspace_id=webspace_id)
                await self.event(order.id, "plesk_webspace", webspace_id=webspace_id)
                order = (await self.store.get(order.id)) or order

            # 3./4. welcome mail with the password link
            if not order.welcome_sent_at:
                token = secrets.token_urlsafe(32)
                expires = int(time.time()) + self.cfg.welcome_link_ttl_days * 86400
                await self.store.update(order.id, welcome_token_hash=hashlib.sha256(token.encode()).hexdigest(), welcome_token_expires=expires)
                order = (await self.store.get(order.id)) or order
                subject, text = render_welcome(order, self.cfg, self._settings, token=token)
                await self.mailer.send(to=order.email, subject=subject, text=text)
                await self.store.update(order.id, welcome_sent_at=int(time.time()))
                await self.event(order.id, "welcome_mail_sent")
                order = (await self.store.get(order.id)) or order

            # 5. active
            await self.store.set_status(order.id, ACTIVE, activated_at=order.activated_at or int(time.time()), attempts=0, last_error=None, suspended_at=None, suspend_reason=None)
            await self.event(order.id, "activated", plesk_webspace_id=order.plesk_webspace_id)
            order = (await self.store.get(order.id)) or order
            await self.note(
                order,
                f"Bestellung {order.id} aktiviert. Plesk-Abonnement {order.domain} (Webspace-ID {order.plesk_webspace_id}, Kunde {order.plesk_login}). Willkommensmail versendet."
                + (f" Domain-Registrierung bei Netim: {order.domain_status} (Operation {order.netim_operation_id})." if order.domain_mode == "new" else ""),
                subject="Bestellung aktiviert",
            )
            return order
        except (ExternalError, PleskError) as exc:
            await self.store.set_status(order.id, AWAITING_PAYMENT)
            refreshed = (await self.store.get(order.id)) or order
            await self._fail_step(refreshed, "activation", exc)
            return (await self.store.get(order.id)) or order

    # ---------------------------------------------------------------- lifecycle
    async def _refresh_domain_expiry(self, order: Order) -> None:
        if self.netim is None:
            return
        try:
            info = await self.netim.info(order.domain)
        except ExternalError as exc:
            await self.event(order.id, "netim_info_failed", error=exc.code)
            return
        expires = NetimClient.expiration_of(info)
        if expires:
            await self.store.update(order.id, domain_expires=expires)

    async def _check_pending_domain(self, order: Order) -> Order:
        if self.netim is None or order.domain_status != "pending" or not order.netim_operation_id:
            return order
        try:
            op = await self.netim.operation(int(order.netim_operation_id))
        except ExternalError as exc:
            await self.event(order.id, "netim_operation_check_failed", error=exc.code)
            return order
        status = NetimClient.status_of(op)
        if status == "done":
            await self.store.update(order.id, domain_status="registered")
            await self.event(order.id, "netim_registered", operation_id=order.netim_operation_id)
            await self._refresh_domain_expiry((await self.store.get(order.id)) or order)
            await self.note(order, f"Domain {order.domain} ist bei Netim registriert (Operation {order.netim_operation_id}).")
        elif status in ("failed", "cancelled"):
            await self.store.update(order.id, domain_status="failed")
            await self.event(order.id, "netim_register_failed", operation_id=order.netim_operation_id, status=status)
            await self.needs_attention((await self.store.get(order.id)) or order, "domain_registration_failed", f"Netim-Operation {order.netim_operation_id}: {status}. {op.get('MESSAGE') or ''}")
        elif order.netim_operation_started and time.time() - int(order.netim_operation_started) > self.cfg.netim_operation_timeout_hours * 3600:
            await self.needs_attention(order, "domain_registration_pending", f"Netim-Operation {order.netim_operation_id} ist seit mehr als {self.cfg.netim_operation_timeout_hours} Stunden offen.")
        return (await self.store.get(order.id)) or order

    async def _maybe_renew_domain(self, order: Order) -> None:
        """Renew the domain at Netim shortly before expiry, but only when the current period is paid."""
        if self.netim is None or order.domain_mode != "new" or order.domain_status != "registered":
            return
        if not order.domain_expires:
            await self._refresh_domain_expiry(order)
            order = (await self.store.get(order.id)) or order
            if not order.domain_expires:
                return
        expires = _parse(order.domain_expires)
        if expires is None or _today() < expires - timedelta(days=self.cfg.domain_renew_days_before):
            return
        if order.domain_renewed_until == order.domain_expires:
            return
        paid = order.last_invoice_status == "paid" and order.subscription_active and order.status == ACTIVE
        if paid:
            try:
                op = await self.netim.renew(order.domain, 1)
            except ExternalError as exc:
                await self.event(order.id, "netim_renew_failed", error=exc.code)
                await self.note(order, f"Verlängerung der Domain {order.domain} bei Netim fehlgeschlagen ({exc.code}).")
                return
            status = NetimClient.status_of(op)
            if status in ("failed", "cancelled"):
                await self.event(order.id, "netim_renew_failed", status=status)
                await self.note(order, f"Verlängerung der Domain {order.domain} bei Netim fehlgeschlagen: {op.get('MESSAGE') or status}.")
                return
            await self.store.update(order.id, domain_renewed_until=order.domain_expires)
            await self.event(order.id, "netim_renewed", status=status or "unknown", operation_id=NetimClient.operation_id_of(op))
            await self.note(order, f"Domain {order.domain} bei Netim um ein Jahr verlängert (Ablauf war {order.domain_expires}).")
            await self._refresh_domain_expiry(order)
        elif order.domain_renew_notice_for != order.domain_expires:
            await self.store.update(order.id, domain_renew_notice_for=order.domain_expires)
            await self.event(order.id, "netim_renew_skipped", reason="unpaid" if order.subscription_active else "cancelled")
            await self.note(
                order,
                f"Domain {order.domain} läuft am {order.domain_expires} ab und wird NICHT verlängert: "
                + ("die Rechnung der laufenden Periode ist nicht bezahlt." if order.subscription_active else "das Abo ist gekündigt."),
                subject="Domain wird nicht verlängert",
            )

    async def suspend(self, order: Order, reason: str) -> Order:
        if order.plesk_login:
            await self._plesk.customer_set_status(self._plesk_auth, str(order.plesk_login), PleskClient.STATUS_SUSPENDED_ADMIN)
        now = int(time.time())
        await self.store.set_status(order.id, SUSPENDED, suspended_at=now, suspend_reason=reason, delete_after=now + self.cfg.delete_after_days * 86400)
        await self.event(order.id, "suspended", reason=reason)
        order = (await self.store.get(order.id)) or order
        text = {
            "unpaid": f"Abo {order.domain} gesperrt: Rechnung {order.last_invoice_id} ist seit mehr als {self.cfg.suspend_after_days} Tagen fällig (Fälligkeit {order.last_invoice_due}).",
            "cancelled": f"Abo {order.domain} gesperrt: Abo in reBill deaktiviert, bezahlte Laufzeit bis {order.period_end} abgelaufen.",
        }.get(reason, f"Abo {order.domain} gesperrt ({reason}).")
        await self.note(order, text + f" Löschung frühestens in {self.cfg.delete_after_days} Tagen.", subject="Abo gesperrt")
        return order

    async def unsuspend(self, order: Order) -> Order:
        if order.plesk_login:
            await self._plesk.customer_set_status(self._plesk_auth, str(order.plesk_login), PleskClient.STATUS_ACTIVE)
        await self.store.set_status(order.id, ACTIVE, suspended_at=None, suspend_reason=None, delete_after=None)
        await self.event(order.id, "unsuspended")
        order = (await self.store.get(order.id)) or order
        await self.note(order, f"Abo {order.domain} wieder freigeschaltet: Rechnung {order.last_invoice_id} bezahlt.", subject="Abo freigeschaltet")
        return order

    async def start_backup(self, order: Order) -> None:
        """SIGNUP_DELETE_BACKUP_MODE=plesk: full backup of the subscription into the Plesk backup repository
        (REST CLI gateway `pleskbackup --domains-name`), run as a background task so the scheduler loop goes on.
        The next lifecycle pass deletes once backup_done_at is set."""
        if order.id in self._backups and not self._backups[order.id].done():
            return
        await self.store.update(order.id, backup_started_at=int(time.time()), backup_result=None)
        await self.event(order.id, "backup_started")

        async def run() -> None:
            try:
                result = await asyncio.wait_for(
                    self.plesk_rest.backup_domain(order.domain, description=f"PleskMCP signup {order.id}: Sicherung vor der Loeschung"),
                    timeout=self.cfg.backup_timeout,
                )
                summary = (str(result.get("stdout") or "").strip().splitlines() or ["ok"])[-1][:128]
                await self.store.update(order.id, backup_done_at=int(time.time()), backup_result=summary)
                await self.event(order.id, "backup_done")
                await self.note(order, f"Backup des Abos {order.domain} im Plesk-Backup-Manager erstellt (pleskbackup, Prefix pleskmcp). Löschung folgt beim nächsten Lauf.")
            except (ExternalError, asyncio.TimeoutError) as exc:
                code = getattr(exc, "code", "timeout")
                await self.store.update(order.id, backup_started_at=None, backup_result=f"failed: {code}"[:128])
                await self.event(order.id, "backup_failed", error=code)
                refreshed = (await self.store.get(order.id)) or order
                await self.needs_attention(refreshed, "backup_failed", f"pleskbackup fuer {order.domain} fehlgeschlagen ({code}). Nach der Behebung 'Erneut versuchen'.")
            except Exception as exc:  # noqa: BLE001
                logger.exception("backup task for order %s crashed: %s", order.id, exc)

        task = asyncio.create_task(run())
        self._backups[order.id] = task
        task.add_done_callback(lambda t: self._backups.pop(order.id, None))

    async def wait_for_backups(self) -> None:
        """Tests and shutdown: wait for running backup tasks."""
        if self._backups:
            await asyncio.gather(*list(self._backups.values()), return_exceptions=True)

    async def delete(self, order: Order, *, confirmed_by: str = "scheduler") -> Order:
        """Remove subscription and customer in Plesk. Mode plesk: after the backup; manual: after confirmation (admin page); none: directly."""
        if order.plesk_login:
            try:
                await self._plesk.webspace_del(self._plesk_auth, order.domain)
            except PleskResultError as exc:
                await self.event(order.id, "plesk_webspace_del_failed", error=exc.code)
            await self._plesk.customer_del(self._plesk_auth, str(order.plesk_login))
        await self.store.set_status(order.id, DELETED, deleted_at=int(time.time()))
        await self.event(order.id, "deleted", confirmed_by=confirmed_by)
        order = (await self.store.get(order.id)) or order
        await self.note(order, f"Abo {order.domain} und Plesk-Kunde {order.plesk_login} gelöscht ({confirmed_by}).", subject="Abo gelöscht")
        return order

    async def lifecycle(self, order: Order) -> Order:
        """Scheduler, every SIGNUP_LIFECYCLE_SECONDS, for active and suspended orders."""
        async with self.lock(order.id):
            order = (await self.store.get(order.id)) or order
            if order.status not in (ACTIVE, SUSPENDED, PENDING_DELETION):
                return order
            try:
                order, _ = await self._refresh_invoices(order)
            except ExternalError as exc:
                await self.event(order.id, "lifecycle_refresh_failed", error=exc.code)
                return order
            order = await self._check_pending_domain(order)
            today = _today()
            due = _parse(order.last_invoice_due)
            period_end = _parse(order.period_end)
            try:
                if order.status == ACTIVE:
                    if order.last_invoice_status == "open" and due and today > due + timedelta(days=self.cfg.suspend_after_days):
                        order = await self.suspend(order, "unpaid")
                    elif not order.subscription_active and period_end and today > period_end:
                        order = await self.suspend(order, "cancelled")
                elif order.status == SUSPENDED:
                    if order.suspend_reason == "unpaid" and order.last_invoice_status == "paid":
                        order = await self.unsuspend(order)
                    elif order.delete_after and time.time() >= int(order.delete_after):
                        if self.cfg.delete_backup_mode == "none":
                            order = await self.delete(order)
                        else:
                            await self.store.set_status(order.id, PENDING_DELETION)
                            await self.event(order.id, "pending_deletion")
                            order = (await self.store.get(order.id)) or order
                            if self.cfg.delete_backup_mode == "plesk":
                                await self.note(order, f"Abo {order.domain} ist seit {self.cfg.delete_after_days} Tagen gesperrt. Backup wird erstellt, danach wird gelöscht.", subject="Löschung eingeleitet")
                                await self.start_backup(order)
                            else:
                                await self.note(order, f"Abo {order.domain} ist seit {self.cfg.delete_after_days} Tagen gesperrt. Bitte Backup erstellen und die Löschung in der Admin-Übersicht bestätigen.", subject="Löschung freigeben")
                elif order.status == PENDING_DELETION and self.cfg.delete_backup_mode == "plesk":
                    if order.backup_done_at:
                        order = await self.delete(order, confirmed_by="scheduler after backup")
                    elif not order.backup_started_at:
                        await self.start_backup(order)
            except (PleskError, ExternalError) as exc:
                await self._fail_step(order, "lifecycle", exc)
                return (await self.store.get(order.id)) or order
            if order.status in (ACTIVE, SUSPENDED):
                await self._maybe_renew_domain(order)
            return (await self.store.get(order.id)) or order

    # -------------------------------------------------------------------- admin
    async def admin_retry(self, order: Order) -> Order:
        """needs_attention -> previous status, attempts reset; the scheduler picks it up again."""
        async with self.lock(order.id):
            order = (await self.store.get(order.id)) or order
            if order.status != NEEDS_ATTENTION:
                return order
            target = order.previous_status or AWAITING_PAYMENT
            if target in (ACTIVATING,):
                target = AWAITING_PAYMENT
            await self.store.set_status(order.id, target, attempts=0, last_error=None, attention_reason=None, backup_started_at=None)
            await self.event(order.id, "admin_retry", status=target)
            return (await self.store.get(order.id)) or order

    async def admin_confirm_delete(self, order: Order, who: str) -> Order:
        async with self.lock(order.id):
            order = (await self.store.get(order.id)) or order
            if order.status != PENDING_DELETION:
                return order
            return await self.delete(order, confirmed_by=who)

    async def admin_check_now(self, order: Order) -> Order:
        if order.status == AWAITING_PAYMENT:
            return await self.poll_payment(order)
        if order.status in (ACTIVE, SUSPENDED, PENDING_DELETION):
            return await self.lifecycle(order)
        return order

    # ------------------------------------------------------------ scheduler API
    async def run_payment_polls(self) -> int:
        count = 0
        for order in await self.store.list(status=AWAITING_PAYMENT):
            try:
                await self.poll_payment(order)
                count += 1
            except Busy:
                continue
            except Exception as exc:  # noqa: BLE001 - one order must not stop the loop
                logger.exception("payment poll for order %s crashed: %s", order.id, exc)
        return count

    async def run_lifecycle(self) -> int:
        count = 0
        for order in await self.store.list(status=(ACTIVE, SUSPENDED, PENDING_DELETION)):
            try:
                await self.lifecycle(order)
                count += 1
            except Busy:
                continue
            except Exception as exc:  # noqa: BLE001
                logger.exception("lifecycle for order %s crashed: %s", order.id, exc)
        return count

    # ------------------------------------------------------------ welcome link
    async def plesk_login_url(self, order: Order, *, client_ip: str) -> str:
        """One-time Plesk login (XML API create_session + rsession_init.php) or the panel's password reset page."""
        if self.cfg.plesk_login_link_mode == "session" and order.plesk_login:
            token = await self._plesk.create_session(self._plesk_auth, login=str(order.plesk_login), user_ip=client_ip, source_server=self._settings.public_host)
            url = f"{self.cfg.plesk_panel_url}/enterprise/rsession_init.php?PLESKSESSID={token}"
            if self.cfg.plesk_password_page_path:
                from urllib.parse import quote

                url += "&success_redirect_url=" + quote(self.cfg.plesk_password_page_path, safe="/")
            return url
        return f"{self.cfg.plesk_panel_url}/get_password.php"
