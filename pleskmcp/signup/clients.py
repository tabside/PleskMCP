"""HTTP clients of the signup service: reBill, bexio, Netim, Zammad, SMTP.

Every client takes an optional httpx transport so tests run against fakes. Errors
are raised as ExternalError with a short code; messages never include customer
data beyond what the caller passes in explicitly.
"""

from __future__ import annotations

import asyncio
import json
import logging
import smtplib
import time
from datetime import date
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class ExternalError(Exception):
    """A call to an external service failed. `service` and `code` are safe to log and to put into notes."""

    def __init__(self, service: str, code: str, message: str = "", *, retryable: bool = True, status: int | None = None):
        super().__init__(f"{service}: {code}" + (f" ({message})" if message else ""))
        self.service = service
        self.code = code
        self.detail = message
        self.retryable = retryable
        self.status = status


def _body(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return {"raw": response.text[:500]}


def _message(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("message", "error", "error_description", "MESSAGE"):
            if data.get(key):
                return str(data[key])[:300]
        if data.get("errors"):
            return json.dumps(data["errors"], ensure_ascii=False)[:300]
    return json.dumps(data, ensure_ascii=False)[:300] if data is not None else ""


class _Http:
    service = "http"

    def __init__(self, base_url: str, *, timeout: float = 30.0, transport: httpx.AsyncBaseTransport | None = None, headers: dict[str, str] | None = None):
        self._base = base_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=timeout, transport=transport, headers=headers or {}, follow_redirects=False)

    async def aclose(self) -> None:
        await self._client.aclose()

    async def _request(self, method: str, path: str, *, json_body: Any = None, params: dict[str, Any] | None = None, headers: dict[str, str] | None = None, ok: tuple[int, ...] = (200, 201)) -> Any:
        url = self._base + "/" + path.lstrip("/")
        try:
            response = await self._client.request(method, url, json=json_body, params=params, headers=headers)
        except httpx.HTTPError as exc:
            raise ExternalError(self.service, "unreachable", exc.__class__.__name__) from exc
        data = _body(response) if response.content else None
        if response.status_code not in ok:
            retryable = response.status_code >= 500 or response.status_code in (408, 429)
            raise ExternalError(self.service, f"http_{response.status_code}", _message(data), retryable=retryable, status=response.status_code)
        return data


# ----------------------------------------------------------------------- reBill
class RebillClient(_Http):
    """reBill API v1 (docs/API.md of the rebill repository)."""

    service = "rebill"

    def __init__(self, base_url: str, token: str, *, transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(base_url, transport=transport, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})

    async def create_subscription(self, payload: dict[str, Any]) -> tuple[dict[str, Any], bool, bool]:
        """POST /subscriptions. Returns (subscription, first_invoice_queued, existed). 409 = external_ref exists (idempotent)."""
        url = self._base + "/subscriptions"
        try:
            response = await self._client.post(url, json=payload)
        except httpx.HTTPError as exc:
            raise ExternalError(self.service, "unreachable", exc.__class__.__name__) from exc
        data = _body(response)
        if response.status_code == 201:
            return data.get("subscription") or {}, bool(data.get("first_invoice_queued")), False
        if response.status_code == 409:
            sub = data.get("subscription") if isinstance(data, dict) else None
            if not sub:
                sub = await self.get_subscription(payload["external_ref"])
            return sub, False, True
        retryable = response.status_code >= 500 or response.status_code == 429
        raise ExternalError(self.service, f"http_{response.status_code}", _message(data), retryable=retryable, status=response.status_code)

    async def get_subscription(self, external_ref: str) -> dict[str, Any]:
        data = await self._request("GET", f"/subscriptions/{external_ref}")
        return (data or {}).get("subscription") or {}

    @staticmethod
    def newest_invoice(subscription: dict[str, Any]) -> dict[str, Any] | None:
        invoices = [i for i in subscription.get("invoices") or [] if i.get("bexio_invoice_id")]
        if not invoices:
            return None
        return sorted(invoices, key=lambda i: (str(i.get("created_at") or ""), int(i["bexio_invoice_id"])))[-1]


# ------------------------------------------------------------------------ bexio
class BexioClient(_Http):
    """bexio REST API 2.0 with a static API token (read contacts, read invoice status, create a contact)."""

    service = "bexio"

    def __init__(self, base_url: str, token: str, *, transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(base_url, transport=transport, headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        self._countries: dict[str, int] | None = None

    async def find_contacts_by_email(self, email: str) -> list[dict[str, Any]]:
        found: dict[int, dict[str, Any]] = {}
        for field in ("mail", "mail_second"):
            rows = await self._request("POST", "/2.0/contact/search", json_body=[{"field": field, "value": email, "criteria": "="}])
            for row in rows or []:
                if isinstance(row, dict) and row.get("id"):
                    found[int(row["id"])] = row
        return list(found.values())

    async def country_id(self, iso2: str) -> int | None:
        if self._countries is None:
            rows = await self._request("GET", "/2.0/country", params={"limit": 2000})
            table: dict[str, int] = {}
            for row in rows or []:
                code = row.get("iso_3166_alpha2") or row.get("iso3166_alpha2") or row.get("name_short")
                if code and row.get("id"):
                    table[str(code).upper()] = int(row["id"])
            self._countries = table
        return self._countries.get(iso2.upper())

    async def create_contact(self, *, company: str | None, first_name: str, last_name: str, email: str, street: str, zip_code: str, city: str, country: str, phone: str | None, user_id: int | None) -> int:
        body: dict[str, Any] = {
            "contact_type_id": 1 if company else 2,
            "name_1": company or last_name,
            "mail": email,
            "address": street,
            "postcode": zip_code,
            "city": city,
        }
        if company:
            # bexio stores the contact person of a company contact separately; the order keeps the full name
            body["name_2"] = f"{first_name} {last_name}".strip()
        else:
            body["name_2"] = first_name
        if phone:
            body["phone_fixed"] = phone
        cid = await self.country_id(country)
        if cid is not None:
            body["country_id"] = cid
        if user_id:
            body["user_id"] = user_id
            body["owner_id"] = user_id
        data = await self._request("POST", "/2.0/contact", json_body=body)
        if not isinstance(data, dict) or not data.get("id"):
            raise ExternalError(self.service, "contact_create_failed", _message(data), retryable=False)
        return int(data["id"])

    async def invoice(self, invoice_id: int) -> dict[str, Any]:
        data = await self._request("GET", f"/2.0/kb_invoice/{int(invoice_id)}")
        if not isinstance(data, dict):
            raise ExternalError(self.service, "invoice_invalid", retryable=False)
        return data

    @staticmethod
    def status_id(invoice: dict[str, Any]) -> int | None:
        for key in ("kb_item_status_id", "kb_invoice_status_id"):
            if invoice.get(key) is not None:
                try:
                    return int(invoice[key])
                except (TypeError, ValueError):
                    return None
        return None


# ------------------------------------------------------------------------ Netim
class NetimClient:
    """Netim REST API 1.0: one session per operation batch (POST /session/ with basic auth, Bearer token afterwards)."""

    service = "netim"

    def __init__(self, base_url: str, login: str, secret: str, *, transport: httpx.AsyncBaseTransport | None = None):
        self._base = base_url.rstrip("/")
        self._login = login
        self._secret = secret
        self._transport = transport

    async def _session(self) -> tuple[httpx.AsyncClient, dict[str, str]]:
        client = httpx.AsyncClient(timeout=60, transport=self._transport)
        try:
            response = await client.post(f"{self._base}/session/", auth=(self._login, self._secret), headers={"Accept-Language": "EN", "Content-Type": "application/json"})
        except httpx.HTTPError as exc:
            await client.aclose()
            raise ExternalError(self.service, "unreachable", exc.__class__.__name__) from exc
        data = _body(response)
        if response.status_code != 200 or not isinstance(data, dict) or not data.get("access_token"):
            await client.aclose()
            raise ExternalError(self.service, "auth_failed", _message(data), retryable=response.status_code >= 500)
        return client, {"Authorization": f"Bearer {data['access_token']}", "Content-Type": "application/json", "Accept-Language": "EN"}

    async def call(self, method: str, path: str, body: Any = None) -> Any:
        client, headers = await self._session()
        try:
            try:
                response = await client.request(method, f"{self._base}/{path.lstrip('/')}", headers=headers, content=json.dumps(body).encode("utf-8") if body is not None else None)
            except httpx.HTTPError as exc:
                raise ExternalError(self.service, "unreachable", exc.__class__.__name__) from exc
            data = _body(response) if response.content else None
            if not 200 <= response.status_code < 300:
                raise ExternalError(self.service, f"http_{response.status_code}", _message(data), retryable=response.status_code >= 500, status=response.status_code)
            return data
        finally:
            try:
                await client.delete(f"{self._base}/session/", headers=headers)
            except Exception:  # noqa: BLE001 - closing the session is best effort
                pass
            await client.aclose()

    async def check(self, domain: str) -> tuple[bool, str]:
        """(available, reason) from GET /domain/{domain}/check/."""
        data = await self.call("GET", f"domain/{domain}/check/")
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            if isinstance(entry, dict) and str(entry.get("domain", "")).lower() in ("", domain.lower()):
                result = str(entry.get("result", "")).upper()
                reason = str(entry.get("reason") or "")
                if result == "AVAILABLE" and reason.upper() in ("PREMIUM", "RESERVED", "PENDING APPLICATION"):
                    return False, reason
                return result == "AVAILABLE", reason
        raise ExternalError(self.service, "check_invalid", retryable=False)

    async def create_owner_contact(self, contact: dict[str, Any]) -> str:
        data = await self.call("POST", "contact/", {"contact": contact})
        if isinstance(data, str) and data:
            return data
        if isinstance(data, dict):
            for key in ("id", "ID", "idContact", "contact_id"):
                if data.get(key):
                    return str(data[key])
        raise ExternalError(self.service, "contact_invalid", _message(data), retryable=False)

    async def register(self, domain: str, *, owner: str, admin: str, tech: str, billing: str, nameservers: list[str], duration: int = 1) -> dict[str, Any]:
        body: dict[str, Any] = {"idOwner": owner, "idAdmin": admin, "idTech": tech, "idBilling": billing, "duration": duration}
        for i, ns in enumerate(nameservers[:5], start=1):
            body[f"ns{i}"] = ns
        data = await self.call("POST", f"domain/{domain}/", body)
        return data if isinstance(data, dict) else {"STATUS": "Unknown", "raw": data}

    async def operation(self, operation_id: int) -> dict[str, Any]:
        data = await self.call("GET", f"operation/{int(operation_id)}")
        return data if isinstance(data, dict) else {"STATUS": "Unknown"}

    async def info(self, domain: str) -> dict[str, Any]:
        data = await self.call("GET", f"domain/{domain}/info/")
        return data if isinstance(data, dict) else {}

    async def renew(self, domain: str, duration: int = 1) -> dict[str, Any]:
        data = await self.call("PATCH", f"domain/{domain}/renew/", {"duration": str(duration)})
        return data if isinstance(data, dict) else {"STATUS": "Unknown"}

    async def set_auto_renew(self, domain: str, enabled: bool) -> dict[str, Any]:
        data = await self.call("PATCH", f"domain/{domain}/preference/", {"codePref": "auto_renew", "value": "1" if enabled else "0"})
        return data if isinstance(data, dict) else {"STATUS": "Unknown"}

    @staticmethod
    def status_of(op: dict[str, Any]) -> str:
        for key in ("STATUS", "status", "Status"):
            if op.get(key):
                return str(op[key]).lower()
        return ""

    @staticmethod
    def operation_id_of(op: dict[str, Any]) -> int | None:
        for key in ("ID_OPE", "id_ope", "idOpe"):
            if op.get(key) not in (None, ""):
                try:
                    return int(op[key])
                except (TypeError, ValueError):
                    return None
        return None

    @staticmethod
    def expiration_of(info: dict[str, Any]) -> str | None:
        for key in ("dateExpiration", "DateExpiration", "date_expiration", "expiration", "dateExpire"):
            value = info.get(key)
            if value:
                text = str(value)[:10]
                try:
                    date.fromisoformat(text)
                    return text
                except ValueError:
                    continue
        return None


# ----------------------------------------------------------------------- Zammad
class ZammadClient(_Http):
    service = "zammad"

    def __init__(self, base_url: str, token: str, group: str, *, transport: httpx.AsyncBaseTransport | None = None):
        super().__init__(base_url, transport=transport, headers={"Authorization": f"Token token={token}", "Accept": "application/json"})
        self._group = group

    async def create_ticket(self, *, title: str, customer_email: str, body: str) -> int:
        payload = {
            "title": title,
            "group": self._group,
            "customer_id": f"guess:{customer_email}",
            "article": {"subject": title, "body": body, "type": "note", "internal": True, "content_type": "text/plain"},
        }
        data = await self._request("POST", "/api/v1/tickets", json_body=payload)
        if not isinstance(data, dict) or not data.get("id"):
            raise ExternalError(self.service, "ticket_invalid", _message(data), retryable=False)
        return int(data["id"])

    async def add_note(self, ticket_id: int, body: str, *, subject: str | None = None) -> None:
        payload = {"ticket_id": int(ticket_id), "body": body, "type": "note", "internal": True, "content_type": "text/plain"}
        if subject:
            payload["subject"] = subject
        await self._request("POST", "/api/v1/ticket_articles", json_body=payload)


# ------------------------------------------------------------------------- mail
class Mailer:
    """SMTP mail with the credentials from the environment; runs smtplib in a worker thread."""

    service = "smtp"

    def __init__(self, *, host: str, port: int, user: str | None, password: str | None, starttls: bool, ssl: bool, sender: str, reply_to: str | None, bcc: str | None):
        self._host = host
        self._port = port
        self._user = user
        self._password = password
        self._starttls = starttls
        self._ssl = ssl
        self._from = sender
        self._reply_to = reply_to
        self._bcc = bcc

    def build(self, *, to: str, subject: str, text: str) -> EmailMessage:
        message = EmailMessage()
        message["From"] = self._from
        message["To"] = to
        message["Subject"] = subject
        message["Date"] = formatdate(localtime=True)
        message["Message-ID"] = make_msgid()
        if self._reply_to:
            message["Reply-To"] = self._reply_to
        message.set_content(text, charset="utf-8")
        return message

    def _send_sync(self, message: EmailMessage, recipients: list[str]) -> None:
        if self._ssl:
            server: smtplib.SMTP = smtplib.SMTP_SSL(self._host, self._port, timeout=30)
        else:
            server = smtplib.SMTP(self._host, self._port, timeout=30)
        try:
            server.ehlo()
            if self._starttls and not self._ssl:
                server.starttls()
                server.ehlo()
            if self._user and self._password:
                server.login(self._user, self._password)
            server.send_message(message, from_addr=self._from, to_addrs=recipients)
        finally:
            try:
                server.quit()
            except Exception:  # noqa: BLE001
                pass

    async def send(self, *, to: str, subject: str, text: str) -> None:
        message = self.build(to=to, subject=subject, text=text)
        recipients = [to] + ([self._bcc] if self._bcc else [])
        try:
            await asyncio.to_thread(self._send_sync, message, recipients)
        except (smtplib.SMTPException, OSError) as exc:
            raise ExternalError(self.service, "send_failed", exc.__class__.__name__) from exc


def today_iso() -> str:
    return time.strftime("%Y-%m-%d")
