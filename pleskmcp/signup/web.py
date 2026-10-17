"""HTTP endpoints of the signup service (mounted under the service base path).

    GET  /signup/config            price list, countries, terms version (CORS for the website)
    GET  /signup/token             stateless form token (HMAC over time + nonce), CORS
    GET  /signup/check-domain      availability of a new domain at Netim (rate limited)
    POST /signup                   the order (form POST from the website or JSON); CSRF token, honeypot,
                                   minimum fill time, per-IP and per-e-mail limits, HTTPS only
    GET  /signup/thanks/{id}       built-in page after the order (check your mail) and after the confirmation (invoice comes)
    GET  /signup/confirm/{token}   link from the confirmation mail: creates subscription, invoice and ticket
    GET  /signup/welcome/{token}   one-time login link from the welcome mail
    GET  /signup/admin             overview of all orders (HTTP Basic, SIGNUP_ADMIN_USER/PASSWORD)
    POST /signup/admin/action      retry / check now / confirm deletion
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
import secrets
import time
from typing import Any

from redis.asyncio import Redis
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response

from ..auth.login import STYLE, client_ip, simple_page
from ..auth.ratelimit import RedisLimiter
from ..config import Settings
from ..plesk_api import PleskError
from .clients import ExternalError
from .forms import COUNTRIES, domain_format_ok, honeypot_filled, normalize_domain, parse_order
from .service import Busy, OrderRejected, SignupService
from .store import ACTIVE, AWAITING_CONFIRMATION, AWAITING_PAYMENT, NEEDS_ATTENTION, PENDING_DELETION, STATUSES, SUSPENDED

logger = logging.getLogger(__name__)

STATUS_LABELS = {
    AWAITING_CONFIRMATION: "wartet auf E-Mail-Bestätigung",
    AWAITING_PAYMENT: "wartet auf Zahlung",
    "activating": "wird freigeschaltet",
    ACTIVE: "aktiv",
    SUSPENDED: "gesperrt",
    PENDING_DELETION: "Löschung freigeben",
    "deleted": "gelöscht",
    NEEDS_ATTENTION: "manuelle Prüfung",
    "expired": "nicht bestätigt, verfallen",
}

_THANKS = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{title}</title><style>{style}</style></head>
<body><div class="card">
  <h1>{title}</h1>
  {body}
</div></body></html>"""

_THANKS_CONFIRM = """<p>Ihre Bestellung für <strong>{domain}</strong> ist eingegangen (Bestell-Nr. {order_id}).</p>
  <p>Wir haben eine E-Mail an <strong>{email}</strong> geschickt. Bitte klicken Sie auf den Link darin, um Ihre Adresse zu bestätigen. Erst danach stellen wir die Rechnung aus.</p>
  <p class="muted">Keine E-Mail erhalten? Bitte den Spam-Ordner prüfen. Der Link ist {ttl_hours} Stunden gültig.</p>"""

_THANKS_CONFIRMED = """<p>Ihre E-Mail-Adresse ist bestätigt. Die Rechnung für <strong>{domain}</strong> (Bestell-Nr. {order_id}) kommt in den nächsten Minuten per E-Mail an <strong>{email}</strong>. Sie können sie mit QR-Rechnung oder Kreditkarte bezahlen.</p>
  <p>Sobald die Zahlung eingegangen ist, wird Ihr Hosting automatisch freigeschaltet. Sie erhalten dann eine E-Mail mit dem Link zum Setzen Ihres Passworts und der Anleitung für den KI-Zugang.</p>
  <p class="muted">Keine Rechnung erhalten? Bitte auch den Spam-Ordner prüfen oder auf die Rechnungsmail antworten.</p>"""

_CONFIRM_FAILED = {
    "invalid": ("Link ungültig", "Dieser Bestätigungslink ist unbekannt. Bitte den Link aus der E-Mail vollständig kopieren oder die Bestellung neu aufgeben."),
    "expired": ("Link abgelaufen", "Dieser Bestätigungslink ist abgelaufen. Bitte geben Sie die Bestellung neu auf; es sind keine Kosten entstanden."),
    "domain_taken": ("Domain nicht mehr verfügbar", "Die gewünschte Domain wurde in der Zwischenzeit anderweitig vergeben oder eingerichtet. Bitte geben Sie die Bestellung mit einer anderen Domain neu auf; es sind keine Kosten entstanden."),
}

_WELCOME_EXPIRED = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>Link abgelaufen</title><style>{style}</style></head>
<body><div class="card">
  <h1>Dieser Link ist nicht mehr gültig</h1>
  <p>Der Anmeldelink aus der Willkommensmail funktioniert nur einmal und für begrenzte Zeit.</p>
  <p>Sie können sich jederzeit ein neues Passwort setzen lassen: <a href="{reset_url}">Passwort vergessen</a> auf der Anmeldeseite von Plesk. Ihr Benutzername steht in der Willkommensmail.</p>
</div></body></html>"""

_ADMIN = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{service} - Bestellungen</title><style>{style}
  .card.wide {{ max-width: 1180px; }} td.actions form {{ display: inline; margin-right: 4px; }} .tag {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 12px; background: #e5e7eb; color: #1b1f24; }}
  .tag.active {{ background: #dcfce7; color: #166534; }} .tag.attention, .tag.pending_deletion {{ background: #fee2e2; color: #991b1b; }} .tag.suspended {{ background: #fef3c7; color: #92400e; }}
  details {{ margin-top: 6px; }} pre {{ font-size: 12px; white-space: pre-wrap; }} .counts span {{ margin-right: 14px; }}
</style></head>
<body><div class="card wide">
  <h1>{service}: Bestellungen AI Hosting</h1>
  {notice_block}
  <p class="counts muted">{counts}</p>
  <table><thead><tr><th>Bestellung</th><th>Status</th><th>Domain</th><th>Kunde</th><th>Rechnung</th><th>Plesk</th><th>Netim</th><th>Aktionen</th></tr></thead>
  <tbody>{rows}</tbody></table>
</div></body></html>"""


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64url(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class SignupPages:
    def __init__(self, settings: Settings, service: SignupService, limiter: RedisLimiter, redis: Redis):
        self._settings = settings
        self.service = service
        self.cfg = service.cfg
        self._limiter = limiter
        self._redis = redis

    @property
    def base(self) -> str:
        return self._settings.base_path

    # ------------------------------------------------------------------- CORS
    def _origin_ok(self, request: Request) -> str | None:
        origin = request.headers.get("origin")
        if not origin:
            return None
        if origin.rstrip("/") in self.cfg.allowed_origins or origin.rstrip("/") == f"https://{self._settings.public_host}":
            return origin
        return ""

    def _cors(self, request: Request, response: Response) -> Response:
        origin = self._origin_ok(request)
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Vary"] = "Origin"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
            response.headers["Access-Control-Allow-Headers"] = "Content-Type"
            response.headers["Access-Control-Max-Age"] = "600"
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    async def options(self, request: Request) -> Response:
        return self._cors(request, Response(status_code=204))

    def _https_only(self, request: Request) -> Response | None:
        proto = request.headers.get("x-forwarded-proto", request.url.scheme)
        if proto != "https" and request.url.hostname not in ("127.0.0.1", "localhost"):
            return self._cors(request, JSONResponse({"ok": False, "error": "https_required"}, status_code=400))
        return None

    # ------------------------------------------------------------------ tokens
    def _sign(self, payload: bytes) -> str:
        return _b64url(hmac.new(self.cfg.token_secret, payload, hashlib.sha256).digest()[:20])

    def make_token(self) -> str:
        payload = f"{int(time.time())}.{secrets.token_hex(8)}".encode()
        return _b64url(payload) + "." + self._sign(payload)

    async def verify_token(self, token: str) -> str | None:
        """None when valid, else an error code (invalid, too_fast, expired, replayed)."""
        try:
            body, sig = token.split(".", 1)
            payload = _unb64url(body)
            ts_text, nonce = payload.decode().split(".", 1)
            ts = int(ts_text)
        except (ValueError, UnicodeDecodeError):
            return "invalid"
        if not hmac.compare_digest(sig, self._sign(payload)):
            return "invalid"
        age = time.time() - ts
        if age < self.cfg.min_fill_seconds:
            return "too_fast"
        if age > self.cfg.token_max_age:
            return "expired"
        if not await self._redis.set(f"signup:nonce:{nonce}", "1", nx=True, ex=self.cfg.token_max_age + 60):
            return "replayed"
        return None

    async def _limited(self, key: str, limit: int, window: int) -> bool:
        allowed, _, _ = await self._limiter._take(f"rl:signup:{key}", limit, window)  # noqa: SLF001 - same Lua bucket as the login limits
        return not allowed

    # --------------------------------------------------------------- endpoints
    async def get_config(self, request: Request) -> Response:
        data = {
            "price_list": self.service.price_list.public(),
            "countries": [{"code": c, "name": n} for c, n in COUNTRIES],
            "terms_version": self.cfg.terms_version,
            "terms_url": self.cfg.terms_url,
            "new_domains_enabled": self.cfg.new_domains_enabled,
            "min_fill_seconds": self.cfg.min_fill_seconds,
            "endpoint": f"{self._settings.public_base_url}/signup",
        }
        response = JSONResponse(data)
        response.headers["Cache-Control"] = "public, max-age=300"
        return self._cors(request, response)

    async def get_token(self, request: Request) -> Response:
        return self._cors(request, JSONResponse({"token": self.make_token(), "min_fill_seconds": self.cfg.min_fill_seconds}))

    async def check_domain(self, request: Request) -> Response:
        ip = client_ip(request)
        if await self._limited(f"check:{ip}", 30, 300):
            return self._cors(request, JSONResponse({"ok": False, "error": "rate_limited"}, status_code=429))
        domain = normalize_domain(request.query_params.get("domain", ""))
        if not domain_format_ok(domain):
            return self._cors(request, JSONResponse({"ok": False, "error": "invalid_domain", "message": "Bitte einen gültigen Domainnamen angeben."}, status_code=400))
        tld = self.service.price_list.tld_for(domain)
        if tld is None or not tld.orderable:
            return self._cors(request, JSONResponse({"ok": True, "domain": domain, "orderable": False, "available": None, "message": "Diese Endung ist online nicht bestellbar, wir registrieren sie gern auf Anfrage."}))
        if len(domain.split(".")) != len(tld.tld.split(".")) + 1:
            return self._cors(request, JSONResponse({"ok": False, "error": "invalid_domain", "message": "Bitte nur die Hauptdomain angeben, ohne Subdomain."}, status_code=400))
        try:
            available, _ = await self.service.check_domain_available(domain)
        except ExternalError as exc:
            logger.warning("domain check failed: %s", exc)
            return self._cors(request, JSONResponse({"ok": False, "error": "check_unavailable", "message": "Die Prüfung ist gerade nicht möglich."}, status_code=503))
        return self._cors(
            request,
            JSONResponse({"ok": True, "domain": domain, "orderable": True, "available": available, "price_per_year": tld.price_per_year, "currency": self.service.price_list.currency, "owner_fields": list(tld.owner_fields)}),
        )

    async def post_order(self, request: Request) -> Response:
        blocked = self._https_only(request)
        if blocked:
            return blocked
        if self._origin_ok(request) == "":
            return JSONResponse({"ok": False, "error": "origin"}, status_code=403)
        ip = client_ip(request)
        wants_json = "application/json" in request.headers.get("accept", "") or "application/json" in request.headers.get("content-type", "")
        if "application/json" in request.headers.get("content-type", ""):
            try:
                form: dict[str, Any] = await request.json()
            except ValueError:
                return self._cors(request, JSONResponse({"ok": False, "error": "invalid_json"}, status_code=400))
            if not isinstance(form, dict):
                return self._cors(request, JSONResponse({"ok": False, "error": "invalid_json"}, status_code=400))
        else:
            form = dict(await request.form())

        def reply(status: int, payload: dict[str, Any], *, redirect: str | None = None) -> Response:
            if wants_json:
                return self._cors(request, JSONResponse(payload, status_code=status))
            if redirect:
                return RedirectResponse(redirect, status_code=303)
            if payload.get("ok"):
                return RedirectResponse(payload["redirect"], status_code=303)
            errors = payload.get("errors") or {}
            text = payload.get("message") or " ".join(errors.values()) or "Die Bestellung konnte nicht angenommen werden."
            return simple_page("Bestellung nicht möglich", text, status=status)

        # honeypot: pretend success, create nothing
        if honeypot_filled(form):
            self.service._audit.write("signup_honeypot", ip_hash=hashlib.sha256(ip.encode()).hexdigest()[:16])  # noqa: SLF001
            logger.info("signup honeypot hit")
            fake = secrets.token_hex(8)
            return reply(200, {"ok": True, "order_id": fake, "redirect": self._thanks_url(fake, None)})
        if await self._limited(f"ip:{ip}", self.cfg.rate_limit_ip, self.cfg.rate_limit_ip_window):
            return reply(429, {"ok": False, "error": "rate_limited", "message": "Zu viele Bestellungen von dieser Adresse. Bitte später erneut versuchen."})
        token_error = await self.verify_token(str(form.get("token") or ""))
        if token_error:
            messages = {
                "too_fast": "Das Formular wurde zu schnell abgeschickt. Bitte noch einmal prüfen und erneut senden.",
                "expired": "Das Formular war zu lange offen. Bitte die Seite neu laden.",
                "replayed": "Diese Bestellung wurde bereits gesendet.",
                "invalid": "Das Formular konnte nicht geprüft werden. Bitte die Seite neu laden.",
            }
            return reply(400, {"ok": False, "error": f"token_{token_error}", "message": messages.get(token_error, "")})
        data = parse_order(form, self.service.price_list, terms_version=self.cfg.terms_version, new_domains_enabled=self.cfg.new_domains_enabled)
        if not data.ok:
            return reply(422, {"ok": False, "error": "validation", "errors": data.errors})
        if await self._limited(f"email:{hashlib.sha256(data.email.encode()).hexdigest()[:32]}", self.cfg.rate_limit_email, self.cfg.rate_limit_email_window):
            return reply(429, {"ok": False, "error": "rate_limited", "message": "Für diese E-Mail-Adresse liegen bereits mehrere Bestellungen vor. Bitte später erneut versuchen."})
        try:
            order, created = await self.service.submit(data, client_ip=ip)
        except OrderRejected as exc:
            return reply(422 if exc.code != "mail_failed" else 503, {"ok": False, "error": exc.code, "errors": {exc.field: exc.message}, "message": exc.message})
        step = "confirm" if order.status == AWAITING_CONFIRMATION else "confirmed"
        return reply(200, {"ok": True, "order_id": order.id, "created": created, "domain": order.domain, "step": step, "redirect": self._thanks_url(order.id, order.domain, step=step)})

    def _thanks_url(self, order_id: str, domain: str | None, *, step: str = "confirm") -> str:
        """step=confirm: 'check your mail'; step=confirmed: 'invoice is on its way'."""
        if self.cfg.success_url:
            sep = "&" if "?" in self.cfg.success_url else "?"
            return f"{self.cfg.success_url}{sep}order={order_id}&step={step}"
        return f"{self._settings.public_base_url}/signup/thanks/{order_id}?step={step}"

    async def thanks(self, request: Request) -> Response:
        order_id = request.path_params.get("order_id", "")
        order = await self.service.store.get(order_id) if len(order_id) == 16 else None
        confirmed = request.query_params.get("step") == "confirmed" and order is not None and order.status != AWAITING_CONFIRMATION
        values = {
            "domain": html.escape(order.domain) if order else "Ihre Domain",
            "order_id": html.escape(order.id) if order else html.escape(order_id[:16]),
            "email": html.escape(order.email) if order else "Ihre E-Mail-Adresse",
            "ttl_hours": self.cfg.confirm_ttl_hours,
        }
        if confirmed:
            page = _THANKS.format(style=STYLE, title="Vielen Dank, Ihre Bestellung ist bestätigt", body=_THANKS_CONFIRMED.format(**values))
        else:
            page = _THANKS.format(style=STYLE, title="Bitte E-Mail-Adresse bestätigen", body=_THANKS_CONFIRM.format(**values))
        return HTMLResponse(page, headers={"Cache-Control": "no-store"})

    async def confirm(self, request: Request) -> Response:
        token = request.path_params.get("token", "")
        ip = client_ip(request)
        if await self._limited(f"confirm:{ip}", 20, 600):
            return simple_page("Zu viele Versuche", "Bitte später erneut versuchen.", status=429)
        if not token or len(token) > 100:
            title, text = _CONFIRM_FAILED["invalid"]
            return simple_page(title, text, status=404)
        outcome, order = await self.service.confirm(token)
        if outcome in ("confirmed", "already") and order is not None:
            return RedirectResponse(self._thanks_url(order.id, order.domain, step="confirmed"), status_code=303, headers={"Cache-Control": "no-store"})
        title, text = _CONFIRM_FAILED.get(outcome, _CONFIRM_FAILED["invalid"])
        return simple_page(title, text, status=410 if outcome != "invalid" else 404)

    async def welcome(self, request: Request) -> Response:
        token = request.path_params.get("token", "")
        reset = f"{self.cfg.plesk_panel_url}/get_password.php"
        if not token or len(token) > 100:
            return HTMLResponse(_WELCOME_EXPIRED.format(style=STYLE, reset_url=html.escape(reset)), status_code=404, headers={"Cache-Control": "no-store"})
        ip = client_ip(request)
        if await self._limited(f"welcome:{ip}", 10, 600):
            return simple_page("Zu viele Versuche", "Bitte später erneut versuchen.", status=429)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        order = await self.service.store.find_by_welcome_token(token_hash)
        if order is None or order.status != ACTIVE or not order.welcome_token_expires or time.time() > int(order.welcome_token_expires):
            return HTMLResponse(_WELCOME_EXPIRED.format(style=STYLE, reset_url=html.escape(reset)), status_code=410, headers={"Cache-Control": "no-store"})
        try:
            url = await self.service.plesk_login_url(order, client_ip=ip)
        except PleskError as exc:
            logger.error("welcome login for order %s failed: %s", order.id, exc)
            await self.service.event(order.id, "welcome_login_failed", error=exc.__class__.__name__)
            return simple_page("Anmeldung gerade nicht möglich", "Bitte in einigen Minuten erneut versuchen oder auf der Plesk-Anmeldeseite 'Passwort vergessen' wählen.", status=503)
        if not await self.service.store.consume_welcome_token(order.id, token_hash):
            return HTMLResponse(_WELCOME_EXPIRED.format(style=STYLE, reset_url=html.escape(reset)), status_code=410, headers={"Cache-Control": "no-store"})
        await self.service.event(order.id, "welcome_link_used")
        return RedirectResponse(url, status_code=303, headers={"Cache-Control": "no-store"})

    # ------------------------------------------------------------------- admin
    def _admin_ok(self, request: Request) -> bool:
        if not self.cfg.admin_user or not self.cfg.admin_password:
            return False
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("basic "):
            return False
        try:
            user, _, password = base64.b64decode(header[6:]).decode("utf-8").partition(":")
        except (ValueError, UnicodeDecodeError):
            return False
        return hmac.compare_digest(user, self.cfg.admin_user) and hmac.compare_digest(password, self.cfg.admin_password)

    def _admin_challenge(self) -> Response:
        return PlainTextResponse("Anmeldung erforderlich", status_code=401, headers={"WWW-Authenticate": 'Basic realm="PleskMCP Signup"', "Cache-Control": "no-store"})

    async def _admin_csrf(self) -> str:
        token = secrets.token_urlsafe(24)
        await self._redis.set(f"signup:admincsrf:{token}", "1", ex=3600)
        return token

    async def admin(self, request: Request, notice: str | None = None) -> Response:
        if not self._admin_ok(request):
            return self._admin_challenge()
        ip = client_ip(request)
        if await self._limited(f"admin:{ip}", 120, 60):
            return simple_page("Zu viele Anfragen", "Bitte kurz warten.", status=429)
        wanted = request.query_params.get("status")
        orders = await self.service.store.list(status=wanted if wanted in STATUSES else None)
        counts = await self.service.store.counts()
        csrf = await self._admin_csrf()
        rows = []
        for o in orders:
            actions = []
            if o.status == NEEDS_ATTENTION:
                actions.append(("retry", "Erneut versuchen", ""))
            if o.status == PENDING_DELETION:
                actions.append(("confirm_delete", "Backup erledigt, löschen", "danger"))
            if o.status in (AWAITING_PAYMENT, ACTIVE, SUSPENDED, PENDING_DELETION):
                actions.append(("check", "Jetzt prüfen", "secondary"))
            buttons = "".join(
                f'<form method="post" action="{self.base}/signup/admin/action"><input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="order_id" value="{o.id}">'
                f'<input type="hidden" name="action" value="{a}"><button type="submit" class="small {cls}">{label}</button></form>'
                for a, label, cls in actions
            )
            events = await self.service.store.events(o.id, limit=12)
            event_text = "\n".join(f"{time.strftime('%Y-%m-%d %H:%M', time.gmtime(e['ts']))} {e['event']} " + " ".join(f"{k}={v}" for k, v in e.items() if k not in ('ts', 'event')) for e in events)
            customer = html.escape(f"{o.display_name}" + (f" ({o.company})" if o.company else "")) + f"<br><span class=\"muted\">{html.escape(o.email)}</span>"
            invoice = f"{o.last_invoice_id or o.bexio_invoice_id or '-'}<br><span class=\"muted\">{html.escape(str(o.last_invoice_status or ''))} {html.escape(str(o.last_invoice_due or ''))}</span>"
            plesk = f"{html.escape(str(o.plesk_login or '-'))}<br><span class=\"muted\">ws {o.plesk_webspace_id or '-'}</span>"
            netim = "-" if o.domain_mode != "new" else f"{html.escape(str(o.domain_status))}<br><span class=\"muted\">op {o.netim_operation_id or '-'} bis {html.escape(str(o.domain_expires or '?'))}</span>"
            status = f'<span class="tag {o.status}">{html.escape(STATUS_LABELS.get(o.status, o.status))}</span>'
            if o.attention_reason:
                status += f"<br><span class=\"muted\">{html.escape(str(o.attention_reason))}</span>"
            if o.last_error:
                status += f"<br><span class=\"muted\">{html.escape(str(o.last_error))}</span>"
            rows.append(
                f"<tr><td>{o.id}<br><span class=\"muted\">{time.strftime('%Y-%m-%d %H:%M', time.gmtime(o.created_at))}</span></td><td>{status}</td>"
                f"<td>{html.escape(o.domain)}<br><span class=\"muted\">{'neu' if o.domain_mode == 'new' else 'eigene'}</span></td><td>{customer}</td><td>{invoice}</td><td>{plesk}</td><td>{netim}</td>"
                f"<td class=\"actions\">{buttons}<details><summary class=\"muted\">Verlauf</summary><pre>{html.escape(event_text)}</pre></details></td></tr>"
            )
        count_text = " ".join(f"<span>{html.escape(STATUS_LABELS.get(s, s))}: {n}</span>" for s, n in sorted(counts.items()))
        page = _ADMIN.format(
            service=html.escape(self._settings.service_name),
            style=STYLE,
            notice_block=f'<p class="notice">{html.escape(notice)}</p>' if notice else "",
            counts=count_text or "keine Bestellungen",
            rows="".join(rows) or '<tr><td colspan="8" class="muted">keine Bestellungen</td></tr>',
        )
        return HTMLResponse(page, headers={"Cache-Control": "no-store"})

    async def admin_action(self, request: Request) -> Response:
        if not self._admin_ok(request):
            return self._admin_challenge()
        form = await request.form()
        csrf = str(form.get("csrf") or "")
        if not csrf or not await self._redis.delete(f"signup:admincsrf:{csrf}"):
            return simple_page("Ungültige Anfrage", "Das Formular ist abgelaufen. Bitte die Seite neu laden.", status=400)
        order = await self.service.store.get(str(form.get("order_id") or ""))
        if order is None:
            return simple_page("Nicht gefunden", "Diese Bestellung gibt es nicht.", status=404)
        action = str(form.get("action") or "")
        try:
            if action == "retry":
                await self.service.admin_retry(order)
                notice = f"Bestellung {order.id}: wird erneut verarbeitet."
            elif action == "confirm_delete":
                await self.service.admin_confirm_delete(order, who=f"admin {self.cfg.admin_user}")
                notice = f"Bestellung {order.id}: gelöscht."
            elif action == "check":
                await self.service.admin_check_now(order)
                notice = f"Bestellung {order.id}: geprüft."
            else:
                return simple_page("Ungültige Anfrage", "Unbekannte Aktion.", status=400)
        except Busy:
            notice = f"Bestellung {order.id} wird gerade vom Scheduler bearbeitet."
        except (ExternalError, PleskError) as exc:
            logger.error("admin action %s on %s failed: %s", action, order.id, exc)
            notice = f"Bestellung {order.id}: Aktion fehlgeschlagen ({exc.__class__.__name__})."
        await self.service.event(order.id, "admin_action", action=action)
        return await self.admin(request, notice=notice)


def admin_json(orders: list[Any]) -> str:
    """Compact JSON for the CLI (`pleskmcp signup-orders`)."""
    return "\n".join(json.dumps({k: v for k, v in o.data.items() if k not in ("welcome_token_hash", "ip_hash")}, ensure_ascii=False) for o in orders)
