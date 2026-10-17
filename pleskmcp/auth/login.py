"""The service's own login page: Plesk username + password, then consent.

GET  /login?req=<id>   render the form for a pending authorization request
POST /login            verify credentials against Plesk, issue the code, redirect

The checkbox "Andere Verbindungen trennen" (on by default) revokes every older
token family of the login once the new connection has its tokens.
"""

from __future__ import annotations

import html
import logging
import secrets
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..accounts import AccountService, LoginRejected
from ..audit import AuditLog
from ..config import Settings
from .provider import PleskAuthProvider
from .ratelimit import RateLimited, RedisLimiter

logger = logging.getLogger(__name__)

CSRF_COOKIE = "pleskmcp_login"

SCOPE_TEXT = {
    "files:read": "Dateien der eigenen Webseiten lesen",
    "files:write": "Dateien der eigenen Webseiten ändern, verschieben und in den Papierkorb legen",
    "dns:read": "DNS-Einträge der eigenen Domains lesen",
    "dns:write": "DNS-Einträge der eigenen Domains anlegen, ändern und löschen (ausser SOA und NS)",
    "db:read": "Datenbanken der eigenen Webseiten abfragen (Zugangsdaten bleiben verborgen)",
    "db:write": "Daten in eigenen Datenbanken ändern (mit Sicherung)",
    "db:admin": "Eigene Datenbanken anlegen, Schema ändern und wieder löschen (mit Sicherung)",
}

STYLE = """
  :root { color-scheme: light dark; }
  body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 0; padding: 24px 16px;
         background: #f4f5f7; color: #1b1f24; }
  .card { max-width: 520px; margin: 0 auto 18px; background: #ffffff; color: #1b1f24; border-radius: 10px;
          padding: 28px 28px 22px; box-shadow: 0 2px 12px rgba(0,0,0,.08); }
  h1 { font-size: 20px; margin: 0 0 6px; }
  h2 { font-size: 16px; margin: 18px 0 6px; }
  p { line-height: 1.45; margin: 10px 0; }
  a { color: #2563eb; }
  .muted { color: #5b6471; font-size: 14px; }
  ul { padding-left: 20px; margin: 6px 0 14px; }
  li { margin: 2px 0; }
  label { display: block; font-size: 14px; margin: 14px 0 4px; }
  label.check { display: flex; gap: 8px; align-items: center; margin-top: 16px; }
  label.check input { width: auto; }
  input, select { width: 100%; box-sizing: border-box; padding: 10px 12px; font-size: 16px; border: 1px solid #c8ccd2;
           border-radius: 6px; background: #ffffff; color: #1b1f24; }
  input:focus, select:focus { outline: 2px solid #2563eb; outline-offset: 1px; border-color: #2563eb; }
  .row { display: flex; gap: 10px; margin-top: 20px; }
  button { flex: 1; padding: 11px 14px; font-size: 16px; border-radius: 6px; border: 1px solid #2563eb;
           background: #2563eb; color: #fff; cursor: pointer; }
  button.secondary { background: transparent; color: inherit; border-color: #9aa1a9; }
  button.small { flex: none; padding: 6px 10px; font-size: 14px; }
  button.danger { background: #b91c1c; border-color: #b91c1c; color: #fff; }
  .error { background: #fde8e8; color: #9b1c1c; border-radius: 6px; padding: 10px 12px; font-size: 14px; }
  .notice { background: #e8f5e9; color: #1b5e20; border-radius: 6px; padding: 10px 12px; font-size: 14px; }
  .client { font-weight: 600; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  td, th { text-align: left; padding: 8px 6px; border-bottom: 1px solid #e5e7eb; vertical-align: middle; }
  form.inline { display: inline; }
  @media (prefers-color-scheme: dark) {
    body { background: #15181c; color: #e6e8eb; }
    .card { background: #1f242a; color: #e6e8eb; box-shadow: 0 2px 12px rgba(0,0,0,.4); }
    a { color: #7aa7ff; }
    .muted { color: #a3abb5; }
    input, select { background: #15181c; color: #e6e8eb; border-color: #3a4149; }
    button.secondary { border-color: #6b7280; }
    .error { background: #3b1414; color: #fca5a5; }
    .notice { background: #12301a; color: #a7e3b3; }
    td, th { border-bottom-color: #3a4149; }
  }
"""

_PAGE = """<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>{service} - Anmeldung</title>
<style>{style}</style>
</head>
<body>
<div class="card">
  <h1>{service}</h1>
  <p><span class="client">{client_name}</span> möchte sich mit deinem Hosting verbinden.</p>
  <p class="muted">Die Verbindung erhält folgende Rechte (gelten nur für Abos mit gebuchtem KI-Zugang):</p>
  <ul>{scope_items}</ul>
  {error_block}
  <form method="post" action="{action}" autocomplete="off">
    <input type="hidden" name="req" value="{req}">
    <input type="hidden" name="csrf" value="{csrf}">
    <label for="login">Plesk-Benutzername</label>
    <input id="login" name="login" type="text" required autocapitalize="none" autocorrect="off" spellcheck="false" value="{login_value}">
    <label for="password">Plesk-Passwort</label>
    <input id="password" name="password" type="password" required autocomplete="current-password">
    <label class="check"><input type="checkbox" name="revoke_others" value="1" {revoke_checked}> Andere Verbindungen trennen</label>
    <p class="muted">Trennt alle bisher verbundenen KI-Anwendungen dieses Kontos, z.B. nach einem Passwortwechsel. Einzelne Verbindungen verwaltest du unter <a href="{account_url}">{account_url}</a>.</p>
    <div class="row">
      <button type="submit" name="action" value="allow">Verbinden</button>
      <button type="submit" name="action" value="deny" class="secondary" formnovalidate>Abbrechen</button>
    </div>
  </form>
  <p class="muted">Anmeldung mit den Zugangsdaten deines Plesk-Hostings. Das Passwort wird nur zur Prüfung an Plesk
  weitergegeben und nicht gespeichert. Zugriff gibt es ausschliesslich auf die eigenen Abonnements.</p>
</div>
</body>
</html>
"""

_SIMPLE = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>body{{font-family:system-ui,sans-serif;padding:40px 16px;max-width:520px;margin:auto;line-height:1.5}}</style></head>
<body><h1>{title}</h1><p>{text}</p></body></html>"""


def simple_page(title: str, text: str, status: int = 400) -> Response:
    return HTMLResponse(_SIMPLE.format(title=html.escape(title), text=html.escape(text)), status_code=status, headers={"Cache-Control": "no-store"})


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


class LoginPages:
    def __init__(
        self,
        settings: Settings,
        provider: PleskAuthProvider,
        accounts: AccountService,
        limiter: RedisLimiter,
        audit: AuditLog,
    ):
        self._settings = settings
        self._provider = provider
        self._accounts = accounts
        self._limiter = limiter
        self._audit = audit

    @property
    def action_path(self) -> str:
        return f"{self._settings.base_path}/login"

    def _render(
        self,
        *,
        request_id: str,
        client_name: str,
        scopes: list[str],
        csrf: str,
        error: str | None = None,
        login_value: str = "",
        revoke_others: bool = True,
    ) -> str:
        items = "".join(f"<li>{html.escape(SCOPE_TEXT.get(s, s))}</li>" for s in scopes) or "<li>Keine</li>"
        error_block = f'<div class="error">{html.escape(error)}</div>' if error else ""
        return _PAGE.format(
            style=STYLE,
            service=html.escape(self._settings.service_name),
            client_name=html.escape(client_name),
            scope_items=items,
            error_block=error_block,
            action=html.escape(self.action_path),
            req=html.escape(request_id),
            csrf=html.escape(csrf),
            login_value=html.escape(login_value),
            revoke_checked="checked" if revoke_others else "",
            account_url=html.escape(f"{self._settings.public_base_url}/account"),
        )

    async def _client_name(self, client_id: str) -> str:
        client = await self._provider.get_client(client_id)
        if client is None:
            return "Eine unbekannte Anwendung"
        name = (client.client_name or "").strip()
        if name:
            return name
        if client_id.startswith("https://"):
            return client_id
        return f"Anwendung {client_id[:8]}"

    async def get(self, request: Request) -> Response:
        request_id = request.query_params.get("req", "")
        pending = await self._provider.load_pending_request(request_id) if request_id else None
        if pending is None:
            return simple_page("Anfrage abgelaufen", "Diese Anmeldeanfrage ist ungültig oder abgelaufen. Bitte starte die Verbindung in deiner App erneut.")
        client_id, params = pending
        csrf = secrets.token_urlsafe(24)
        page = self._render(
            request_id=request_id,
            client_name=await self._client_name(client_id),
            scopes=params["scopes"],
            csrf=csrf,
        )
        response = HTMLResponse(page, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})
        response.set_cookie(
            CSRF_COOKIE,
            csrf,
            max_age=self._settings.auth_request_ttl,
            httponly=True,
            secure=self._settings.public_base_url.startswith("https://"),
            samesite="lax",
            path=self.action_path,
        )
        return response

    async def post(self, request: Request) -> Response:
        form = await request.form()
        request_id = str(form.get("req") or "")
        csrf = str(form.get("csrf") or "")
        action = str(form.get("action") or "allow")
        login = str(form.get("login") or "").strip()
        password = str(form.get("password") or "")
        revoke_others = str(form.get("revoke_others") or "") == "1"
        ip = client_ip(request)

        pending = await self._provider.load_pending_request(request_id) if request_id else None
        if pending is None:
            return simple_page("Anfrage abgelaufen", "Diese Anmeldeanfrage ist ungültig oder abgelaufen. Bitte starte die Verbindung in deiner App erneut.")
        client_id, params = pending

        cookie = request.cookies.get(CSRF_COOKIE, "")
        if not csrf or not cookie or not secrets.compare_digest(csrf, cookie):
            return simple_page("Ungültige Anfrage", "Das Formular konnte nicht geprüft werden. Bitte lade die Seite neu.", 400)

        if action == "deny":
            self._audit.write("login_denied", ip=ip, client=client_id)
            return RedirectResponse(await self._provider.deny_login(request_id, params), status_code=302, headers={"Cache-Control": "no-store"})

        client_name = await self._client_name(client_id)

        def failure(message: str, status: int = 200) -> Response:
            page = self._render(
                request_id=request_id,
                client_name=client_name,
                scopes=params["scopes"],
                csrf=csrf,
                error=message,
                login_value=login,
                revoke_others=revoke_others,
            )
            return HTMLResponse(page, status_code=status, headers={"Cache-Control": "no-store"})

        try:
            await self._limiter.check_login(ip=ip, login=login)
        except RateLimited as exc:
            self._audit.write("login_rate_limited", ip=ip, login=login, scope=exc.scope, client=client_id)
            return failure("Zu viele Anmeldeversuche. Bitte warte einige Minuten und versuche es erneut.", 429)

        try:
            await self._accounts.login(login, password, client_ip=ip, client_id=client_id)
        except LoginRejected as exc:
            reached_plesk = exc.reason in ("credentials", "suspended", "not_customer")
            await self._limiter.record_login_failure(ip=ip, login=login, plesk_checked=reached_plesk)
            self._audit.write("login_failed", ip=ip, login=login, reason=exc.reason, client=client_id)
            return failure(exc.message, 401 if reached_plesk else 503)

        await self._limiter.record_login_success(ip=ip, login=login)
        redirect = await self._provider.complete_login(request_id, client_id, params, login, revoke_others=revoke_others)
        response = RedirectResponse(redirect, status_code=302, headers={"Cache-Control": "no-store"})
        response.delete_cookie(CSRF_COOKIE, path=self.action_path)
        return response


def login_params_summary(params: dict[str, Any]) -> dict[str, Any]:  # pragma: no cover - debugging aid
    return {k: v for k, v in params.items() if k != "code_challenge"}
