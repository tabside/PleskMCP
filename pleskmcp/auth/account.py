"""Customer self-service page at <PUBLIC_BASE_URL>/account.

Login with the Plesk credentials (same rate limits as the OAuth login), then:
  - connected AI clients (name, last used) with "Trennen" per client and "Alle trennen"
    ("Alle trennen" also deletes the per-customer secret key in Plesk),
  - stored database credentials: add/replace/delete, never displayed.

Sessions live in Redis (short TTL), the cookie is Secure/HttpOnly/SameSite=Strict,
every POST carries a CSRF token bound to the session.
"""

from __future__ import annotations

import html
import json
import logging
import re
import secrets
import time
from typing import Any

from redis.asyncio import Redis
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from ..accounts import AccountInactive, AccountService, LoginRejected
from ..audit import AuditLog
from ..config import Settings
from ..db import Store
from .login import STYLE, client_ip, simple_page
from .ratelimit import RateLimited, RedisLimiter

logger = logging.getLogger(__name__)

SESSION_COOKIE = "pleskmcp_account"
DB_NAME_RE = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.-]{0,63}$")
IDENT_RE = re.compile(r"^[A-Za-z0-9_$.-]{1,64}$")

_LOGIN = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{service} - Konto</title><style>{style}</style></head>
<body><div class="card">
  <h1>{service}: Konto</h1>
  <p class="muted">Hier siehst du, welche KI-Anwendungen mit deinem Hosting verbunden sind, trennst Verbindungen und hinterlegst Datenbank-Zugangsdaten.</p>
  {error_block}
  <form method="post" action="{base}/account/login" autocomplete="off">
    <input type="hidden" name="csrf" value="{csrf}">
    <label for="login">Plesk-Benutzername</label>
    <input id="login" name="login" type="text" required autocapitalize="none" autocorrect="off" spellcheck="false" value="{login_value}">
    <label for="password">Plesk-Passwort</label>
    <input id="password" name="password" type="password" required autocomplete="current-password">
    <div class="row"><button type="submit">Anmelden</button></div>
  </form>
  <p class="muted">Das Passwort wird nur zur Prüfung an Plesk weitergegeben und nicht gespeichert.</p>
</div></body></html>"""

_DASHBOARD = """<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex"><title>{service} - Konto</title><style>{style}</style></head>
<body>
<div class="card">
  <h1>{service}: Konto {login}</h1>
  {notice_block}
  <h2>Verbundene Anwendungen</h2>
  {connections}
  <form method="post" action="{base}/account/disconnect" class="row">
    <input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="client_id" value="*">
    <button type="submit" class="danger">Alle trennen</button>
  </form>
  <p class="muted">"Alle trennen" widerruft jede Verbindung und löscht den für dieses Konto in Plesk hinterlegten API-Schlüssel. Danach muss jede Anwendung neu verbunden werden.</p>
</div>
<div class="card">
  <h2>Datenbank-Zugangsdaten</h2>
  <p class="muted">Für Datenbanken, deren Zugangsdaten nicht aus der Konfiguration der Website gelesen werden können. Die Werte werden verschlüsselt gespeichert, nur dem Auftrag auf dem Server übergeben und nie angezeigt.</p>
  {credentials}
  <form method="post" action="{base}/account/db" autocomplete="off">
    <input type="hidden" name="csrf" value="{csrf}"><input type="hidden" name="action" value="save">
    <label for="database">Datenbank</label>
    {database_field}
    <label for="db_user">Datenbank-Benutzer</label>
    <input id="db_user" name="db_user" type="text" required autocapitalize="none" spellcheck="false">
    <label for="db_password">Passwort</label>
    <input id="db_password" name="db_password" type="password" required autocomplete="new-password">
    <div class="row"><button type="submit">Speichern / ersetzen</button></div>
  </form>
</div>
<div class="card">
  <form method="post" action="{base}/account/logout" class="row">
    <input type="hidden" name="csrf" value="{csrf}">
    <button type="submit" class="secondary">Abmelden</button>
  </form>
</div>
</body></html>"""


def _when(ts: int | None) -> str:
    if not ts:
        return "noch nie"
    return time.strftime("%Y-%m-%d %H:%M", time.gmtime(int(ts))) + " UTC"


class AccountPages:
    def __init__(self, settings: Settings, store: Store, accounts: AccountService, limiter: RedisLimiter, audit: AuditLog, redis: Redis):
        self._settings = settings
        self._store = store
        self._accounts = accounts
        self._limiter = limiter
        self._audit = audit
        self._redis = redis

    @property
    def base(self) -> str:
        return self._settings.base_path

    # ---------------------------------------------------------------- sessions
    async def _session(self, request: Request) -> dict[str, Any] | None:
        sid = request.cookies.get(SESSION_COOKIE)
        if not sid or not re.match(r"^[A-Za-z0-9_-]{20,64}$", sid):
            return None
        raw = await self._redis.get(f"acct:sess:{sid}")
        if not raw:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None
        data["sid"] = sid
        return data

    async def _new_session(self, login: str | None) -> tuple[str, str]:
        sid = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        await self._redis.set(f"acct:sess:{sid}", json.dumps({"login": login, "csrf": csrf, "created": int(time.time())}), ex=self._settings.account_session_ttl)
        return sid, csrf

    async def _drop_session(self, sid: str) -> None:
        await self._redis.delete(f"acct:sess:{sid}")

    def _set_cookie(self, response: Response, sid: str) -> Response:
        response.set_cookie(
            SESSION_COOKIE,
            sid,
            max_age=self._settings.account_session_ttl,
            httponly=True,
            secure=self._settings.public_base_url.startswith("https://"),
            samesite="strict",
            path=f"{self.base}/account",
        )
        return response

    async def _form(self, request: Request) -> tuple[dict[str, Any] | None, dict[str, str]]:
        """Session plus form data, after the CSRF check. Session is None when the check fails."""
        session = await self._session(request)
        form = await request.form()
        data = {k: str(v) for k, v in form.items()}
        if session is None or not secrets.compare_digest(data.get("csrf", ""), session.get("csrf", "")):
            return None, data
        return session, data

    def _redirect(self) -> Response:
        return RedirectResponse(f"{self.base}/account", status_code=303, headers={"Cache-Control": "no-store"})

    # ------------------------------------------------------------------- pages
    async def get(self, request: Request) -> Response:
        session = await self._session(request)
        if session is None or not session.get("login"):
            sid, csrf = await self._new_session(None)
            return self._set_cookie(self._login_page(csrf), sid)
        return await self._dashboard(session, notice=request.query_params.get("m"))

    def _login_page(self, csrf: str, error: str | None = None, login_value: str = "", status: int = 200) -> Response:
        page = _LOGIN.format(
            service=html.escape(self._settings.service_name),
            style=STYLE,
            base=html.escape(self.base),
            csrf=html.escape(csrf),
            error_block=f'<div class="error">{html.escape(error)}</div>' if error else "",
            login_value=html.escape(login_value),
        )
        return HTMLResponse(page, status_code=status, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    async def _known_databases(self, login: str) -> list[str]:
        try:
            account = await self._accounts.get_active_account(login)
        except AccountInactive:
            return []
        names: list[str] = []
        seen: set[str] = set()
        for d in account.domains:
            if d.status != 0 or d.webspace in seen:
                continue
            seen.add(d.webspace)
            for db in await self._accounts.databases_for(login, d):
                if db.get("name") and db["name"] not in names:
                    names.append(db["name"])
        return names

    async def _dashboard(self, session: dict[str, Any], notice: str | None = None, error: str | None = None) -> Response:
        login = session["login"]
        csrf = session["csrf"]
        rows = await self._store.connections_for_login(login)
        if rows:
            parts = ["<table><tr><th>Anwendung</th><th>Zuletzt benutzt</th><th></th></tr>"]
            for r in rows:
                name = r.get("client_name") or r["client_id"]
                parts.append(
                    "<tr><td>{name}</td><td>{last}</td><td><form method=\"post\" action=\"{base}/account/disconnect\" class=\"inline\">"
                    "<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"client_id\" value=\"{cid}\">"
                    "<button type=\"submit\" class=\"small secondary\">Trennen</button></form></td></tr>".format(
                        name=html.escape(str(name)[:80]), last=_when(r.get("last_used") or r.get("since")), base=html.escape(self.base), csrf=html.escape(csrf), cid=html.escape(r["client_id"])
                    )
                )
            parts.append("</table>")
            connections = "".join(parts)
        else:
            connections = '<p class="muted">Keine aktive Verbindung.</p>'

        creds = await self._store.list_db_credentials(login)
        if creds:
            parts = ["<table><tr><th>Datenbank</th><th>Benutzer</th><th>Herkunft</th><th></th></tr>"]
            for c in creds:
                parts.append(
                    "<tr><td>{db}</td><td>{user}</td><td>{src}</td><td><form method=\"post\" action=\"{base}/account/db\" class=\"inline\">"
                    "<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><input type=\"hidden\" name=\"action\" value=\"delete\">"
                    "<input type=\"hidden\" name=\"database\" value=\"{db}\"><button type=\"submit\" class=\"small secondary\">Löschen</button></form></td></tr>".format(
                        db=html.escape(c["database"]), user=html.escape(c["db_user"]), src="vom Dienst angelegt" if c.get("source") == "service" else "hinterlegt", base=html.escape(self.base), csrf=html.escape(csrf)
                    )
                )
            parts.append("</table>")
            credentials = "".join(parts)
        else:
            credentials = '<p class="muted">Keine hinterlegten Zugangsdaten.</p>'

        known = await self._known_databases(login)
        if known:
            options = "".join(f'<option value="{html.escape(n)}">{html.escape(n)}</option>' for n in known)
            database_field = f'<select id="database" name="database" required>{options}</select>'
        else:
            database_field = '<input id="database" name="database" type="text" required spellcheck="false" placeholder="Name der Datenbank in Plesk">'

        blocks = []
        if notice:
            blocks.append(f'<div class="notice">{html.escape(notice)}</div>')
        if error:
            blocks.append(f'<div class="error">{html.escape(error)}</div>')
        page = _DASHBOARD.format(
            service=html.escape(self._settings.service_name),
            style=STYLE,
            login=html.escape(login),
            base=html.escape(self.base),
            csrf=html.escape(csrf),
            notice_block="".join(blocks),
            connections=connections,
            credentials=credentials,
            database_field=database_field,
        )
        return HTMLResponse(page, headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"})

    # ------------------------------------------------------------------- posts
    async def post_login(self, request: Request) -> Response:
        session, data = await self._form(request)
        if session is None:
            return simple_page("Ungültige Anfrage", "Das Formular konnte nicht geprüft werden. Bitte lade die Seite neu.", 400)
        login = data.get("login", "").strip()
        password = data.get("password", "")
        ip = client_ip(request)
        try:
            await self._limiter.check_login(ip=ip, login=login)
        except RateLimited as exc:
            self._audit.write("login_rate_limited", ip=ip, login=login, scope=exc.scope, client="account_page")
            return self._login_page(session["csrf"], "Zu viele Anmeldeversuche. Bitte warte einige Minuten.", login, 429)
        try:
            await self._accounts.verify_password(login, password)
        except LoginRejected as exc:
            reached_plesk = exc.reason in ("credentials", "suspended", "not_customer")
            await self._limiter.record_login_failure(ip=ip, login=login, plesk_checked=reached_plesk)
            self._audit.write("login_failed", ip=ip, login=login, reason=exc.reason, client="account_page")
            return self._login_page(session["csrf"], exc.message, login, 401 if reached_plesk else 503)
        await self._limiter.record_login_success(ip=ip, login=login)
        await self._drop_session(session["sid"])
        sid, _ = await self._new_session(login)
        self._audit.write("account_page_login", ip=ip, login=login)
        return self._set_cookie(self._redirect(), sid)

    async def post_logout(self, request: Request) -> Response:
        session, _ = await self._form(request)
        if session is not None:
            await self._drop_session(session["sid"])
        response = self._redirect()
        response.delete_cookie(SESSION_COOKIE, path=f"{self.base}/account")
        return response

    async def post_disconnect(self, request: Request) -> Response:
        session, data = await self._form(request)
        if session is None or not session.get("login"):
            return simple_page("Ungültige Anfrage", "Bitte zuerst anmelden.", 400)
        login = session["login"]
        client_id = data.get("client_id", "")
        if client_id == "*":
            n = await self._accounts.revoke_login(login, delete_secret_key=True, source="account_page")
            await self._accounts.invalidate_caches(login)
            return await self._dashboard(session, notice=f"Alle Verbindungen getrennt ({n} Token widerrufen). Der API-Schlüssel in Plesk wurde gelöscht.")
        n = await self._store.revoke_login(login, client_id=client_id)
        self._audit.write("tokens_revoked", login=login, tokens_revoked=n, source="account_page", client=client_id)
        return await self._dashboard(session, notice=f"Verbindung getrennt ({n} Token widerrufen).")

    async def post_db(self, request: Request) -> Response:
        session, data = await self._form(request)
        if session is None or not session.get("login"):
            return simple_page("Ungültige Anfrage", "Bitte zuerst anmelden.", 400)
        login = session["login"]
        database = data.get("database", "").strip()
        if not DB_NAME_RE.match(database):
            return await self._dashboard(session, error="Ungültiger Datenbankname.")
        if data.get("action") == "delete":
            row = await self._store.get_db_credential_row(login, database)
            if row and row.get("source") == "service":
                return await self._dashboard(session, error="Zugangsdaten einer vom Dienst angelegten Datenbank können hier nicht gelöscht werden (db_drop).")
            n = await self._store.delete_db_credential(login, database)
            self._audit.write("db_credentials_deleted", login=login, database=database, source="account_page")
            return await self._dashboard(session, notice=f"Zugangsdaten gelöscht ({n})." if n else "Keine Zugangsdaten vorhanden.")
        user = data.get("db_user", "").strip()
        password = data.get("db_password", "")
        if not IDENT_RE.match(user) or not password:
            return await self._dashboard(session, error="Benutzer oder Passwort fehlt.")
        if not self._accounts.can_encrypt:
            return await self._dashboard(session, error="Der Dienst kann keine Zugangsdaten speichern (DATA_ENCRYPTION_KEY fehlt).")
        known = await self._known_databases(login)
        if known and database not in known:
            return await self._dashboard(session, error="Diese Datenbank gehört laut Plesk nicht zu deinen Abos.")
        if not known:
            return await self._dashboard(session, error="Bitte zuerst eine KI-Anwendung verbinden; danach kennt der Dienst die Datenbanken deiner Abos.")
        row = await self._store.get_db_credential_row(login, database)
        source = "service" if row and row.get("source") == "service" else "stored"
        await self._store.save_db_credential(login, database, user, self._accounts.encrypt(password), source=source)
        self._audit.write("db_credentials_saved", login=login, database=database, source="account_page")
        return await self._dashboard(session, notice=f"Zugangsdaten für {database} gespeichert.")
