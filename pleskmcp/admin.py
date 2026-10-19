"""Operator endpoint: who uses the service.

    GET /admin/usage    accounts with their connections (OAuth clients, last use),
                        call counters and the plan access of their domains

Protected by ADMIN_API_TOKEN, sent either as `Authorization: Bearer <token>`
(scripts) or as the password of HTTP Basic auth with any user name (browser).
Without ADMIN_API_TOKEN the route answers 404. Failed attempts are rate
limited per IP (successful requests are not counted) and written to the audit log. The response contains logins,
display names, domain names and client names, but never tokens or secrets.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import html
import time
from typing import Any

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response

from .audit import AuditLog
from .auth.login import client_ip
from .auth.ratelimit import RedisLimiter
from .config import Settings
from .db import Store
from .usage import UsageTracker

ACTIVE_WINDOW = 30 * 86400  # a login counts as "active" with a call in the last 30 days


class AdminPages:
    def __init__(self, settings: Settings, store: Store, usage: UsageTracker, limiter: RedisLimiter, audit: AuditLog):
        self._settings = settings
        self._store = store
        self._usage = usage
        self._limiter = limiter
        self._audit = audit

    # ----------------------------------------------------------------- auth
    def _presented_token(self, request: Request) -> str | None:
        header = request.headers.get("authorization", "")
        scheme, _, value = header.partition(" ")
        value = value.strip()
        if scheme.lower() == "bearer" and value:
            return value
        if scheme.lower() == "basic" and value:
            try:
                decoded = base64.b64decode(value, validate=True).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return None
            _, _, password = decoded.partition(":")
            return password or None
        return None

    def _authorized(self, request: Request) -> bool:
        expected = self._settings.admin_api_token
        presented = self._presented_token(request)
        if not expected or not presented:
            return False
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))

    @staticmethod
    def _challenge(status: int = 401) -> Response:
        return JSONResponse(
            {"error": "unauthorized"},
            status_code=status,
            headers={"WWW-Authenticate": 'Basic realm="pleskmcp admin", charset="UTF-8"', "Cache-Control": "no-store"},
        )

    # --------------------------------------------------------------- report
    async def report(self) -> dict[str, Any]:
        now = int(time.time())
        accounts = await self._store.list_accounts()
        connections = await self._store.connections_summary()
        usage = await self._usage.summary()
        known = {a["plesk_login"] for a in accounts}
        rows: list[dict[str, Any]] = []
        for account in accounts:
            login = account["plesk_login"]
            rows.append(self._row(login, account, connections.get(login, []), usage.get(login)))
        # tokens or counters of a login whose account row is gone (deleted after a full disconnect)
        for login in sorted((set(connections) | set(usage)) - known):
            rows.append(self._row(login, None, connections.get(login, []), usage.get(login)))
        connected = sum(1 for r in rows if r["connections"])
        active = sum(1 for r in rows if r["usage"]["last_call_at"] and r["usage"]["last_call_at"] >= now - ACTIVE_WINDOW)
        return {
            "generated_at": now,
            "totals": {
                "accounts": len(rows),
                "connected": connected,
                "active_30d": active,
                "calls_7d": sum(r["usage"]["calls_7d"] for r in rows),
                "calls_30d": sum(r["usage"]["calls_30d"] for r in rows),
            },
            "accounts": rows,
        }

    @staticmethod
    def _row(login: str, account: dict[str, Any] | None, connections: list[dict[str, Any]], usage: dict[str, Any] | None) -> dict[str, Any]:
        domains = []
        for d in (account or {}).get("domains", []):
            if not isinstance(d, dict):
                continue
            domains.append({"name": d.get("name"), "kind": d.get("kind"), "webspace": d.get("webspace"), "status": d.get("status")})
        return {
            "login": login,
            "display_name": (account or {}).get("display_name"),
            "status": (account or {}).get("status", "unknown"),
            "created_at": (account or {}).get("created_at"),
            "checked_at": (account or {}).get("checked_at"),
            "domains": domains,
            "connections": connections,
            "usage": usage
            or {
                "calls": 0,
                "writes": 0,
                "first_call_at": None,
                "last_call_at": None,
                "last_client": None,
                "last_write_tool": None,
                "last_write_at": None,
                "calls_7d": 0,
                "calls_30d": 0,
            },
        }

    # ------------------------------------------------------------- endpoint
    async def usage(self, request: Request) -> Response:
        if not self._settings.admin_api_token:
            return JSONResponse({"error": "not_found"}, status_code=404)
        ip = client_ip(request)
        retry_after = await self._limiter.admin_retry_after(ip)
        if retry_after is not None:
            return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"})
        if not self._authorized(request):
            # only failures count towards the limit; a browser reloading the report is never locked out
            await self._limiter.record_admin_failure(ip)
            self._audit.write("admin_denied", ip=ip, endpoint="usage")
            return self._challenge()
        self._audit.write("admin_usage", ip=ip)
        data = await self.report()
        wants_html = request.query_params.get("format") == "html" or (
            "format" not in request.query_params and "text/html" in request.headers.get("accept", "") and "application/json" not in request.headers.get("accept", "")
        )
        if wants_html:
            return HTMLResponse(render_html(self._settings.service_name, data), headers={"Cache-Control": "no-store"})
        return JSONResponse(data, headers={"Cache-Control": "no-store"})


# ------------------------------------------------------------------ HTML view
_PAGE = """<!doctype html><html lang="de"><head><meta charset="utf-8"><title>{service}: Nutzung</title>
<meta name="robots" content="noindex"><meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font:14px/1.45 system-ui,sans-serif;margin:2rem;color:#1b1b1b}}table{{border-collapse:collapse;width:100%}}
th,td{{text-align:left;padding:.4rem .6rem;border-bottom:1px solid #ddd;vertical-align:top}}th{{background:#f3f3f3}}
.muted{{color:#777}}.n{{text-align:right;font-variant-numeric:tabular-nums}}small{{color:#555}}</style></head><body>
<h1>{service}: Nutzung</h1>
<p class="muted">Stand {generated} · Konten {accounts} · verbunden {connected} · aktiv (30 Tage) {active} · Aufrufe 7 Tage {calls7} · 30 Tage {calls30}</p>
<table><thead><tr><th>Login</th><th>Status</th><th>Domains</th><th>Verbindungen</th><th class="n">Aufrufe</th><th class="n">7 Tage</th><th class="n">30 Tage</th><th class="n">Schreibend</th><th>Letzter Aufruf</th></tr></thead>
<tbody>{rows}</tbody></table>
<p class="muted"><small>Verbindungen: OAuth-Client (Token-Familien, letzte Nutzung). Aufrufe zählen jeden Tool-Aufruf, Schreibend nur Änderungen; Details im Audit-Log.</small></p>
</body></html>"""


def _fmt_ts(ts: int | None) -> str:
    if not ts:
        return "–"
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


def render_html(service: str, data: dict[str, Any]) -> str:
    rows = []
    for a in data["accounts"]:
        u = a["usage"]
        domains = ", ".join(html.escape(d["name"] or "") for d in a["domains"] if d.get("status", 0) == 0) or "–"
        conns = (
            "<br>".join(
                f"{html.escape(c['client_name'] or c['client_id'][:40])} <small>({c['families']}, {html.escape(_fmt_ts(c['last_used']))})</small>" for c in a["connections"]
            )
            or "<span class='muted'>keine</span>"
        )
        name = f" <small>{html.escape(a['display_name'])}</small>" if a.get("display_name") else ""
        last = _fmt_ts(u["last_call_at"])
        if u.get("last_write_tool"):
            last += f" <small>({html.escape(u['last_write_tool'])} {html.escape(_fmt_ts(u['last_write_at']))})</small>"
        rows.append(
            f"<tr><td>{html.escape(a['login'])}{name}</td><td>{html.escape(a['status'])}</td><td>{domains}</td><td>{conns}</td>"
            f"<td class='n'>{u['calls']}</td><td class='n'>{u['calls_7d']}</td><td class='n'>{u['calls_30d']}</td><td class='n'>{u['writes']}</td><td>{last}</td></tr>"
        )
    t = data["totals"]
    return _PAGE.format(
        service=html.escape(service),
        generated=html.escape(_fmt_ts(data["generated_at"])),
        accounts=t["accounts"],
        connected=t["connected"],
        active=t["active_30d"],
        calls7=t["calls_7d"],
        calls30=t["calls_30d"],
        rows="".join(rows) or "<tr><td colspan='9' class='muted'>keine Konten</td></tr>",
    )
