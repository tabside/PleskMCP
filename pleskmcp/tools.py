"""MCP tools for files, versions, storage and jobs.

Every call resolves the Plesk login from the bearer token, re-validates the
account, checks the domain belongs to that login, applies the access profile
of the subscription (effective scopes = token scopes intersected with the
profile), takes a token from the per-login rate limiter and then submits a
job for the worker. The api waits up to TOOL_SYNC_WAIT seconds for the
result; longer jobs return a job_id for `job_status`.
"""

from __future__ import annotations

import base64
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Literal

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations
from redis.asyncio import Redis

from .accounts import Account, AccountInactive, AccountService, NoAccess
from .audit import AuditLog
from .auth.ratelimit import RateLimited, RedisLimiter
from .config import Settings
from .plesk_api import DomainInfo
from .profiles import Profile
from .queue import HI, JobInfo, JobQueue
from .usage import UsageTracker

logger = logging.getLogger(__name__)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)

LONG_RUNNING_OPS = {"search_log", "purge_store", "retention", "report_ownership", "db_restore", "restore_version"}


@dataclass
class CallContext:
    login: str
    client_id: str
    token_scopes: list[str]
    account: Account


@dataclass
class DomainContext:
    info: DomainInfo
    profile: Profile
    scopes: list[str]  # effective scopes
    limits: dict[str, Any]


class ToolRunner:
    def __init__(self, settings: Settings, accounts: AccountService, queue: JobQueue, limiter: RedisLimiter, audit: AuditLog, redis: Redis):
        self._settings = settings
        self._accounts = accounts
        self._queue = queue
        self._limiter = limiter
        self._audit = audit
        self._redis = redis
        self._usage = UsageTracker(redis)

    @property
    def settings(self) -> Settings:
        return self._settings

    @property
    def accounts(self) -> AccountService:
        return self._accounts

    @property
    def audit(self) -> AuditLog:
        return self._audit

    @property
    def limiter(self) -> RedisLimiter:
        return self._limiter

    @property
    def redis(self) -> Redis:
        return self._redis

    @property
    def usage(self) -> UsageTracker:
        return self._usage

    # ----------------------------------------------------------------- context
    async def context(self) -> CallContext:
        token = get_access_token()
        if token is None:
            raise ToolError("Nicht angemeldet.")
        login = getattr(token, "plesk_login", None) or token.subject
        if not login:
            raise ToolError("Nicht angemeldet.")
        try:
            account = await self._accounts.get_active_account(login)
        except AccountInactive:
            raise ToolError("Das Plesk-Konto ist nicht mehr aktiv oder der Zugang wurde widerrufen. Bitte neu verbinden.")
        await self._usage.record(login, client_id=token.client_id)
        return CallContext(login=login, client_id=token.client_id, token_scopes=list(token.scopes), account=account)

    async def domain(self, ctx: CallContext, name: str, *, need_scope: str, tool: str) -> DomainContext:
        info = ctx.account.find_domain(name)
        if info is None:
            names = ", ".join(sorted(d.name for d in ctx.account.domains if d.status == 0)) or "keine"
            self._audit.write("domain_rejected", login=ctx.login, domain=name, tool=tool, client=ctx.client_id)
            raise ToolError(f"Die Domain '{name}' gehört nicht zu diesem Konto. Verfügbare Domains: {names}")
        try:
            profile = await self._accounts.profile_for(ctx.login, info)
        except NoAccess:
            self._audit.write("no_access", login=ctx.login, domain=info.name, tool=tool, client=ctx.client_id)
            raise ToolError(f"KI-Zugang für dieses Abo nicht gebucht ({info.webspace}).")
        effective = [s for s in ctx.token_scopes if s in profile.scopes]
        if need_scope not in effective:
            if need_scope in profile.scopes:
                raise ToolError(f"Für diese Aktion fehlt die Berechtigung {need_scope}. Bitte die Verbindung mit diesem Recht neu herstellen.")
            raise ToolError(f"Das Abo {info.webspace} erlaubt {need_scope} nicht (Profil: {profile.name}).")
        limits: dict[str, Any] = dict(self._settings.helper_limits)
        limits.update(profile.limits(self._settings.profile_defaults))
        quota = await self._accounts.quota_for(ctx.login, info)
        limits["quota_bytes"] = quota.quota_bytes
        limits["used_bytes"] = quota.used_bytes
        return DomainContext(info=info, profile=profile, scopes=effective, limits=limits)

    async def accessible_domains(self, ctx: CallContext) -> list[dict[str, Any]]:
        result = []
        for d in ctx.account.domains:
            if d.status != 0:
                continue
            try:
                profile = await self._accounts.profile_for(ctx.login, d)
            except NoAccess:
                continue
            result.append(
                {
                    "name": d.name,
                    "kind": d.kind,
                    "webspace": d.webspace,
                    "docroot": d.docroot,
                    "profile": profile.name,
                    "scopes": [s for s in ctx.token_scopes if s in profile.scopes],
                }
            )
        return result

    # ------------------------------------------------------------------- jobs
    async def submit(
        self,
        ctx: CallContext,
        dom: DomainContext,
        op: str,
        args: dict[str, Any],
        *,
        write: bool,
        tool: str,
        write_bytes: int = 0,
        priority: str = HI,
        long_running: bool | None = None,
        audit_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        profile_limits = dom.profile.limits(self._settings.profile_defaults)
        try:
            await self._limiter.take_tool_call(ctx.login, write=write, write_bytes=write_bytes, limits=profile_limits)
        except RateLimited as exc:
            self._audit.write("rate_limited", login=ctx.login, domain=dom.info.name, tool=tool, scope=exc.scope, retry_after=exc.retry_after, client=ctx.client_id)
            raise ToolError(f"Limit erreicht ({exc.scope}). Bitte in {exc.retry_after} Sekunden erneut versuchen.")
        limits = dict(dom.limits)
        is_long = long_running if long_running is not None else op in LONG_RUNNING_OPS
        limits["time_limit"] = self._settings.job_time_limit if is_long else self._settings.helper_time_limit
        request: dict[str, Any] = {
            "v": 2,
            "op": op,
            "domain": dom.info.name,
            "docroot": dom.info.docroot,
            "limits": limits,
            "args": args,
            "tool": tool,
        }
        if write:
            request["request_id"] = secrets.token_urlsafe(16)
            fields = {"login": ctx.login, "domain": dom.info.name, "tool": tool, "client": ctx.client_id, "request_id": request["request_id"]}
            fields.update(audit_fields or {"path": args.get("path") or args.get("src"), "dst": args.get("dst")})
            self._audit.write("tool_write", **fields)
            await self._usage.record(ctx.login, client_id=ctx.client_id, tool=tool, write=True)
        job_id = await self._queue.submit(login=ctx.login, domain=dom.info.name, sysuser=dom.info.sysuser, request=request, write=write, priority=priority, tool=tool)
        info = await self._queue.wait(job_id, self._settings.tool_sync_wait)
        return self._outcome(ctx, dom, tool, write, info, job_id)

    def _outcome(self, ctx: CallContext, dom: DomainContext | None, tool: str, write: bool, info: JobInfo | None, job_id: str) -> dict[str, Any]:
        if info is None:
            raise ToolError("Der Auftrag ist verloren gegangen. Bitte erneut versuchen.")
        if info.status == "done":
            return info.result if isinstance(info.result, dict) else {"result": info.result}
        if info.status == "failed":
            error = info.error or {"code": "unknown", "message": "operation failed"}
            if write and dom is not None:
                self._audit.write("tool_write_failed", login=ctx.login, domain=dom.info.name, tool=tool, error=error.get("code"), client=ctx.client_id)
            raise ToolError(self.explain_error(error))
        return {
            "job_id": job_id,
            "status": info.status,
            "hint": f"Der Auftrag läuft noch. Status und Ergebnis mit job_status(job_id='{job_id}') abfragen.",
        }

    @staticmethod
    def explain_error(error: dict[str, Any]) -> str:
        code = str(error.get("code", "error"))
        message = str(error.get("message", ""))
        details = error.get("details") or {}
        operator = "Der Hoster muss das beheben; der Fehler steht im Worker-Log."
        if code in ("remote_unavailable", "ssh_unreachable"):
            return f"Der Dateidienst auf dem Server ist derzeit nicht erreichbar. Bitte später erneut versuchen. [{code}]"
        if code == "ssh_config":
            return f"Der Dateidienst ist nicht korrekt eingerichtet (SSH-Schlüssel oder Host-Key des Servers nicht verwendbar). {operator} [{code}]"
        if code == "ssh_auth":
            return f"Der Server hat die Anmeldung des Dateidienstes abgelehnt (SSH-Schlüssel nicht hinterlegt). {operator} [{code}]"
        if code == "sudo_refused":
            return f"Dem Dateidienst fehlt auf dem Server die Berechtigung, als Systembenutzer des Abos zu arbeiten (sudoers). {operator} [{code}]"
        if code == "helper_crash":
            return f"Das Hilfsprogramm auf dem Server hat keine gültige Antwort geliefert (veraltete Version oder Absturz; install.sh erneut ausführen). {operator} [{code}]"
        if code in ("timeout", "helper_timeout"):
            return f"Zeitlimit überschritten: {message or 'der Auftrag auf dem Server hat zu lange gedauert'} [{code}]"
        if code == "worker_lost":
            return f"Der Auftrag wurde unterbrochen und mehrfach wiederholt, ohne Ergebnis. Bitte erneut versuchen. [{code}]"
        if code == "internal":
            kind = details.get("error")
            return f"Interner Fehler im Dateidienst{f' ({kind})' if kind else ''}. {operator} [{code}]"
        if code == "quota_exceeded":
            usage = details.get("usage_bytes")
            limit = details.get("limit_bytes")
            if usage is not None and limit is not None:
                return f"Speicherkontingent des Abos erschöpft: {usage} von {limit} Bytes belegt. Die Sicherungen wurden bereits aufgeräumt; bitte Dateien löschen oder das Kontingent erhöhen. [{code}]"
            return f"Speicherkontingent erschöpft: {message} [{code}]"
        if code == "not_owner":
            return f"{message} [{code}] (Pfad: {details.get('path')}, Besitzer: {details.get('owner')})"
        return f"{message} [{code}]"

    async def job_status(self, ctx: CallContext, job_id: str) -> dict[str, Any]:
        info = await self._queue.get_for_login(ctx.login, job_id)
        if info is None:
            raise ToolError("Unbekannte oder abgelaufene job_id.")
        data = info.public()
        if info.status == "failed" and info.error:
            data["message"] = self.explain_error(info.error)
        return data


def register_tools(mcp: MCPServer, runner: ToolRunner, settings: Settings) -> None:
    @mcp.tool(
        description="Listet die Domains des angemeldeten Plesk-Kontos, für die KI-Zugang gebucht ist, mit Document Root, Profil und effektiven Rechten.",
        annotations=READ_ONLY,
    )
    async def list_domains() -> dict[str, Any]:
        ctx = await runner.context()
        return {"login": ctx.login, "domains": await runner.accessible_domains(ctx)}

    @mcp.tool(description="Status und Ergebnis eines Hintergrund-Auftrags (job_id aus einem früheren Tool-Aufruf).", annotations=READ_ONLY)
    async def job_status(job_id: str) -> dict[str, Any]:
        ctx = await runner.context()
        return await runner.job_status(ctx, job_id)

    @mcp.tool(description="Listet ein Verzeichnis unterhalb des Document Root einer Domain (path relativ, leer = Document Root).", annotations=READ_ONLY)
    async def list_dir(domain: str, path: str = "") -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:read", tool="list_dir")
        return await runner.submit(ctx, dom, "list_dir", {"path": path}, write=False, tool="list_dir")

    @mcp.tool(
        description=(
            "Liest eine Datei unterhalb des Document Root. encoding=text liefert UTF-8-Text, encoding=base64 den Inhalt "
            "für Binärdateien. In geschützten Dateien (wp-config.php, .env, ...) sind Zugangsdaten als *** geschwärzt; "
            "Schlüsseldateien (*.pem, *.key) sind nicht lesbar. Grosse Dateien werden gekürzt (truncated=true), weitere "
            "Teile lassen sich mit offset lesen."
        ),
        annotations=READ_ONLY,
    )
    async def read_file(domain: str, path: str, encoding: Literal["text", "base64"] = "text", offset: int = 0, max_bytes: int | None = None) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:read", tool="read_file")
        args: dict[str, Any] = {"path": path, "encoding": encoding, "offset": max(0, offset)}
        if max_bytes is not None and max_bytes > 0:
            args["max_bytes"] = min(max_bytes, settings.read_max_bytes)
        return await runner.submit(ctx, dom, "read_file", args, write=False, tool="read_file")

    @mcp.tool(
        description=(
            "Schreibt eine Datei unterhalb des Document Root (neu anlegen oder überschreiben). Die bisherige Version wird "
            "vorher gesichert (list_versions/restore_version). encoding=base64 für Binärdateien, create_dirs=true legt "
            "fehlende Zwischenordner an. In geschützten Dateien darf kein geschwärzter Wert (***) zurückgeschrieben werden."
        ),
        annotations=WRITE,
    )
    async def write_file(domain: str, path: str, content: str, encoding: Literal["text", "base64"] = "text", create_dirs: bool = False) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:write", tool="write_file")
        size = len(content.encode("utf-8")) if encoding == "text" else _b64_size(content)
        if size > settings.write_max_bytes:
            raise ToolError(f"Inhalt überschreitet das Schreiblimit von {settings.write_max_bytes} Bytes.")
        args = {"path": path, "content": content, "encoding": encoding, "create_dirs": create_dirs, "backup": True}
        return await runner.submit(ctx, dom, "write_file", args, write=True, tool="write_file", write_bytes=size)

    @mcp.tool(
        description=(
            "Ersetzt eine Textstelle in einer UTF-8-Datei. old_str muss exakt vorkommen; bei mehreren Treffern ist "
            "replace_all=true nötig. Die bisherige Version wird gesichert."
        ),
        annotations=WRITE,
    )
    async def replace_in_file(domain: str, path: str, old_str: str, new_str: str, replace_all: bool = False) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:write", tool="replace_in_file")
        args = {"path": path, "old_str": old_str, "new_str": new_str, "replace_all": replace_all}
        return await runner.submit(ctx, dom, "replace_in_file", args, write=True, tool="replace_in_file", write_bytes=len(new_str.encode("utf-8")))

    @mcp.tool(
        description="Verschiebt oder benennt eine Datei oder einen Ordner innerhalb des Document Root um. Ein bestehendes Ziel wird nur mit overwrite=true ersetzt (nur Dateien, mit Sicherung).",
        annotations=WRITE,
    )
    async def move_file(domain: str, src: str, dst: str, overwrite: bool = False, create_dirs: bool = False) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:write", tool="move_file")
        args = {"src": src, "dst": dst, "overwrite": overwrite, "create_dirs": create_dirs}
        return await runner.submit(ctx, dom, "move_file", args, write=True, tool="move_file")

    @mcp.tool(
        description="Verschiebt eine Datei oder (mit recursive=true) einen Ordner in den Papierkorb ausserhalb des Webroots. Nichts wird endgültig gelöscht; restore_file stellt den Eintrag wieder her.",
        annotations=DESTRUCTIVE,
    )
    async def delete_file(domain: str, path: str, recursive: bool = False) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:write", tool="delete_file")
        return await runner.submit(ctx, dom, "delete_file", {"path": path, "recursive": recursive}, write=True, tool="delete_file")

    @mcp.tool(
        description="Ohne trash_id: listet die Papierkorb-Einträge der Domain. Mit trash_id: stellt den Eintrag am ursprünglichen Ort wieder her (nur wenn dort nichts liegt).",
        annotations=WRITE,
    )
    async def restore_file(domain: str, trash_id: str | None = None) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:write", tool="restore_file")
        return await runner.submit(ctx, dom, "restore_file", {"trash_id": trash_id}, write=bool(trash_id), tool="restore_file", audit_fields={"trash_id": trash_id})

    @mcp.tool(
        description="Listet die gesicherten Versionen einer Datei (neueste zuerst). Jede schreibende Änderung legt vorher eine Version an.",
        annotations=READ_ONLY,
    )
    async def list_versions(domain: str, path: str) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:read", tool="list_versions")
        return await runner.submit(ctx, dom, "list_versions", {"path": path}, write=False, tool="list_versions")

    @mcp.tool(
        description=(
            "Spielt eine gesicherte Version einer Datei zurück (version_id aus list_versions). Der aktuelle Stand wird "
            "vorher ebenfalls gesichert. Funktioniert auch für gelöschte Dateien, solange eine Version existiert."
        ),
        annotations=WRITE,
    )
    async def restore_version(domain: str, path: str, version_id: str) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:write", tool="restore_version")
        return await runner.submit(ctx, dom, "restore_version", {"path": path, "version_id": version_id}, write=True, tool="restore_version", audit_fields={"path": path, "version_id": version_id})

    @mcp.tool(
        description=(
            "Letzte schreibende Änderungen der Domain (Dateiversionen, Papierkorb, DNS-Exporte, Datenbank-Dumps), neueste "
            "zuerst. since: ISO-Zeitpunkt oder Unix-Zeit. Damit lassen sich die letzten Änderungen rückgängig machen "
            "(restore_version, restore_file, dns_restore_zone, db_restore)."
        ),
        annotations=READ_ONLY,
    )
    async def list_changes(domain: str, since: str | None = None, limit: int = 50) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:read", tool="list_changes")
        return await runner.submit(ctx, dom, "list_changes", {"since": since, "limit": limit}, write=False, tool="list_changes")

    @mcp.tool(
        description="Belegung des Webspace, Belegung der Sicherungen (Versionen, Papierkorb, DNS-Exporte, Datenbank-Dumps), Kontingent und verbleibender Platz.",
        annotations=READ_ONLY,
    )
    async def storage_status(domain: str) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:read", tool="storage_status")
        result = await runner.submit(ctx, dom, "storage_status", {}, write=False, tool="storage_status")
        if "job_id" not in result:
            result["profile"] = dom.profile.name
            result["rate_limits"] = await runner._limiter.status(ctx.login)
        return result

    @mcp.tool(
        description=(
            "Räumt die Sicherungen auf: what=trash (Papierkorb), backups (Dateiversionen und DNS-Exporte), db_dumps oder "
            "all; older_than_days begrenzt auf ältere Einträge. Ohne confirm=true nur Vorschau. Endgültig."
        ),
        annotations=DESTRUCTIVE,
    )
    async def purge_store(domain: str, what: Literal["trash", "backups", "db_dumps", "all"] = "trash", older_than_days: int | None = None, confirm: bool = False) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:write", tool="purge_store")
        args = {"what": what, "older_than_days": older_than_days, "confirm": confirm}
        return await runner.submit(ctx, dom, "purge_store", args, write=confirm, tool="purge_store", audit_fields={"what": what, "older_than_days": older_than_days})

    @mcp.tool(
        description=(
            "Durchsucht ein Webserver-Log der Domain (access_log, error_log, proxy_access_log, proxy_error_log, auch "
            "rotierte wie error_log.1 oder access_log-20260101.gz) nach einem regulären Ausdruck und liefert die letzten "
            "Treffer. Zeilen mit Zugangsdaten werden geschwärzt. Grosse Logs laufen als Hintergrund-Auftrag."
        ),
        annotations=READ_ONLY,
    )
    async def search_log(domain: str, log: str = "error_log", pattern: str = "", lines: int = 200) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="files:read", tool="search_log")
        args = {"log": log, "pattern": pattern, "lines": max(1, min(lines, settings.log_max_lines)), "kind": dom.info.kind}
        return await runner.submit(ctx, dom, "search_log", args, write=False, tool="search_log")


def _b64_size(content: str) -> int:
    try:
        return len(base64.b64decode(content, validate=True))
    except (ValueError, TypeError):
        raise ToolError("content ist kein gültiges Base64.")
