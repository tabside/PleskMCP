"""MCP tools. Every call resolves the Plesk login from the bearer token,
re-validates the account, checks the domain belongs to that login and then
runs the helper on the Plesk server as the subscription's system user.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Literal

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from .accounts import AccountInactive, AccountService
from .audit import AuditLog
from .config import Settings
from .plesk_api import DomainInfo
from .remote import HelperError, RemoteError, RemoteExecutor

logger = logging.getLogger(__name__)

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=False)
WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=False)
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)


class ToolRunner:
    def __init__(self, settings: Settings, accounts: AccountService, executor: RemoteExecutor, audit: AuditLog):
        self._settings = settings
        self._accounts = accounts
        self._executor = executor
        self._audit = audit

    async def context(self) -> tuple[str, str, list[str], Any]:
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
        return login, token.client_id, token.scopes, account

    async def run(self, op: str, domain: str, args: dict[str, Any], *, write: bool, tool: str) -> dict[str, Any]:
        login, client_id, scopes, account = await self.context()
        if write and "files:write" not in scopes:
            raise ToolError("Für diese Aktion fehlt die Berechtigung files:write.")
        info: DomainInfo | None = account.find_domain(domain)
        if info is None:
            names = ", ".join(sorted(d.name for d in account.domains)) or "keine"
            self._audit.write("domain_rejected", login=login, domain=domain, tool=tool, client=client_id)
            raise ToolError(f"Die Domain '{domain}' gehört nicht zu diesem Konto. Verfügbare Domains: {names}")
        request = {
            "v": 1,
            "op": op,
            "domain": info.name,
            "docroot": info.docroot,
            "limits": {
                "read_max_bytes": self._settings.read_max_bytes,
                "write_max_bytes": self._settings.write_max_bytes,
                "list_max_entries": self._settings.list_max_entries,
                "log_max_lines": self._settings.log_max_lines,
            },
            "args": args,
        }
        if write:
            self._audit.write(
                "tool_write",
                login=login,
                domain=info.name,
                tool=tool,
                path=args.get("path") or args.get("src"),
                dst=args.get("dst"),
                client=client_id,
            )
        try:
            result = await self._executor.run(info.sysuser, request)
        except HelperError as exc:
            if write:
                self._audit.write("tool_write_failed", login=login, domain=info.name, tool=tool, error=exc.code, client=client_id)
            raise ToolError(f"{exc.message} [{exc.code}]")
        except RemoteError as exc:
            logger.error("remote execution failed for %s/%s: %s", login, info.name, exc)
            raise ToolError("Der Dateidienst auf dem Server ist derzeit nicht erreichbar.")
        return result


def register_tools(mcp: MCPServer, runner: ToolRunner, settings: Settings) -> None:
    @mcp.tool(
        description="Listet die Domains (Abonnements, Addon-Domains, Subdomains) des angemeldeten Plesk-Kontos mit ihrem Document Root.",
        annotations=READ_ONLY,
    )
    async def list_domains() -> dict[str, Any]:
        login, _client_id, _scopes, account = await runner.context()
        return {
            "login": login,
            "domains": [
                {"name": d.name, "kind": d.kind, "webspace": d.webspace, "docroot": d.docroot}
                for d in account.domains
                if d.status == 0
            ],
        }

    @mcp.tool(
        description="Listet ein Verzeichnis unterhalb des Document Root einer Domain (path relativ, leer = Document Root).",
        annotations=READ_ONLY,
    )
    async def list_dir(domain: str, path: str = "") -> dict[str, Any]:
        return await runner.run("list_dir", domain, {"path": path}, write=False, tool="list_dir")

    @mcp.tool(
        description=(
            "Liest eine Datei unterhalb des Document Root. encoding=text liefert UTF-8-Text, encoding=base64 den "
            "Inhalt für Binärdateien. Grosse Dateien werden auf READ_MAX_BYTES gekürzt (truncated=true), "
            "weitere Teile lassen sich mit offset lesen."
        ),
        annotations=READ_ONLY,
    )
    async def read_file(
        domain: str,
        path: str,
        encoding: Literal["text", "base64"] = "text",
        offset: int = 0,
        max_bytes: int | None = None,
    ) -> dict[str, Any]:
        args: dict[str, Any] = {"path": path, "encoding": encoding, "offset": max(0, offset)}
        if max_bytes is not None and max_bytes > 0:
            args["max_bytes"] = min(max_bytes, settings.read_max_bytes)
        return await runner.run("read_file", domain, args, write=False, tool="read_file")

    @mcp.tool(
        description=(
            "Schreibt eine Datei unterhalb des Document Root (neu anlegen oder überschreiben). Bestehende Dateien "
            "werden vorher in die Sicherung ausserhalb des Webroots kopiert. encoding=base64 für Binärdateien. "
            "create_dirs=true legt fehlende Zwischenordner an."
        ),
        annotations=WRITE,
    )
    async def write_file(
        domain: str,
        path: str,
        content: str,
        encoding: Literal["text", "base64"] = "text",
        create_dirs: bool = False,
    ) -> dict[str, Any]:
        size = len(content.encode("utf-8")) if encoding == "text" else _b64_size(content)
        if size > settings.write_max_bytes:
            raise ToolError(f"Inhalt überschreitet das Schreiblimit von {settings.write_max_bytes} Bytes.")
        args = {"path": path, "content": content, "encoding": encoding, "create_dirs": create_dirs, "backup": True}
        return await runner.run("write_file", domain, args, write=True, tool="write_file")

    @mcp.tool(
        description=(
            "Ersetzt eine Textstelle in einer UTF-8-Datei. old_str muss exakt vorkommen; bei mehreren Treffern ist "
            "replace_all=true nötig. Vor dem Schreiben wird eine Sicherung angelegt."
        ),
        annotations=WRITE,
    )
    async def replace_in_file(domain: str, path: str, old_str: str, new_str: str, replace_all: bool = False) -> dict[str, Any]:
        args = {"path": path, "old_str": old_str, "new_str": new_str, "replace_all": replace_all}
        return await runner.run("replace_in_file", domain, args, write=True, tool="replace_in_file")

    @mcp.tool(
        description=(
            "Verschiebt oder benennt eine Datei oder einen Ordner innerhalb des Document Root um. Ein bestehendes "
            "Ziel wird nur mit overwrite=true ersetzt (nur Dateien, mit Sicherung)."
        ),
        annotations=WRITE,
    )
    async def move_file(domain: str, src: str, dst: str, overwrite: bool = False, create_dirs: bool = False) -> dict[str, Any]:
        args = {"src": src, "dst": dst, "overwrite": overwrite, "create_dirs": create_dirs}
        return await runner.run("move_file", domain, args, write=True, tool="move_file")

    @mcp.tool(
        description=(
            "Verschiebt eine Datei oder (mit recursive=true) einen Ordner in den Papierkorb ausserhalb des Webroots. "
            "Nichts wird endgültig gelöscht; restore_file stellt den Eintrag wieder her."
        ),
        annotations=DESTRUCTIVE,
    )
    async def delete_file(domain: str, path: str, recursive: bool = False) -> dict[str, Any]:
        return await runner.run("delete_file", domain, {"path": path, "recursive": recursive}, write=True, tool="delete_file")

    @mcp.tool(
        description=(
            "Ohne trash_id: listet die Papierkorb-Einträge der Domain. Mit trash_id: stellt den Eintrag am "
            "ursprünglichen Ort wieder her (nur wenn dort nichts liegt)."
        ),
        annotations=WRITE,
    )
    async def restore_file(domain: str, trash_id: str | None = None) -> dict[str, Any]:
        return await runner.run("restore_file", domain, {"trash_id": trash_id}, write=True, tool="restore_file")

    @mcp.tool(
        description=(
            "Durchsucht ein Webserver-Log der Domain (access_log, error_log, proxy_access_log, proxy_error_log, "
            "auch rotierte wie error_log.1 oder access_log-20260101.gz) nach einem regulären Ausdruck und liefert "
            "die letzten Treffer. Nur lesend."
        ),
        annotations=READ_ONLY,
    )
    async def search_log(domain: str, log: str = "error_log", pattern: str = "", lines: int = 200) -> dict[str, Any]:
        login, _client_id, _scopes, account = await runner.context()
        info = account.find_domain(domain)
        kind = info.kind if info else "webspace"
        args = {"log": log, "pattern": pattern, "lines": max(1, min(lines, settings.log_max_lines)), "kind": kind}
        return await runner.run("search_log", domain, args, write=False, tool="search_log")


def _b64_size(content: str) -> int:
    try:
        return len(base64.b64decode(content, validate=True))
    except (ValueError, TypeError):
        raise ToolError("content ist kein gültiges Base64.")
