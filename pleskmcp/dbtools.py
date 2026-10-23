"""Database tools (profiles with db:read / db:write / db:admin).

Queries run on the Plesk server in the helper, as the subscription's system
user, with the customer's own database user. Credentials come from the site
configuration on the server (wp-config.php, .env, ...), from the /account page
(stored Fernet-encrypted, decrypted only to hand them to the job) or from a
database the service created itself. They never reach the AI client.

Database management (db_create / db_drop) uses the Plesk XML API in the
customer context, i.e. with the customer's own secret key: the service has no
administrator write access. It is switched on with DB_MANAGEMENT_ENABLED after
the installation-specific verification described in the README.
"""

from __future__ import annotations

import logging
import re
import secrets
import string
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .accounts import AccountService, DatabaseListUnavailable
from .db import Store
from .plesk_api import PleskClient, PleskError, PleskResultError
from .tools import DESTRUCTIVE, READ_ONLY, WRITE, CallContext, DomainContext, ToolRunner

logger = logging.getLogger(__name__)

SUFFIX_RE = re.compile(r"^[a-z0-9_]{1,24}$")
DB_NAME_RE = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.-]{0,63}$")


class DbRunner:
    def __init__(self, runner: ToolRunner, store: Store, accounts: AccountService, plesk: PleskClient):
        self._runner = runner
        self._store = store
        self._accounts = accounts
        self._plesk = plesk

    @property
    def runner(self) -> ToolRunner:
        return self._runner

    async def prepare(self, domain: str, *, scope: str, tool: str) -> tuple[CallContext, DomainContext]:
        ctx = await self._runner.context()
        dom = await self._runner.domain(ctx, domain, need_scope=scope, tool=tool)
        return ctx, dom

    # ------------------------------------------------------------ credentials
    async def stored_credentials(self, login: str, database: str) -> dict[str, str] | None:
        row = await self._store.get_db_credential(login, database)
        if row is None:
            return None
        user, enc = row
        password = self._accounts.decrypt(enc)
        if password is None:
            return None
        return {"user": user, "password": password}

    async def all_credentials(self, login: str) -> tuple[dict[str, dict[str, str]], list[str]]:
        """{database: {user, password}} for every stored credential, plus the names the service created."""
        creds: dict[str, dict[str, str]] = {}
        created: list[str] = []
        for row in await self._store.list_db_credentials(login, with_secret=True):
            password = self._accounts.decrypt(row["password_enc"])
            if password is None:
                continue
            creds[row["database"]] = {"user": row["db_user"], "password": password}
            if row["source"] == "service":
                created.append(row["database"])
        return creds, created

    async def db_args(self, ctx: CallContext, dom: DomainContext, database: str, extra: dict[str, Any]) -> dict[str, Any]:
        if not DB_NAME_RE.match(database or ""):
            raise ToolError("Ungültiger Datenbankname.")
        await self.ensure_subscription_database(ctx, dom, database)
        args: dict[str, Any] = {"database": database}
        args.update(extra)
        stored = await self.stored_credentials(ctx.login, database)
        if stored is not None:
            args["credentials"] = stored
        return args

    async def ensure_subscription_database(self, ctx: CallContext, dom: DomainContext, database: str) -> None:
        """Hard server-side check that the database belongs to the subscription of the domain.

        Accepted are the databases Plesk lists for the subscription (cached for
        PLAN_CACHE_TTL, re-read once before refusing) and the ones the service
        created for this subscription. Everything else is refused here, so the
        isolation does not depend on the MySQL grants of the customer's database
        user alone. Without Plesk API access (ACCOUNT_CHECK_MODE=login_only) the
        database tools are unavailable.
        """
        try:
            names = {d.get("name") for d in await self._accounts.databases_for(ctx.login, dom.info, strict=True)}
            if database not in names:
                names = {d.get("name") for d in await self._accounts.databases_for(ctx.login, dom.info, refresh=True, strict=True)}
        except DatabaseListUnavailable as exc:
            if await self._accounts.api_auth_for(ctx.login) is None:
                raise ToolError("Datenbank-Tools sind in diesem Betriebsmodus nicht verfügbar (ACCOUNT_CHECK_MODE=login_only).")
            logger.warning("database ownership check for %s/%s failed: %s", ctx.login, dom.info.webspace, exc)
            raise ToolError("Die Datenbanken des Abos konnten in Plesk nicht abgefragt werden; bitte später erneut versuchen.")
        if database in names:
            return
        row = await self.service_row(ctx.login, database)
        if row is not None and row.get("webspace") == dom.info.webspace:
            return
        self._runner.audit.write("db_foreign_refused", login=ctx.login, domain=dom.info.name, database=database, client=ctx.client_id)
        raise ToolError(f"Die Datenbank {database} gehört nicht zum Abo {dom.info.webspace} (laut Plesk). Nur Datenbanken dieses Abos sind erreichbar; db_list zeigt sie.")

    async def known_database(self, ctx: CallContext, dom: DomainContext, database: str) -> dict[str, Any] | None:
        """The Plesk record of a database if the XML API lists it for the subscription."""
        for d in await self._accounts.databases_for(ctx.login, dom.info):
            if d.get("name") == database:
                return d
        return None

    async def service_row(self, login: str, database: str) -> dict[str, Any] | None:
        row = await self._store.get_db_credential_row(login, database)
        if row is None or row.get("source") != "service":
            return None
        return row

    # -------------------------------------------------------------- management
    def management_enabled(self) -> None:
        settings = self._runner.settings  # read per call: operators may toggle it at runtime
        if not settings.db_management_enabled:
            raise ToolError(
                "Das Anlegen und Löschen von Datenbanken ist auf diesem Dienst nicht freigeschaltet "
                "(DB_MANAGEMENT_ENABLED). Datenbanken bitte im Plesk-Panel anlegen und die Zugangsdaten auf der Kontoseite hinterlegen."
            )
        if settings.account_check_mode != "customer_key":
            raise ToolError("Datenbankverwaltung braucht den Kundenkontext (ACCOUNT_CHECK_MODE=customer_key).")

    async def customer_auth(self, ctx: CallContext) -> Any:
        auth = await self._accounts.customer_auth_for(ctx.login)
        if auth is None:
            raise ToolError("Für dieses Konto ist kein Plesk-Schlüssel hinterlegt. Bitte die Verbindung neu herstellen.")
        return auth

    @staticmethod
    def db_name_for(dom: DomainContext, suffix: str) -> str:
        """Plesk-style prefix (first label of the subscription) plus the sanitised suffix (a-z, 0-9, _; at most 24 chars)."""
        clean = re.sub(r"[^a-z0-9_]+", "_", (suffix or "").strip().lower()).strip("_")[:24].strip("_")
        if not SUFFIX_RE.match(clean):
            raise ToolError("name_suffix muss nach der Bereinigung mindestens ein Zeichen aus a-z, 0-9 oder _ enthalten.")
        prefix = re.sub(r"[^a-z0-9]", "_", dom.info.webspace.split(".")[0].lower())[:16].strip("_") or "db"
        return f"{prefix}_{clean}"[:64]

    @staticmethod
    def db_user_for(name: str) -> str:
        base = re.sub(r"[^a-z0-9_]", "_", name.lower())[:24].strip("_") or "u"
        return f"{base}_u{secrets.token_hex(2)}"[:32]

    @staticmethod
    def random_password(length: int = 40) -> str:
        alphabet = string.ascii_letters + string.digits + "-_.!$%*+:=?@^"
        while True:
            pw = "".join(secrets.choice(alphabet) for _ in range(length))
            if any(c.islower() for c in pw) and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
                return pw


def _explain_plesk_error(exc: PleskError) -> str:
    if isinstance(exc, PleskResultError):
        text = exc.text or ""
        if exc.code == 1006:
            return "Plesk verweigert die Operation für dieses Konto (Fehler 1006). Die Datenbankverwaltung über die API ist für Kundenlogins auf dieser Installation offenbar nicht erlaubt; bitte den Hoster informieren."
        if exc.code in (1007,):
            return f"Plesk: {text} (Name bereits vergeben)."
        if "limit" in text.lower() or exc.code == 1023:
            return f"Plesk: {text} (Datenbank-Limit des Abos erreicht)."
        return f"Plesk-Fehler {exc.code}: {text}"
    return f"Plesk-API nicht erreichbar: {exc}"


def register_db_tools(mcp: MCPServer, db: DbRunner) -> None:
    runner = db.runner

    @mcp.tool(
        description=(
            "Listet die Datenbanken des Abos einer Domain mit Grösse und Herkunft der Zugangsdaten: config (aus der "
            "Konfiguration der Website, z.B. wp-config.php), stored (auf der Kontoseite hinterlegt), service (vom "
            "Dienst mit db_create angelegt) oder missing (dann auf der Kontoseite hinterlegen). Zugangsdaten selbst "
            "werden nie angezeigt."
        ),
        annotations=READ_ONLY,
    )
    async def db_list(domain: str) -> dict[str, Any]:
        ctx, dom = await db.prepare(domain, scope="db:read", tool="db_list")
        known = [d["name"] for d in await db._accounts.databases_for(ctx.login, dom.info)]
        creds, created = await db.all_credentials(ctx.login)
        args = {"databases": known, "stored": list(creds.keys()), "stored_credentials": creds, "created": created}
        result = await runner.submit(ctx, dom, "db_list", args, write=False, tool="db_list")
        if "job_id" not in result:
            result["webspace"] = dom.info.webspace
            result["account_page"] = f"{runner.settings.public_base_url}/account"
            result["management_enabled"] = runner.settings.db_management_enabled and "db:admin" in dom.scopes
        return result

    @mcp.tool(description="Tabellen einer Datenbank (ohne table) oder Spalten einer Tabelle (mit table).", annotations=READ_ONLY)
    async def db_schema(domain: str, database: str, table: str | None = None) -> dict[str, Any]:
        ctx, dom = await db.prepare(domain, scope="db:read", tool="db_schema")
        args = await db.db_args(ctx, dom, database, {"table": table})
        return await runner.submit(ctx, dom, "db_schema", args, write=False, tool="db_schema")

    @mcp.tool(
        description=(
            "Führt genau eine Leseabfrage aus (SELECT, SHOW, DESCRIBE, EXPLAIN). Serverseitig in einer READ ONLY "
            "Transaktion, Zeilen auf DB_MAX_ROWS begrenzt (truncated=true), sensible Spalten (Passwörter, Tokens) "
            "werden geschwärzt."
        ),
        annotations=READ_ONLY,
    )
    async def db_query(domain: str, database: str, sql: str) -> dict[str, Any]:
        ctx, dom = await db.prepare(domain, scope="db:read", tool="db_query")
        args = await db.db_args(ctx, dom, database, {"sql": sql})
        return await runner.submit(ctx, dom, "db_query", args, write=False, tool="db_query")

    @mcp.tool(
        description=(
            "Führt genau ein INSERT, UPDATE oder DELETE auf bestehende Tabellen aus (kein DDL). Ohne confirm=true: "
            "Vorschau in einer Transaktion mit ROLLBACK, meldet die betroffene Zeilenzahl. Mit confirm=true: sichert "
            "die betroffenen Tabellen per mysqldump (db_restore) und führt das Statement aus. Abbruch oberhalb von "
            "DB_MAX_AFFECTED_ROWS Zeilen."
        ),
        annotations=DESTRUCTIVE,
    )
    async def db_execute(domain: str, database: str, sql: str, confirm: bool = False) -> dict[str, Any]:
        ctx, dom = await db.prepare(domain, scope="db:write", tool="db_execute")
        args = await db.db_args(ctx, dom, database, {"sql": sql, "confirm": confirm})
        return await runner.submit(ctx, dom, "db_execute", args, write=confirm, tool="db_execute", audit_fields={"database": database, "confirm": confirm})

    @mcp.tool(
        description=(
            "Schemaänderung (DDL): genau ein CREATE TABLE, ALTER TABLE, CREATE INDEX, DROP INDEX oder RENAME TABLE. "
            "Kein DROP TABLE, keine Datenbank-, Benutzer- oder Rechteverwaltung. Ohne confirm=true: Vorschau "
            "(betroffene Tabellen, Spalten vorher). Mit confirm=true: vollständiger Dump der Datenbank (db_restore), "
            "dann die Änderung. Nur mit Recht db:admin; ohne db:admin nur für Datenbanken, die der Dienst selbst "
            "angelegt hat."
        ),
        annotations=DESTRUCTIVE,
    )
    async def db_apply_schema(domain: str, database: str, sql: str, confirm: bool = False) -> dict[str, Any]:
        ctx = await runner.context()
        dom = await runner.domain(ctx, domain, need_scope="db:write", tool="db_apply_schema")
        if "db:admin" not in dom.scopes and await db.service_row(ctx.login, database) is None:
            raise ToolError("Schemaänderungen an dieser Datenbank brauchen das Recht db:admin (nur vom Dienst angelegte Datenbanken gehen ohne).")
        args = await db.db_args(ctx, dom, database, {"sql": sql, "confirm": confirm})
        return await runner.submit(ctx, dom, "db_apply_schema", args, write=confirm, tool="db_apply_schema", audit_fields={"database": database, "confirm": confirm})

    @mcp.tool(
        description=(
            "Ohne dump_id: listet die Datenbank-Dumps (aus db_execute, db_apply_schema, db_drop). Mit dump_id: Vorschau "
            "(Tabellen, Zeitpunkt). Mit confirm=true: spielt den Dump zurück; der aktuelle Stand wird vorher gesichert. "
            "Tabellen-Dumps brauchen db:write, vollständige Dumps db:admin."
        ),
        annotations=DESTRUCTIVE,
    )
    async def db_restore(domain: str, database: str, dump_id: str | None = None, confirm: bool = False) -> dict[str, Any]:
        ctx, dom = await db.prepare(domain, scope="db:write", tool="db_restore")
        extra = {"dump_id": dump_id, "confirm": confirm, "allow_full": "db:admin" in dom.scopes}
        args = await db.db_args(ctx, dom, database, extra)
        return await runner.submit(ctx, dom, "db_restore", args, write=bool(dump_id and confirm), tool="db_restore", audit_fields={"database": database, "dump_id": dump_id})

    @mcp.tool(
        description=(
            "Legt eine neue MariaDB/MySQL-Datenbank mit eigenem Benutzer für das Abo an (über die Plesk-API im "
            "Kundenkontext). Name = Plesk-Präfix des Abos + name_suffix. Die Zugangsdaten werden verschlüsselt beim "
            "Dienst gespeichert und als Datei private/pleskmcp-db/<name>.env im Abo abgelegt (ausserhalb des Webroots); "
            "write_config_path kann zusätzlich eine .env-Datei unterhalb des Document Root schreiben. Zugangsdaten "
            "erscheinen nie in der Antwort. Ohne confirm=true nur Vorschau. Recht db:admin."
        ),
        annotations=WRITE,
    )
    async def db_create(domain: str, name_suffix: str, confirm: bool = False, write_config_path: str | None = None) -> dict[str, Any]:
        ctx, dom = await db.prepare(domain, scope="db:admin", tool="db_create")
        db.management_enabled()
        name = db.db_name_for(dom, name_suffix)
        limit = int(dom.limits.get("max_databases_created", runner.settings.max_databases_created))
        created = await db._store.count_service_databases(ctx.login, dom.info.webspace)
        existing = await db.known_database(ctx, dom, name)
        preview = {
            "database": name,
            "webspace": dom.info.webspace,
            "created_by_service": created,
            "max_databases_created": limit,
            "credentials_file": f"private/pleskmcp-db/{name}.env",
            "config_path": write_config_path,
            "preview": not confirm,
        }
        if existing is not None:
            raise ToolError(f"Die Datenbank {name} existiert bereits.")
        if created >= limit:
            raise ToolError(f"Dieses Abo hat bereits {created} vom Dienst angelegte Datenbanken (Limit {limit}).")
        if not confirm:
            return preview
        auth = await db.customer_auth(ctx)
        user = db.db_user_for(name)
        password = db.random_password()
        runner.audit.write("db_create", login=ctx.login, domain=dom.info.name, database=name, client=ctx.client_id)
        await runner.usage.record(ctx.login, client_id=ctx.client_id, tool="db_create", write=True)
        try:
            db_id = await db._plesk.database_add(auth, dom.info.webspace_id or dom.info.id, name)
        except PleskError as exc:
            runner.audit.write("db_create_failed", login=ctx.login, domain=dom.info.name, database=name, error=str(getattr(exc, "code", "")), client=ctx.client_id)
            raise ToolError(_explain_plesk_error(exc))
        try:
            user_id = await db._plesk.database_add_user(auth, db_id, user, password)
        except PleskError as exc:
            try:
                await db._plesk.database_del(auth, db_id)
            except PleskError:
                logger.warning("could not roll back database %s after add-db-user failed", name)
            runner.audit.write("db_create_failed", login=ctx.login, domain=dom.info.name, database=name, error=str(getattr(exc, "code", "")), client=ctx.client_id)
            raise ToolError(_explain_plesk_error(exc))
        await db._store.save_db_credential(
            ctx.login, name, user, db._accounts.encrypt(password), source="service", webspace=dom.info.webspace, plesk_db_id=db_id, plesk_user_id=user_id
        )
        await db._accounts.forget_databases(ctx.login, dom.info.webspace)
        file_result = await runner.submit(
            ctx, dom, "db_credentials_file", {"database": name, "user": user, "password": password}, write=True, tool="db_create", audit_fields={"database": name}
        )
        result: dict[str, Any] = {
            "database": name,
            "webspace": dom.info.webspace,
            "credentials_file": file_result.get("credentials_file") if isinstance(file_result, dict) else None,
            "credentials_stored": True,
            "preview": False,
            "hint": "Zugangsdaten stehen in der Datei im Abo (private/pleskmcp-db) und beim Dienst; sie werden nie über die Schnittstelle ausgegeben.",
        }
        if write_config_path:
            body = f"DB_HOST=localhost\nDB_NAME={name}\nDB_USER={user}\nDB_PASSWORD={password}\n"
            cfg = await runner.submit(
                ctx,
                dom,
                "write_file",
                {"path": write_config_path, "content": body, "encoding": "text", "create_dirs": True, "backup": True},
                write=True,
                tool="db_create",
                write_bytes=len(body),
                audit_fields={"database": name, "path": write_config_path},
            )
            result["config_written"] = cfg.get("path") if isinstance(cfg, dict) else None
        return result

    @mcp.tool(
        description=(
            "Löscht eine Datenbank, die der Dienst selbst mit db_create angelegt hat (andere Datenbanken werden "
            "abgelehnt). Vorher wird ein vollständiger Dump gesichert; db_create plus db_restore stellt die Datenbank "
            "wieder her. Entfernt Datenbank und Benutzer über die Plesk-API und die gespeicherten Zugangsdaten. "
            "Ohne confirm=true nur Vorschau. Recht db:admin."
        ),
        annotations=DESTRUCTIVE,
    )
    async def db_drop(domain: str, database: str, confirm: bool = False) -> dict[str, Any]:
        ctx, dom = await db.prepare(domain, scope="db:admin", tool="db_drop")
        db.management_enabled()
        row = await db.service_row(ctx.login, database)
        if row is None or row.get("webspace") != dom.info.webspace:
            raise ToolError(f"Die Datenbank {database} wurde nicht vom Dienst für dieses Abo angelegt und wird nicht gelöscht.")
        if not confirm:
            return {"database": database, "webspace": dom.info.webspace, "preview": True, "will_dump": True}
        auth = await db.customer_auth(ctx)
        dump = await runner.submit(ctx, dom, "db_dump", await db.db_args(ctx, dom, database, {"reason": "db_drop"}), write=True, tool="db_drop", audit_fields={"database": database})
        if "job_id" in dump:
            raise ToolError("Die Sicherung läuft noch; bitte db_drop danach erneut aufrufen.")
        runner.audit.write("db_drop", login=ctx.login, domain=dom.info.name, database=database, dump_id=dump.get("dump_id"), client=ctx.client_id)
        await runner.usage.record(ctx.login, client_id=ctx.client_id, tool="db_drop", write=True)
        db_id = row.get("plesk_db_id")
        try:
            if db_id is None:
                known = await db.known_database(ctx, dom, database)
                db_id = known.get("id") if known else None
            if db_id is None:
                raise ToolError("Die Datenbank ist in Plesk nicht mehr vorhanden; die gespeicherten Zugangsdaten werden entfernt.")
            await db._plesk.database_del(auth, int(db_id))
        except PleskError as exc:
            raise ToolError(_explain_plesk_error(exc))
        finally:
            await db._store.delete_db_credential(ctx.login, database)
            await db._accounts.forget_databases(ctx.login, dom.info.webspace)
            await runner.submit(ctx, dom, "db_credentials_remove", {"database": database}, write=True, tool="db_drop", audit_fields={"database": database})
        return {"database": database, "dropped": True, "dump_id": dump.get("dump_id"), "dump_bytes": dump.get("dump_bytes"), "preview": False}
