"""DNS tools: read and change records of the customer's own zones via the Plesk XML API.

The API call runs in the customer's own context (customer_key mode) or with an
administrator key (admin_key mode). In both modes the domain is first checked
against the account's domain list, and in admin mode every record is also
checked to belong to the requested zone. SOA and NS records can be listed but
never changed. Before every change the complete zone is exported to the
subscription's `.pleskmcp/dns/` directory through the helper.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from typing import Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .accounts import AccountService
from .audit import AuditLog
from .config import Settings
from .plesk_api import DnsRecord, DomainInfo, PleskClient, PleskError, PleskResultError, PleskSystemError
from .remote import HelperError, RemoteError, RemoteExecutor
from .tools import DESTRUCTIVE, READ_ONLY, WRITE, ToolRunner

logger = logging.getLogger(__name__)

LOCKED_TYPES = {"SOA", "NS", "AXFR"}
WRITABLE_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "DS"}
NAME_VALUE_TYPES = {"CNAME", "MX", "SRV", "PTR"}
LABEL_RE = re.compile(r"^(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(?:\.(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?))*$")
HOSTNAME_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+\.?$")

RecordType = Literal["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "DS"]


def relative_name(host: str, zone: str) -> str:
    """'www.example.com.' in zone 'example.com' -> 'www'; the zone itself -> '@'."""
    h = host.rstrip(".").lower()
    z = zone.rstrip(".").lower()
    if h == z:
        return "@"
    if h.endswith("." + z):
        return h[: -(len(z) + 1)]
    return host


def fqdn(name: str, zone: str) -> str:
    """'www' or '@' or 'www.example.com' -> 'www.example.com.'"""
    name = name.strip()
    z = zone.rstrip(".").lower()
    if name in ("", "@"):
        return z + "."
    if name.endswith("."):
        candidate = name[:-1]
    elif name.lower() == z or name.lower().endswith("." + z):
        candidate = name
    else:
        candidate = f"{name}.{z}"
    if not LABEL_RE.match(candidate) or len(candidate) > 253:
        raise ToolError(f"Ungültiger Name: {name!r}")
    if not (candidate.lower() == z or candidate.lower().endswith("." + z)):
        raise ToolError(f"Der Name {name!r} liegt nicht in der Zone {zone}.")
    return candidate + "."


def normalize_value(rtype: str, value: str) -> str:
    value = value.strip()
    if not value:
        raise ToolError("value darf nicht leer sein.")
    if rtype == "A":
        try:
            if ipaddress.ip_address(value).version != 4:
                raise ValueError
        except ValueError:
            raise ToolError("Für A-Records muss value eine IPv4-Adresse sein.")
        return value
    if rtype == "AAAA":
        try:
            if ipaddress.ip_address(value).version != 6:
                raise ValueError
        except ValueError:
            raise ToolError("Für AAAA-Records muss value eine IPv6-Adresse sein.")
        return value
    if rtype in NAME_VALUE_TYPES:
        if not HOSTNAME_RE.match(value):
            raise ToolError(f"Für {rtype}-Records muss value ein Hostname sein, z.B. mail.example.com")
        return value.rstrip(".") + "."
    if len(value) > 4096:
        raise ToolError("value ist zu lang.")
    return value


def build_opt(rtype: str, priority: int | None, weight: int | None, port: int | None) -> str:
    if rtype == "MX":
        prio = 10 if priority is None else priority
        if not 0 <= prio <= 65535:
            raise ToolError("priority muss zwischen 0 und 65535 liegen.")
        return str(prio)
    if rtype == "SRV":
        if port is None:
            raise ToolError("Für SRV-Records ist port erforderlich.")
        prio = 0 if priority is None else priority
        wgt = 0 if weight is None else weight
        for label, number in (("priority", prio), ("weight", wgt), ("port", port)):
            if not 0 <= number <= 65535:
                raise ToolError(f"{label} muss zwischen 0 und 65535 liegen.")
        return f"{prio} {wgt} {port}"
    return ""


class DnsRunner:
    def __init__(
        self,
        settings: Settings,
        accounts: AccountService,
        plesk: PleskClient,
        executor: RemoteExecutor,
        audit: AuditLog,
        files: ToolRunner,
    ):
        self._settings = settings
        self._accounts = accounts
        self._plesk = plesk
        self._executor = executor
        self._audit = audit
        self._files = files

    async def zone(self, domain: str, *, write: bool) -> tuple[str, str, DomainInfo, Any]:
        login, client_id, scopes, account = await self._files.context()
        needed = "dns:write" if write else "dns:read"
        if needed not in scopes:
            raise ToolError(f"Für diese Aktion fehlt die Berechtigung {needed}.")
        info = account.find_domain(domain)
        if info is None:
            names = ", ".join(sorted(d.name for d in account.domains if d.kind != "subdomain")) or "keine"
            self._audit.write("domain_rejected", login=login, domain=domain, tool="dns", client=client_id)
            raise ToolError(f"Die Domain '{domain}' gehört nicht zu diesem Konto. Verfügbare Zonen: {names}")
        if info.kind == "subdomain":
            raise ToolError(f"{info.name} ist eine Subdomain ohne eigene Zone. Die Einträge liegen in der Zone von {info.webspace}.")
        if info.id is None:
            raise ToolError("Für diese Domain ist keine Zonen-ID bekannt. Bitte neu verbinden.")
        auth = self._accounts.api_auth_for(login)
        if auth is None:
            raise ToolError("DNS-Tools sind in diesem Betriebsmodus nicht verfügbar (ACCOUNT_CHECK_MODE=login_only).")
        return login, client_id, info, auth

    async def records(self, info: DomainInfo, auth: Any) -> list[DnsRecord]:
        assert info.id is not None
        try:
            records = await self._plesk.dns_get_records(auth, info.id)
        except PleskResultError as exc:
            raise ToolError(f"Plesk verweigert den Zugriff auf die Zone ({exc.code}: {exc.text}).")
        except (PleskSystemError, PleskError) as exc:
            logger.error("dns get_rec failed for %s: %s", info.name, exc)
            raise ToolError("Die DNS-Zone konnte nicht gelesen werden.")
        # Defence in depth (matters in admin_key mode): keep only records of this zone.
        return [r for r in records if r.site_id == info.id]

    async def record(self, info: DomainInfo, auth: Any, record_id: int) -> DnsRecord:
        try:
            record = await self._plesk.dns_get_record(auth, record_id)
        except PleskResultError as exc:
            raise ToolError(f"Eintrag {record_id} nicht zugänglich ({exc.code}).")
        except (PleskSystemError, PleskError) as exc:
            logger.error("dns get_rec %s failed: %s", record_id, exc)
            raise ToolError("Der DNS-Eintrag konnte nicht gelesen werden.")
        if record is None or record.site_id != info.id:
            raise ToolError(f"Eintrag {record_id} gehört nicht zur Zone {info.name}.")
        return record

    async def backup_zone(self, login: str, info: DomainInfo, records: list[DnsRecord]) -> str | None:
        payload = json.dumps(
            {"domain": info.name, "site_id": info.id, "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "records": [r.as_dict() for r in records]},
            ensure_ascii=False,
            indent=1,
        )
        request = {
            "v": 1,
            "op": "store_write",
            "domain": info.name,
            "docroot": info.docroot,
            "limits": {"write_max_bytes": self._settings.write_max_bytes},
            "args": {"category": "dns", "content": payload},
        }
        try:
            result = await self._executor.run(info.sysuser, request)
            return str(result.get("backup"))
        except (HelperError, RemoteError) as exc:
            logger.error("dns zone backup failed for %s: %s", info.name, exc)
            raise ToolError("Die Sicherung der Zone ist fehlgeschlagen, die Änderung wurde nicht ausgeführt.")

    @staticmethod
    def present(record: DnsRecord, zone: str) -> dict[str, Any]:
        item: dict[str, Any] = {
            "id": record.id,
            "type": record.type,
            "name": relative_name(record.host, zone),
            "host": record.host,
            "value": record.value,
            "locked": record.type in LOCKED_TYPES,
        }
        if record.type == "MX":
            item["priority"] = int(record.opt) if record.opt.isdigit() else record.opt
        elif record.type == "SRV":
            parts = record.opt.split()
            if len(parts) == 3 and all(p.isdigit() for p in parts):
                item["priority"], item["weight"], item["port"] = (int(p) for p in parts)
            else:
                item["opt"] = record.opt
        elif record.opt:
            item["opt"] = record.opt
        return item


def register_dns_tools(mcp: MCPServer, runner: DnsRunner) -> None:
    @mcp.tool(
        description=(
            "Listet die DNS-Einträge der Zone einer eigenen Domain (Abonnement oder Addon-Domain). "
            "SOA- und NS-Einträge sind gesperrt (locked=true) und können nicht geändert werden."
        ),
        annotations=READ_ONLY,
    )
    async def dns_list_records(domain: str) -> dict[str, Any]:
        _login, _client, info, auth = await runner.zone(domain, write=False)
        records = await runner.records(info, auth)
        return {"domain": info.name, "records": [runner.present(r, info.name) for r in records]}

    @mcp.tool(
        description=(
            "Legt einen DNS-Eintrag in der Zone einer eigenen Domain an. name ist relativ zur Zone ('@' für die "
            "Domain selbst, 'www' für www.<domain>). Typen: A, AAAA, CNAME, MX (priority), TXT, SRV (priority, "
            "weight, port; name z.B. _sip._tcp), PTR, DS. SOA und NS sind gesperrt. Vor der Änderung wird die "
            "ganze Zone gesichert. Erfordert confirm=true. Die Änderung ist sofort live."
        ),
        annotations=WRITE,
    )
    async def dns_add_record(
        domain: str,
        type: RecordType,
        name: str,
        value: str,
        priority: int | None = None,
        weight: int | None = None,
        port: int | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        rtype = type.upper()
        if rtype in LOCKED_TYPES or rtype not in WRITABLE_TYPES:
            raise ToolError(f"Einträge vom Typ {rtype} können über diesen Dienst nicht angelegt werden.")
        login, client_id, info, auth = await runner.zone(domain, write=True)
        host = fqdn(name, info.name)
        val = normalize_value(rtype, value)
        opt = build_opt(rtype, priority, weight, port)
        if not confirm:
            return {"preview": True, "domain": info.name, "type": rtype, "host": host, "value": val, "opt": opt, "hint": "confirm=true setzt die Änderung um"}
        records = await runner.records(info, auth)
        for existing in records:
            if existing.type == "CNAME" and existing.host.lower() == host.lower():
                raise ToolError(f"Für {host} existiert bereits ein CNAME (id {existing.id}).")
            if rtype == "CNAME" and existing.host.lower() == host.lower():
                raise ToolError(f"Ein CNAME für {host} ist nicht möglich, es existiert bereits ein {existing.type}-Eintrag (id {existing.id}).")
        backup = await runner.backup_zone(login, info, records)
        try:
            new_id = await runner._plesk.dns_add_record(auth, info.id or 0, rtype, host, val, opt)
        except PleskResultError as exc:
            raise ToolError(f"Plesk hat den Eintrag abgelehnt ({exc.code}: {exc.text}).")
        except (PleskSystemError, PleskError) as exc:
            logger.error("dns add_rec failed for %s: %s", info.name, exc)
            raise ToolError("Der Eintrag konnte nicht angelegt werden.")
        runner._audit.write("dns_add", login=login, domain=info.name, type=rtype, host=host, record_id=new_id, backup=backup, client=client_id)
        return {"domain": info.name, "id": new_id, "type": rtype, "host": host, "value": val, "opt": opt, "backup": backup}

    @mcp.tool(
        description=(
            "Löscht einen DNS-Eintrag (per id aus dns_list_records) aus der Zone einer eigenen Domain. SOA und NS "
            "sind gesperrt. Vor der Änderung wird die ganze Zone gesichert. Erfordert confirm=true."
        ),
        annotations=DESTRUCTIVE,
    )
    async def dns_delete_record(domain: str, record_id: int, confirm: bool = False) -> dict[str, Any]:
        login, client_id, info, auth = await runner.zone(domain, write=True)
        record = await runner.record(info, auth, record_id)
        if record.type in LOCKED_TYPES:
            raise ToolError(f"{record.type}-Einträge sind gesperrt und können nicht gelöscht werden.")
        if not confirm:
            return {"preview": True, "domain": info.name, "record": runner.present(record, info.name), "hint": "confirm=true löscht den Eintrag"}
        records = await runner.records(info, auth)
        backup = await runner.backup_zone(login, info, records)
        try:
            await runner._plesk.dns_del_record(auth, record.id)
        except PleskResultError as exc:
            raise ToolError(f"Plesk hat das Löschen abgelehnt ({exc.code}: {exc.text}).")
        except (PleskSystemError, PleskError) as exc:
            logger.error("dns del_rec failed for %s: %s", info.name, exc)
            raise ToolError("Der Eintrag konnte nicht gelöscht werden.")
        runner._audit.write("dns_delete", login=login, domain=info.name, type=record.type, host=record.host, record_id=record.id, backup=backup, client=client_id)
        return {"domain": info.name, "deleted": runner.present(record, info.name), "backup": backup}

    @mcp.tool(
        description=(
            "Ändert den Wert (und bei MX/SRV die Priorität, Gewicht, Port) eines bestehenden DNS-Eintrags. Plesk "
            "kennt kein direktes Ändern, darum wird der alte Eintrag gelöscht und mit gleichem Typ und Namen neu "
            "angelegt (neue id). SOA und NS sind gesperrt. Vor der Änderung wird die ganze Zone gesichert. "
            "Erfordert confirm=true."
        ),
        annotations=DESTRUCTIVE,
    )
    async def dns_update_record(
        domain: str,
        record_id: int,
        value: str,
        priority: int | None = None,
        weight: int | None = None,
        port: int | None = None,
        confirm: bool = False,
    ) -> dict[str, Any]:
        login, client_id, info, auth = await runner.zone(domain, write=True)
        record = await runner.record(info, auth, record_id)
        if record.type in LOCKED_TYPES or record.type not in WRITABLE_TYPES:
            raise ToolError(f"{record.type}-Einträge können über diesen Dienst nicht geändert werden.")
        val = normalize_value(record.type, value)
        if record.type == "SRV":
            parts = record.opt.split()
            old_prio, old_weight, old_port = (int(p) for p in parts) if len(parts) == 3 and all(p.isdigit() for p in parts) else (0, 0, None)
            opt = build_opt("SRV", old_prio if priority is None else priority, old_weight if weight is None else weight, old_port if port is None else port)
        elif record.type == "MX":
            old_prio = int(record.opt) if record.opt.isdigit() else 10
            opt = build_opt("MX", old_prio if priority is None else priority, None, None)
        else:
            opt = ""
        if not confirm:
            return {"preview": True, "domain": info.name, "old": runner.present(record, info.name), "new": {"type": record.type, "host": record.host, "value": val, "opt": opt}, "hint": "confirm=true setzt die Änderung um"}
        records = await runner.records(info, auth)
        backup = await runner.backup_zone(login, info, records)
        try:
            await runner._plesk.dns_del_record(auth, record.id)
        except (PleskResultError, PleskSystemError, PleskError) as exc:
            logger.error("dns update: delete failed for %s: %s", info.name, exc)
            raise ToolError("Der alte Eintrag konnte nicht entfernt werden, nichts wurde geändert.")
        try:
            new_id = await runner._plesk.dns_add_record(auth, info.id or 0, record.type, record.host, val, opt)
        except (PleskResultError, PleskSystemError, PleskError) as exc:
            logger.error("dns update: add failed for %s after delete: %s", info.name, exc)
            runner._audit.write("dns_update_failed", login=login, domain=info.name, type=record.type, host=record.host, record_id=record.id, backup=backup, client=client_id)
            raise ToolError(
                f"Der alte Eintrag wurde entfernt, der neue konnte nicht angelegt werden. Alter Eintrag: {record.type} {record.host} "
                f"{record.value} opt={record.opt!r}. Bitte mit dns_add_record neu anlegen. Zonen-Sicherung: {backup}"
            )
        runner._audit.write("dns_update", login=login, domain=info.name, type=record.type, host=record.host, record_id=record.id, new_record_id=new_id, backup=backup, client=client_id)
        return {"domain": info.name, "old_id": record.id, "id": new_id, "type": record.type, "host": record.host, "value": val, "opt": opt, "backup": backup}
