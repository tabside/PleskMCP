"""DNS tools: read, change and restore records of the customer's own zones via the Plesk XML API.

API calls run in the customer's own context (customer_key mode) or with an
administrator key (admin_key mode, every record is additionally checked to
belong to the requested zone). SOA and NS records can be listed but never
changed. Before every change the complete zone is exported through the
helper into the subscription's store; `dns_restore_zone` brings a zone back
to such an export.
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

from .plesk_api import DnsRecord, PleskClient, PleskError, PleskResultError, PleskSystemError
from .tools import DESTRUCTIVE, READ_ONLY, WRITE, CallContext, DomainContext, ToolRunner

logger = logging.getLogger(__name__)

LOCKED_TYPES = {"SOA", "NS", "AXFR"}
WRITABLE_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "DS"}
NAME_VALUE_TYPES = {"CNAME", "MX", "SRV", "PTR"}
LABEL_RE = re.compile(r"^(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)(?:\.(?:[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?))*$")
HOSTNAME_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))+\.?$")

RecordType = Literal["A", "AAAA", "CNAME", "MX", "TXT", "SRV", "PTR", "DS"]


def relative_name(host: str, zone: str) -> str:
    h = host.rstrip(".").lower()
    z = zone.rstrip(".").lower()
    if h == z:
        return "@"
    if h.endswith("." + z):
        return h[: -(len(z) + 1)]
    return host


def fqdn(name: str, zone: str) -> str:
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


def record_key(r: dict[str, Any]) -> tuple[str, str, str, str]:
    return (str(r.get("type", "")).upper(), str(r.get("host", "")).lower(), str(r.get("value", "")), str(r.get("opt", "") or ""))


class DnsRunner:
    def __init__(self, runner: ToolRunner, plesk: PleskClient):
        self._runner = runner
        self._plesk = plesk

    async def zone(self, domain: str, *, write: bool, tool: str) -> tuple[CallContext, DomainContext, Any]:
        ctx = await self._runner.context()
        dom = await self._runner.domain(ctx, domain, need_scope="dns:write" if write else "dns:read", tool=tool)
        info = dom.info
        if info.kind == "subdomain":
            raise ToolError(f"{info.name} ist eine Subdomain ohne eigene Zone. Die Einträge liegen in der Zone von {info.webspace}.")
        if info.id is None:
            raise ToolError("Für diese Domain ist keine Zonen-ID bekannt. Bitte neu verbinden.")
        auth = await self._runner.accounts.api_auth_for(ctx.login)
        if auth is None:
            raise ToolError("DNS-Tools sind in diesem Betriebsmodus nicht verfügbar (ACCOUNT_CHECK_MODE=login_only).")
        return ctx, dom, auth

    async def records(self, dom: DomainContext, auth: Any) -> list[DnsRecord]:
        assert dom.info.id is not None
        try:
            records = await self._plesk.dns_get_records(auth, dom.info.id)
        except PleskResultError as exc:
            raise ToolError(f"Plesk verweigert den Zugriff auf die Zone ({exc.code}: {exc.text}).")
        except (PleskSystemError, PleskError) as exc:
            logger.error("dns get_rec failed for %s: %s", dom.info.name, exc)
            raise ToolError("Die DNS-Zone konnte nicht gelesen werden.")
        return [r for r in records if r.site_id == dom.info.id]

    async def record(self, dom: DomainContext, auth: Any, record_id: int) -> DnsRecord:
        try:
            record = await self._plesk.dns_get_record(auth, record_id)
        except PleskResultError as exc:
            raise ToolError(f"Eintrag {record_id} nicht zugänglich ({exc.code}).")
        except (PleskSystemError, PleskError) as exc:
            logger.error("dns get_rec %s failed: %s", record_id, exc)
            raise ToolError("Der DNS-Eintrag konnte nicht gelesen werden.")
        if record is None or record.site_id != dom.info.id:
            raise ToolError(f"Eintrag {record_id} gehört nicht zur Zone {dom.info.name}.")
        return record

    async def export_zone(self, ctx: CallContext, dom: DomainContext, records: list[DnsRecord], tool: str) -> str | None:
        payload = json.dumps(
            {"domain": dom.info.name, "site_id": dom.info.id, "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "records": [r.as_dict() for r in records]},
            ensure_ascii=False,
            indent=1,
        )
        result = await self._runner.submit(ctx, dom, "store_write", {"category": "dns", "content": payload}, write=True, tool=tool, audit_fields={"category": "dns"}, long_running=False)
        if "job_id" in result:
            raise ToolError("Die Sicherung der Zone dauert zu lange, die Änderung wurde nicht ausgeführt. Bitte erneut versuchen.")
        return str(result.get("id") or result.get("backup"))

    @staticmethod
    def present(record: DnsRecord, zone: str) -> dict[str, Any]:
        item: dict[str, Any] = {"id": record.id, "type": record.type, "name": relative_name(record.host, zone), "host": record.host, "value": record.value, "locked": record.type in LOCKED_TYPES}
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

    async def add(self, dom: DomainContext, auth: Any, rtype: str, host: str, value: str, opt: str) -> int:
        try:
            return await self._plesk.dns_add_record(auth, dom.info.id or 0, rtype, host, value, opt)
        except PleskResultError as exc:
            raise ToolError(f"Plesk hat den Eintrag abgelehnt ({exc.code}: {exc.text}).")
        except (PleskSystemError, PleskError) as exc:
            logger.error("dns add_rec failed for %s: %s", dom.info.name, exc)
            raise ToolError("Der Eintrag konnte nicht angelegt werden.")

    async def delete(self, dom: DomainContext, auth: Any, record_id: int) -> None:
        try:
            await self._plesk.dns_del_record(auth, record_id)
        except PleskResultError as exc:
            raise ToolError(f"Plesk hat das Löschen abgelehnt ({exc.code}: {exc.text}).")
        except (PleskSystemError, PleskError) as exc:
            logger.error("dns del_rec failed for %s: %s", dom.info.name, exc)
            raise ToolError("Der Eintrag konnte nicht gelöscht werden.")


def register_dns_tools(mcp: MCPServer, dns: DnsRunner) -> None:
    runner = dns._runner

    @mcp.tool(
        description="Listet die DNS-Einträge der Zone einer eigenen Domain (Abonnement oder Addon-Domain). SOA- und NS-Einträge sind gesperrt (locked=true).",
        annotations=READ_ONLY,
    )
    async def dns_list_records(domain: str) -> dict[str, Any]:
        _ctx, dom, auth = await dns.zone(domain, write=False, tool="dns_list_records")
        records = await dns.records(dom, auth)
        return {"domain": dom.info.name, "records": [dns.present(r, dom.info.name) for r in records]}

    @mcp.tool(
        description=(
            "Legt einen DNS-Eintrag in der Zone einer eigenen Domain an. name ist relativ zur Zone ('@' für die Domain "
            "selbst, 'www' für www.<domain>). Typen: A, AAAA, CNAME, MX (priority), TXT, SRV (priority, weight, port; "
            "name z.B. _sip._tcp), PTR, DS. SOA und NS sind gesperrt. Vor der Änderung wird die ganze Zone gesichert. "
            "Erfordert confirm=true. Die Änderung ist sofort live."
        ),
        annotations=WRITE,
    )
    async def dns_add_record(domain: str, type: RecordType, name: str, value: str, priority: int | None = None, weight: int | None = None, port: int | None = None, confirm: bool = False) -> dict[str, Any]:
        rtype = type.upper()
        if rtype in LOCKED_TYPES or rtype not in WRITABLE_TYPES:
            raise ToolError(f"Einträge vom Typ {rtype} können über diesen Dienst nicht angelegt werden.")
        ctx, dom, auth = await dns.zone(domain, write=True, tool="dns_add_record")
        host = fqdn(name, dom.info.name)
        val = normalize_value(rtype, value)
        opt = build_opt(rtype, priority, weight, port)
        if not confirm:
            return {"preview": True, "domain": dom.info.name, "type": rtype, "host": host, "value": val, "opt": opt, "hint": "confirm=true setzt die Änderung um"}
        records = await dns.records(dom, auth)
        for existing in records:
            if existing.type == "CNAME" and existing.host.lower() == host.lower():
                raise ToolError(f"Für {host} existiert bereits ein CNAME (id {existing.id}).")
            if rtype == "CNAME" and existing.host.lower() == host.lower():
                raise ToolError(f"Ein CNAME für {host} ist nicht möglich, es existiert bereits ein {existing.type}-Eintrag (id {existing.id}).")
        backup = await dns.export_zone(ctx, dom, records, "dns_add_record")
        new_id = await dns.add(dom, auth, rtype, host, val, opt)
        runner.audit.write("dns_add", login=ctx.login, domain=dom.info.name, type=rtype, host=host, record_id=new_id, backup=backup, client=ctx.client_id)
        return {"domain": dom.info.name, "id": new_id, "type": rtype, "host": host, "value": val, "opt": opt, "backup": backup}

    @mcp.tool(
        description="Löscht einen DNS-Eintrag (per id aus dns_list_records) aus der Zone einer eigenen Domain. SOA und NS sind gesperrt. Vor der Änderung wird die ganze Zone gesichert. Erfordert confirm=true.",
        annotations=DESTRUCTIVE,
    )
    async def dns_delete_record(domain: str, record_id: int, confirm: bool = False) -> dict[str, Any]:
        ctx, dom, auth = await dns.zone(domain, write=True, tool="dns_delete_record")
        record = await dns.record(dom, auth, record_id)
        if record.type in LOCKED_TYPES:
            raise ToolError(f"{record.type}-Einträge sind gesperrt und können nicht gelöscht werden.")
        if not confirm:
            return {"preview": True, "domain": dom.info.name, "record": dns.present(record, dom.info.name), "hint": "confirm=true löscht den Eintrag"}
        records = await dns.records(dom, auth)
        backup = await dns.export_zone(ctx, dom, records, "dns_delete_record")
        await dns.delete(dom, auth, record.id)
        runner.audit.write("dns_delete", login=ctx.login, domain=dom.info.name, type=record.type, host=record.host, record_id=record.id, backup=backup, client=ctx.client_id)
        return {"domain": dom.info.name, "deleted": dns.present(record, dom.info.name), "backup": backup}

    @mcp.tool(
        description=(
            "Ändert den Wert (und bei MX/SRV Priorität, Gewicht, Port) eines bestehenden DNS-Eintrags. Plesk kennt kein "
            "direktes Ändern, darum wird der alte Eintrag gelöscht und mit gleichem Typ und Namen neu angelegt (neue id). "
            "SOA und NS sind gesperrt. Vor der Änderung wird die ganze Zone gesichert. Erfordert confirm=true."
        ),
        annotations=DESTRUCTIVE,
    )
    async def dns_update_record(domain: str, record_id: int, value: str, priority: int | None = None, weight: int | None = None, port: int | None = None, confirm: bool = False) -> dict[str, Any]:
        ctx, dom, auth = await dns.zone(domain, write=True, tool="dns_update_record")
        record = await dns.record(dom, auth, record_id)
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
            return {"preview": True, "domain": dom.info.name, "old": dns.present(record, dom.info.name), "new": {"type": record.type, "host": record.host, "value": val, "opt": opt}, "hint": "confirm=true setzt die Änderung um"}
        records = await dns.records(dom, auth)
        backup = await dns.export_zone(ctx, dom, records, "dns_update_record")
        await dns.delete(dom, auth, record.id)
        try:
            new_id = await dns.add(dom, auth, record.type, record.host, val, opt)
        except ToolError as exc:
            runner.audit.write("dns_update_failed", login=ctx.login, domain=dom.info.name, type=record.type, host=record.host, record_id=record.id, backup=backup, client=ctx.client_id)
            raise ToolError(
                f"Der alte Eintrag wurde entfernt, der neue konnte nicht angelegt werden ({exc}). Alter Eintrag: {record.type} {record.host} "
                f"{record.value} opt={record.opt!r}. Bitte mit dns_add_record neu anlegen oder die Zone mit dns_restore_zone zurücksetzen (Export {backup})."
            )
        runner.audit.write("dns_update", login=ctx.login, domain=dom.info.name, type=record.type, host=record.host, record_id=record.id, new_record_id=new_id, backup=backup, client=ctx.client_id)
        return {"domain": dom.info.name, "old_id": record.id, "id": new_id, "type": record.type, "host": record.host, "value": val, "opt": opt, "backup": backup}

    @mcp.tool(
        description=(
            "Setzt die Zone einer eigenen Domain auf einen früheren Export zurück. Ohne export_id: listet die Exporte. "
            "Mit export_id: Vorschau der Unterschiede (zu löschende und anzulegende Einträge). Mit confirm=true: führt die "
            "Änderungen aus; SOA und NS bleiben unangetastet, der aktuelle Stand wird vorher exportiert."
        ),
        annotations=DESTRUCTIVE,
    )
    async def dns_restore_zone(domain: str, export_id: str | None = None, confirm: bool = False) -> dict[str, Any]:
        ctx, dom, auth = await dns.zone(domain, write=True, tool="dns_restore_zone")
        if not export_id:
            listing = await runner.submit(ctx, dom, "store_list", {"category": "dns"}, write=False, tool="dns_restore_zone")
            return {"domain": dom.info.name, "exports": listing.get("entries", [])}
        stored = await runner.submit(ctx, dom, "store_read", {"category": "dns", "id": export_id}, write=False, tool="dns_restore_zone")
        try:
            export = json.loads(stored.get("content") or "{}")
        except ValueError:
            raise ToolError("Der Export ist nicht lesbar.")
        if export.get("domain") != dom.info.name:
            raise ToolError("Der Export gehört zu einer anderen Domain.")
        wanted = [r for r in export.get("records", []) if str(r.get("type", "")).upper() not in LOCKED_TYPES]
        current = [r for r in await dns.records(dom, auth) if r.type not in LOCKED_TYPES]
        current_keys = {record_key(r.as_dict()): r for r in current}
        wanted_keys = {record_key(r): r for r in wanted}
        to_delete = [r for k, r in current_keys.items() if k not in wanted_keys]
        to_add = [r for k, r in wanted_keys.items() if k not in current_keys]
        preview = {
            "domain": dom.info.name,
            "export_id": export_id,
            "exported_at": export.get("exported_at"),
            "delete": [dns.present(r, dom.info.name) for r in to_delete],
            "add": [{"type": r.get("type"), "host": r.get("host"), "value": r.get("value"), "opt": r.get("opt", "")} for r in to_add],
            "unchanged": len(wanted_keys) - len(to_add),
        }
        if not confirm:
            preview["preview"] = True
            preview["hint"] = "confirm=true setzt die Zone auf diesen Export zurück"
            return preview
        all_current = await dns.records(dom, auth)
        backup = await dns.export_zone(ctx, dom, all_current, "dns_restore_zone")
        deleted = 0
        added = 0
        errors: list[str] = []
        for r in to_delete:
            try:
                await dns.delete(dom, auth, r.id)
                deleted += 1
            except ToolError as exc:
                errors.append(f"delete {r.type} {r.host}: {exc}")
        for r in to_add:
            try:
                await dns.add(dom, auth, str(r.get("type")).upper(), str(r.get("host")), str(r.get("value")), str(r.get("opt") or ""))
                added += 1
            except ToolError as exc:
                errors.append(f"add {r.get('type')} {r.get('host')}: {exc}")
        runner.audit.write("dns_restore", login=ctx.login, domain=dom.info.name, export_id=export_id, deleted=deleted, added=added, errors=len(errors), backup=backup, client=ctx.client_id)
        preview.update({"preview": False, "deleted": deleted, "added": added, "errors": errors, "backup": backup})
        return preview
