"""SSL tools: show the certificate a domain currently serves and issue Let's Encrypt certificates.

`ssl_status` (files:read) connects to the domain on port 443 and reads the
certificate it presents: issuer, names, validity, whether it is trusted and
whether it covers the domain (and www). Nothing on the server changes.

`ssl_issue` (ssl:write) asks Plesk to issue a Let's Encrypt certificate for the
customer's own domain, optionally including www. The names are derived from
the domain the account owns, never taken from the client. Plesk has no
customer-context API for Let's Encrypt, so the call goes through the REST CLI
gateway (`extension --exec letsencrypt cli.php -d ... -m ...`) with a
dedicated administrator key (PLESK_SSL_API_KEY). The key is used for this one
call only; the parameters are built here and validated. The feature is off
unless SSL_ISSUE_ENABLED=true.

Guards before a certificate is requested:
- every name resolves, only to public addresses, and (if SSL_EXPECTED_IPS or
  the signup IP is known) only to those addresses;
- a trusted certificate covering all names with more than SSL_RENEW_DAYS left
  is not replaced (Plesk renews Let's Encrypt certificates itself);
- one attempt per domain per SSL_ISSUE_COOLDOWN seconds (Let's Encrypt rate
  limits), plus the usual per-login write limits;
- preview without confirm=true.

The status probe only ever connects to the customer's own domain, and only to
public addresses: a customer controls the DNS of their domain and could
otherwise point it at internal hosts of the service's network.
"""

from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import logging
import re
import socket
import ssl
from typing import Any

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from .auth.ratelimit import RateLimited
from .signup.clients import ExternalError, PleskRestClient
from .tools import READ_ONLY, WRITE, CallContext, DomainContext, ToolRunner

logger = logging.getLogger(__name__)

HOST_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
PROBE_TIMEOUT = 10.0


# ------------------------------------------------------------------ resolving
def is_public(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


async def resolve_host(host: str) -> list[str]:
    """A and AAAA addresses of host; empty when the name does not resolve."""
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(loop.getaddrinfo(host, 443, type=socket.SOCK_STREAM), timeout=PROBE_TIMEOUT)
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        return []
    seen: list[str] = []
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen.append(addr)
    return seen


# --------------------------------------------------------------------- probing
def _names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
    except x509.ExtensionNotFound:
        names = []
    if not names:
        names = [a.value.lower() for a in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) if isinstance(a.value, str)]
    return names


def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else None


def covers(names: list[str], host: str) -> bool:
    host = host.lower()
    for n in names:
        if n == host:
            return True
        if n.startswith("*.") and host.count(".") == n.count(".") and host.endswith(n[1:]):
            return True
    return False


def describe_certificate(der: bytes, now: dt.datetime | None = None) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    now = now or dt.datetime.now(dt.timezone.utc)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    issuer_org = _attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _attr(cert.issuer, NameOID.COMMON_NAME)
    return {
        "names": _names(cert),
        "issuer": issuer_org or issuer_cn,
        "issuer_cn": issuer_cn,
        "lets_encrypt": (issuer_org or "").lower().startswith("let's encrypt"),
        "self_signed": cert.issuer == cert.subject,
        "valid_from": not_before.isoformat(),
        "valid_until": not_after.isoformat(),
        "days_left": int((not_after - now).total_seconds() // 86400),
        "expired": not_after <= now,
    }


async def _handshake(address: str, host: str, context: ssl.SSLContext) -> bytes:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(address, 443, ssl=context, server_hostname=host), timeout=PROBE_TIMEOUT)
    try:
        obj = writer.get_extra_info("ssl_object")
        der = obj.getpeercert(binary_form=True) if obj is not None else None
        if not der:
            raise ssl.SSLError("no certificate")
        return der
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001
            pass


async def probe_certificate(host: str, address: str) -> dict[str, Any]:
    """Certificate served for host (SNI) at address:443, plus whether a default client would trust it."""
    raw = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    raw.check_hostname = False
    raw.verify_mode = ssl.CERT_NONE
    try:
        der = await _handshake(address, host, raw)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        return {"reachable": False, "error": exc.__class__.__name__}
    result: dict[str, Any] = {"reachable": True, **describe_certificate(der)}
    try:
        await _handshake(address, host, ssl.create_default_context())
        result["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        result["trusted"] = False
        result["trust_error"] = (exc.verify_message or "verification failed")[:200]
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        result["trusted"] = False
        result["trust_error"] = exc.__class__.__name__
    return result


# ---------------------------------------------------------------------- runner
class CertRunner:
    def __init__(self, runner: ToolRunner, *, transport: Any | None = None):
        self._runner = runner
        self._transport = transport
        self._rest: PleskRestClient | None = None

    @property
    def runner(self) -> ToolRunner:
        return self._runner

    def rest(self) -> PleskRestClient:
        s = self._runner.settings
        if self._rest is None:
            self._rest = PleskRestClient(s.plesk_url, s.ssl_api_key or "", verify_ssl=s.plesk_verify_ssl, timeout=s.ssl_issue_timeout, transport=self._transport)
        return self._rest

    async def aclose(self) -> None:
        if self._rest is not None:
            await self._rest.aclose()

    async def prepare(self, domain: str, *, scope: str, tool: str) -> tuple[CallContext, DomainContext]:
        ctx = await self._runner.context()
        dom = await self._runner.domain(ctx, domain, need_scope=scope, tool=tool)
        name = dom.info.name.lower().rstrip(".")
        if not HOST_RE.match(name):
            raise ToolError(f"Für den Domainnamen {dom.info.name!r} kann kein Zertifikat geprüft oder ausgestellt werden.")
        return ctx, dom

    @staticmethod
    def candidate_names(dom: DomainContext) -> tuple[str, str | None]:
        name = dom.info.name.lower().rstrip(".")
        www = None if dom.info.kind == "subdomain" or name.startswith("www.") else f"www.{name}"
        return name, www

    async def check_name(self, host: str) -> dict[str, Any]:
        addresses = await resolve_host(host)
        expected = set(self._runner.settings.ssl_expected_ips)
        public = [a for a in addresses if is_public(a)]
        entry: dict[str, Any] = {"name": host, "addresses": addresses, "resolves": bool(addresses)}
        problems = []
        if not addresses:
            problems.append("löst nicht auf")
        elif len(public) != len(addresses):
            problems.append("zeigt auf nicht öffentliche Adressen")
        elif expected and not set(addresses) <= expected:
            problems.append("zeigt nicht (nur) auf diesen Server")
        entry["ok"] = not problems
        if problems:
            entry["problem"] = ", ".join(problems)
        return entry

    async def status_for(self, host: str, addresses: list[str]) -> dict[str, Any]:
        public = [a for a in addresses if is_public(a)]
        if not public:
            return {"reachable": False, "error": "no_public_address"}
        return await probe_certificate(host, public[0])


def _summary(status: dict[str, Any], names: list[str]) -> str:
    if not status.get("reachable"):
        return "Über HTTPS nicht erreichbar."
    missing = [n for n in names if not covers(status.get("names", []), n)]
    if status.get("expired"):
        return f"Zertifikat abgelaufen am {status['valid_until'][:10]}."
    if missing:
        return "Zertifikat deckt " + ", ".join(missing) + " nicht ab."
    if not status.get("trusted"):
        return f"Zertifikat wird von Browsern nicht akzeptiert ({status.get('trust_error', 'unbekannt')})."
    return f"Gültiges Zertifikat von {status.get('issuer')}, noch {status.get('days_left')} Tage."


def register_cert_tools(mcp: MCPServer, certs: CertRunner) -> None:
    runner = certs.runner

    @mcp.tool(
        description=(
            "Zeigt das SSL-Zertifikat, das eine eigene Domain (und www) aktuell ausliefert: Aussteller, abgedeckte "
            "Namen, Gültigkeit, ob Browser es akzeptieren, und ob die Namen per DNS auf diesen Server zeigen. "
            "Ändert nichts."
        ),
        annotations=READ_ONLY,
    )
    async def ssl_status(domain: str) -> dict[str, Any]:
        settings = runner.settings
        ctx, dom = await certs.prepare(domain, scope="files:read", tool="ssl_status")
        try:
            await runner.limiter.take_tool_call(ctx.login, write=False, write_bytes=0, limits=dom.profile.limits(settings.profile_defaults))
        except RateLimited as exc:
            raise ToolError(f"Limit erreicht ({exc.scope}). Bitte in {exc.retry_after} Sekunden erneut versuchen.")
        name, www = certs.candidate_names(dom)
        hosts = [name] + ([www] if www else [])
        dns = [await certs.check_name(h) for h in hosts]
        result: dict[str, Any] = {"domain": name, "dns": dns, "certificates": []}
        for entry in dns:
            if not entry["resolves"]:
                continue
            status = await certs.status_for(entry["name"], entry["addresses"])
            status["host"] = entry["name"]
            status["summary"] = _summary(status, [entry["name"]])
            result["certificates"].append(status)
        result["issue_available"] = settings.ssl_issue_enabled and "ssl:write" in dom.scopes
        return result

    @mcp.tool(
        description=(
            "Stellt über Plesk ein kostenloses Let's-Encrypt-Zertifikat für eine eigene Domain aus, standardmässig "
            "inklusive www, sofern www per DNS auf diesen Server zeigt (include_www=false lässt es weg). Plesk "
            "verlängert das Zertifikat danach selbst. Ohne confirm=true nur Vorschau: geprüfte Namen, DNS, aktuelles "
            "Zertifikat. Ein noch lange gültiges Zertifikat wird nicht ersetzt; pro Domain ist höchstens ein Versuch "
            "pro Stunde möglich."
        ),
        annotations=WRITE,
    )
    async def ssl_issue(domain: str, include_www: bool | None = None, confirm: bool = False) -> dict[str, Any]:
        settings = runner.settings
        if not settings.ssl_issue_enabled:
            raise ToolError("Das Ausstellen von Zertifikaten über den KI-Zugang ist auf diesem Server nicht eingeschaltet. Bitte den Hoster fragen.")
        ctx, dom = await certs.prepare(domain, scope="ssl:write", tool="ssl_issue")
        name, www = certs.candidate_names(dom)
        if include_www and www is None:
            raise ToolError(f"Für {name} gibt es keine www-Variante.")
        main = await certs.check_name(name)
        www_entry = await certs.check_name(www) if www else None
        names = [name]
        notes: list[str] = []
        if www_entry is not None:
            if include_www is None:
                if www_entry["ok"]:
                    names.append(www)
                else:
                    notes.append(f"{www} wird weggelassen: {www_entry.get('problem')}.")
            elif include_www:
                names.append(www)
        checks = [main] + ([www_entry] if www_entry and www in names else [])
        blocking = [c for c in checks if not c["ok"]]
        current = await certs.status_for(name, main["addresses"]) if main["resolves"] else {"reachable": False}
        still_valid = bool(
            current.get("reachable")
            and current.get("trusted")
            and not current.get("expired")
            and all(covers(current.get("names", []), n) for n in names)
            and int(current.get("days_left", 0)) > settings.ssl_renew_days
        )
        preview = {
            "preview": True,
            "domain": name,
            "names": names,
            "dns": checks,
            "current": {k: current.get(k) for k in ("reachable", "issuer", "names", "valid_until", "days_left", "trusted")},
            "notes": notes,
        }
        if blocking:
            preview["blocked"] = "; ".join(f"{c['name']}: {c['problem']}" for c in blocking)
        elif still_valid:
            preview["blocked"] = f"Es gibt bereits ein gültiges Zertifikat für {', '.join(names)} (noch {current.get('days_left')} Tage). Plesk verlängert es selbst."
        if not confirm or "blocked" in preview:
            if "blocked" in preview and confirm:
                raise ToolError(f"Kein Zertifikat ausgestellt. {preview['blocked']}")
            return preview

        email = settings.ssl_contact_email or ""
        if not EMAIL_RE.match(email):
            raise ToolError("Für Let's Encrypt ist keine Kontaktadresse konfiguriert. Bitte den Hoster informieren.")
        try:
            await runner.limiter.take_tool_call(ctx.login, write=True, write_bytes=0, limits=dom.profile.limits(settings.profile_defaults))
        except RateLimited as exc:
            raise ToolError(f"Limit erreicht ({exc.scope}). Bitte in {exc.retry_after} Sekunden erneut versuchen.")
        cooldown_key = f"pleskmcp:ssl:cooldown:{name}"
        if not await runner.redis.set(cooldown_key, ctx.login, nx=True, ex=max(1, settings.ssl_issue_cooldown)):
            ttl = await runner.redis.ttl(cooldown_key)
            raise ToolError(f"Für {name} wurde kürzlich schon ein Zertifikat angefordert. Bitte in {max(ttl, 1)} Sekunden erneut versuchen.")

        params = ["--exec", "letsencrypt", "cli.php"]
        for n in names:
            params += ["-d", n]
        params += ["-m", email]
        runner.audit.write("tool_write", login=ctx.login, domain=name, tool="ssl_issue", client=ctx.client_id, names=names)
        await runner.usage.record(ctx.login, client_id=ctx.client_id, tool="ssl_issue", write=True)
        try:
            await certs.rest().cli("extension", params)
        except ExternalError as exc:
            runner.audit.write("tool_write_failed", login=ctx.login, domain=name, tool="ssl_issue", error=exc.code, client=ctx.client_id)
            logger.warning("letsencrypt for %s failed: %s %s", name, exc.code, exc.detail)
            detail = (exc.detail or "").strip().splitlines()
            hint = f" Meldung: {detail[-1][:200]}" if detail else ""
            raise ToolError(
                f"Let's Encrypt konnte für {', '.join(names)} kein Zertifikat ausstellen [{exc.code}].{hint} "
                "Häufige Ursachen: DNS zeigt noch nicht auf den Server, oder eine .htaccess-Regel blockiert /.well-known/acme-challenge/."
            )
        after = await certs.status_for(name, main["addresses"])
        return {
            "issued": True,
            "domain": name,
            "names": names,
            "notes": notes,
            "certificate": {k: after.get(k) for k in ("reachable", "issuer", "names", "valid_until", "days_left", "trusted")},
            "hint": "Plesk verlängert das Zertifikat automatisch. Eine Weiterleitung von HTTP auf HTTPS lässt sich per .htaccess einrichten.",
        }
