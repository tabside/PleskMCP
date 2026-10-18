"""Starlette application of the api service: MCP endpoint, OAuth, discovery, login and account pages.

Layout for PUBLIC_BASE_URL=https://mcp.example.com/plesk:

    /.well-known/oauth-authorization-server/plesk   AS metadata (RFC 8414)
    /.well-known/openid-configuration/plesk         same document (OIDC discovery fallback)
    /.well-known/oauth-protected-resource/plesk/mcp protected resource metadata (RFC 9728)
    /plesk/.well-known/openid-configuration         issuer-path fallback some clients try
    /plesk/authorize /plesk/token /plesk/register /plesk/revoke   OAuth (MCP SDK)
    /plesk/login                                    this service's login page
    /plesk/account                                  customer self-service page
    /plesk/mcp                                      MCP Streamable HTTP endpoint (bearer token)
    /plesk/healthz  /plesk/readyz  /plesk/metrics   operations
    /plesk/signup/...                               self-signup "AI Hosting" (SIGNUP_ENABLED, signup/web.py)

The api never talks to the Plesk server over SSH; tool calls become jobs for
the worker service (queue.py).
"""

from __future__ import annotations

import json
import logging
import os
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from pydantic import AnyHttpUrl
from redis.asyncio import Redis
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response
from starlette.routing import Mount, Route

from mcp.server.auth.handlers.metadata import MetadataHandler, ProtectedResourceMetadataHandler
from mcp.server.auth.routes import build_metadata, cors_middleware
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.shared.auth import ProtectedResourceMetadata

from . import __version__
from .accounts import AccountService
from .audit import AuditLog
from .auth.account import AccountPages
from .auth.login import LoginPages
from .auth.provider import PleskAuthProvider
from .auth.ratelimit import RedisLimiter
from .config import Settings
from .db import Store, make_engine
from .certs import CertRunner, register_cert_tools
from .dbtools import DbRunner, register_db_tools
from .dns import DnsRunner, register_dns_tools
from .plesk_api import PleskClient
from .queue import JobQueue
from .redis_io import make_redis
from .signup.build import build_signup
from .signup.web import SignupPages
from .tools import ToolRunner, register_tools

logger = logging.getLogger(__name__)

INSTRUCTIONS = (
    "Dieser Server gibt Zugriff auf die Webdateien, DNS-Zonen und (je nach Abo) Datenbanken der Plesk-Abonnements "
    "des angemeldeten Kunden, für die KI-Zugang gebucht ist. Zuerst list_domains aufrufen, dann mit list_dir/read_file "
    "arbeiten. Pfade sind immer relativ zum Document Root der Domain. Schreibende Tools legen Sicherungen an "
    "(list_versions/restore_version, list_changes), delete_file verschiebt in den Papierkorb. Dauert ein Aufruf "
    "länger, kommt eine job_id zurück; das Ergebnis liefert job_status. ssl_status zeigt das SSL-Zertifikat einer "
    "Domain, ssl_issue stellt (falls freigeschaltet) ein Let's-Encrypt-Zertifikat aus."
)


@dataclass
class Services:
    settings: Settings
    store: Store
    redis: Redis
    audit: AuditLog
    plesk: PleskClient
    accounts: AccountService
    provider: PleskAuthProvider
    limiter: RedisLimiter
    queue: JobQueue
    runner: ToolRunner
    mcp: MCPServer
    signup: Any = None  # SignupService or None
    certs: Any = None  # CertRunner


    async def close(self) -> None:
        if self.signup is not None:
            await self.signup.aclose()
        if self.certs is not None:
            await self.certs.aclose()
        await self.plesk.aclose()
        await self.redis.aclose()
        await self.store.close()


def build_core(
    settings: Settings,
    *,
    store: Store | None = None,
    redis: Redis | None = None,
    plesk_transport: Any | None = None,
) -> tuple[Store, Redis, AuditLog, PleskClient, AccountService, JobQueue, RedisLimiter]:
    """Shared objects of api, worker and scheduler."""
    if settings.audit_log_file:
        os.makedirs(os.path.dirname(settings.audit_log_file) or ".", exist_ok=True)
    store = store or Store(make_engine(settings.database_url))
    redis = redis or make_redis(settings.redis_url)
    audit = AuditLog(settings.audit_log_file)
    plesk = PleskClient(settings.plesk_url, verify_ssl=settings.plesk_verify_ssl, timeout=settings.plesk_timeout, transport=plesk_transport)
    accounts = AccountService(settings, store, plesk, audit, redis)
    queue = JobQueue(settings, redis)
    limiter = RedisLimiter(settings, redis)
    return store, redis, audit, plesk, accounts, queue, limiter


def build_services(
    settings: Settings,
    *,
    store: Store | None = None,
    redis: Redis | None = None,
    plesk_transport: Any | None = None,
    cimd_transport: Any | None = None,
    signup_transports: dict[str, Any] | None = None,
    signup_mailer: Any | None = None,
) -> Services:
    store, redis, audit, plesk, accounts, queue, limiter = build_core(settings, store=store, redis=redis, plesk_transport=plesk_transport)
    # the signup service talks to the same Plesk server over its REST API; tests route both through the fake
    signup = build_signup(settings, store, redis, plesk, audit, transports={"plesk_rest": plesk_transport, **(signup_transports or {})}, mailer=signup_mailer)
    provider = PleskAuthProvider(settings, store, audit, cimd_transport=cimd_transport)

    auth_settings = AuthSettings(
        issuer_url=AnyHttpUrl(settings.issuer_url),
        resource_server_url=AnyHttpUrl(settings.resource_url),
        client_registration_options=ClientRegistrationOptions(
            enabled=True, valid_scopes=list(settings.valid_scopes), default_scopes=list(settings.valid_scopes)
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=["files:read"],
        validate_token_resource=True,
    )
    mcp = MCPServer(
        "pleskmcp",
        title=settings.service_name,
        instructions=INSTRUCTIONS,
        version=__version__,
        auth_server_provider=provider,
        auth=auth_settings,
    )
    runner = ToolRunner(settings, accounts, queue, limiter, audit, redis)
    register_tools(mcp, runner, settings)
    register_dns_tools(mcp, DnsRunner(runner, plesk))
    register_db_tools(mcp, DbRunner(runner, store, accounts, plesk))
    certs = CertRunner(runner, transport=plesk_transport)
    register_cert_tools(mcp, certs)
    return Services(settings, store, redis, audit, plesk, accounts, provider, limiter, queue, runner, mcp, signup, certs)


async def readiness(services: Services) -> tuple[bool, dict[str, Any]]:
    checks: dict[str, Any] = {}
    ok = True
    try:
        checks["database"] = await services.store.ping()
    except Exception as exc:  # noqa: BLE001
        checks["database"] = False
        checks["database_error"] = exc.__class__.__name__
    try:
        checks["redis"] = bool(await services.redis.ping())
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = False
        checks["redis_error"] = exc.__class__.__name__
    workers = 0
    preflight: dict[str, Any] = {}
    if checks.get("redis"):
        async for _ in services.redis.scan_iter(match="worker:*", count=100):
            workers += 1
        async for key in services.redis.scan_iter(match="preflight:*", count=100):
            raw = await services.redis.get(key)
            try:
                preflight[key.split(":", 1)[1]] = json.loads(raw) if raw else None
            except ValueError:
                preflight[key.split(":", 1)[1]] = None
    checks["workers"] = workers
    if services.signup is not None:
        checks["signup"] = "enabled"
    # SSH self-check of every worker (key file and host key); failures explain "ssh_config" errors
    checks["ssh_preflight"] = "ok" if preflight and all(p and p.get("ok") for p in preflight.values()) else ("failed" if preflight else "unknown")
    failed = [p.get("message") for p in preflight.values() if p and not p.get("ok")]
    if failed:
        checks["ssh_preflight_errors"] = sorted(set(failed))
    ok = bool(checks.get("database")) and bool(checks.get("redis"))
    return ok, checks


async def metrics_text(services: Services) -> str:
    """Prometheus text format. No logins, domains or paths as labels."""
    lines = [
        "# TYPE pleskmcp_info gauge",
        f'pleskmcp_info{{version="{__version__}"}} 1',
    ]
    try:
        queued = await services.queue.queue_length()
        running = await services.queue.running_count()
        workers = 0
        async for _ in services.redis.scan_iter(match="worker:*", count=100):
            workers += 1
        lines += [
            "# TYPE pleskmcp_jobs_queued gauge",
            f"pleskmcp_jobs_queued {queued}",
            "# TYPE pleskmcp_jobs_running gauge",
            f"pleskmcp_jobs_running {running}",
            "# TYPE pleskmcp_workers_alive gauge",
            f"pleskmcp_workers_alive {workers}",
        ]
        totals = await services.queue.metrics()
        lines.append("# TYPE pleskmcp_jobs_total counter")
        lines.append("# TYPE pleskmcp_job_seconds_total counter")
        for key, value in sorted(totals.items()):
            # keys: <op>:ok, <op>:failed, <op>:duration_sum, <op>:count
            op, _, kind = key.rpartition(":")
            if kind in ("ok", "failed"):
                lines.append(f'pleskmcp_jobs_total{{op="{op}",status="{kind}"}} {int(value)}')
            elif kind == "duration_sum":
                lines.append(f'pleskmcp_job_seconds_total{{op="{op}"}} {value:.3f}')
    except Exception as exc:  # noqa: BLE001
        lines.append(f'pleskmcp_metrics_error{{error="{exc.__class__.__name__}"}} 1')
    return "\n".join(lines) + "\n"


def build_app(services: Services) -> Starlette:
    settings = services.settings
    mcp = services.mcp
    login = LoginPages(settings, services.provider, services.accounts, services.limiter, services.audit)
    account = AccountPages(settings, services.store, services.accounts, services.limiter, services.audit, services.redis)

    @mcp.custom_route("/login", methods=["GET"])
    async def login_get(request: Request) -> Response:
        return await login.get(request)

    @mcp.custom_route("/login", methods=["POST"])
    async def login_post(request: Request) -> Response:
        return await login.post(request)

    @mcp.custom_route("/account", methods=["GET"])
    async def account_get(request: Request) -> Response:
        return await account.get(request)

    @mcp.custom_route("/account/login", methods=["POST"])
    async def account_login(request: Request) -> Response:
        return await account.post_login(request)

    @mcp.custom_route("/account/logout", methods=["POST"])
    async def account_logout(request: Request) -> Response:
        return await account.post_logout(request)

    @mcp.custom_route("/account/disconnect", methods=["POST"])
    async def account_disconnect(request: Request) -> Response:
        return await account.post_disconnect(request)

    @mcp.custom_route("/account/db", methods=["POST"])
    async def account_db(request: Request) -> Response:
        return await account.post_db(request)

    if services.signup is not None:
        signup = SignupPages(settings, services.signup, services.limiter, services.redis)

        @mcp.custom_route("/signup", methods=["POST"])
        async def signup_post(request: Request) -> Response:
            return await signup.post_order(request)

        @mcp.custom_route("/signup", methods=["OPTIONS"])
        async def signup_options(request: Request) -> Response:
            return await signup.options(request)

        @mcp.custom_route("/signup/config", methods=["GET", "OPTIONS"])
        async def signup_config(request: Request) -> Response:
            return await signup.options(request) if request.method == "OPTIONS" else await signup.get_config(request)

        @mcp.custom_route("/signup/token", methods=["GET", "OPTIONS"])
        async def signup_token(request: Request) -> Response:
            return await signup.options(request) if request.method == "OPTIONS" else await signup.get_token(request)

        @mcp.custom_route("/signup/check-domain", methods=["GET", "OPTIONS"])
        async def signup_check(request: Request) -> Response:
            return await signup.options(request) if request.method == "OPTIONS" else await signup.check_domain(request)

        @mcp.custom_route("/signup/thanks/{order_id}", methods=["GET"])
        async def signup_thanks(request: Request) -> Response:
            return await signup.thanks(request)

        @mcp.custom_route("/signup/confirm/{token}", methods=["GET"])
        async def signup_confirm(request: Request) -> Response:
            return await signup.confirm(request)

        @mcp.custom_route("/signup/welcome/{token}", methods=["GET"])
        async def signup_welcome(request: Request) -> Response:
            return await signup.welcome(request)

        @mcp.custom_route("/signup/admin", methods=["GET"])
        async def signup_admin(request: Request) -> Response:
            return await signup.admin(request)

        @mcp.custom_route("/signup/admin/action", methods=["POST"])
        async def signup_admin_action(request: Request) -> Response:
            return await signup.admin_action(request)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok", "version": __version__, "time": int(time.time())})

    @mcp.custom_route("/readyz", methods=["GET"])
    async def readyz(request: Request) -> Response:
        ok, checks = await readiness(services)
        return JSONResponse({"status": "ok" if ok else "degraded", "checks": checks}, status_code=200 if ok else 503)

    if settings.metrics_enabled:

        @mcp.custom_route("/metrics", methods=["GET"])
        async def metrics(request: Request) -> Response:
            return PlainTextResponse(await metrics_text(services), media_type="text/plain; version=0.0.4")

    @mcp.custom_route("/", methods=["GET"])
    async def index(request: Request) -> Response:
        return JSONResponse({"service": settings.service_name, "mcp_endpoint": settings.resource_url, "account_page": f"{settings.public_base_url}/account", "version": __version__})

    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=[settings.public_host, "127.0.0.1:*", "localhost:*"],
        allowed_origins=[f"https://{settings.public_host}", "http://127.0.0.1:*", "http://localhost:*"],
    )
    inner = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        max_request_body_size=settings.write_max_bytes * 2 + 1024 * 1024,
        transport_security=transport_security,
        host=settings.host,
    )

    # Authorization server metadata: the SDK builds the document, we add the
    # flags for Client ID Metadata Documents and the RFC 9207 iss parameter.
    assert mcp.settings.auth is not None
    metadata = build_metadata(
        mcp.settings.auth.issuer_url,
        None,
        mcp.settings.auth.client_registration_options or ClientRegistrationOptions(),
        mcp.settings.auth.revocation_options or RevocationOptions(),
    )
    metadata.client_id_metadata_document_supported = True
    metadata.authorization_response_iss_parameter_supported = True
    metadata_endpoint = cors_middleware(MetadataHandler(metadata).handle, ["GET", "OPTIONS"])

    prm = ProtectedResourceMetadata(
        resource=AnyHttpUrl(settings.resource_url),
        authorization_servers=[AnyHttpUrl(settings.issuer_url)],
        scopes_supported=list(settings.valid_scopes),
        resource_name=settings.service_name,
    )
    prm_endpoint = cors_middleware(ProtectedResourceMetadataHandler(prm).handle, ["GET", "OPTIONS"])

    inner_routes = list(inner.router.routes)
    for position, route in enumerate(inner_routes):
        if isinstance(route, Route) and route.path == "/.well-known/oauth-authorization-server":
            inner_routes[position] = Route(route.path, endpoint=metadata_endpoint, methods=["GET", "OPTIONS"])
    inner_routes.insert(0, Route("/.well-known/openid-configuration", endpoint=metadata_endpoint, methods=["GET", "OPTIONS"]))
    inner.router.routes[:] = inner_routes

    base = settings.base_path
    well_known: list[Route | Mount] = [
        Route(f"/.well-known/oauth-authorization-server{base}", endpoint=metadata_endpoint, methods=["GET", "OPTIONS"]),
        Route(f"/.well-known/openid-configuration{base}", endpoint=metadata_endpoint, methods=["GET", "OPTIONS"]),
        Route(f"/.well-known/oauth-protected-resource{base}/mcp", endpoint=prm_endpoint, methods=["GET", "OPTIONS"]),
    ]
    if not base:
        inner.router.routes[:0] = well_known
        return inner

    @asynccontextmanager
    async def lifespan(app: Starlette):
        async with inner.router.lifespan_context(inner):
            yield

    return Starlette(routes=[*well_known, Mount(base, app=inner)], lifespan=lifespan)


def create_app() -> Starlette:
    """Application factory for uvicorn workers (`API_WORKERS` > 1): every process builds its own services."""
    from .logging_setup import configure_logging

    configure_logging("api")
    settings = Settings.load()
    return build_app(build_services(settings))


def run_api(settings: Settings) -> None:
    import uvicorn

    workers = int(os.environ.get("API_WORKERS", "1") or "1")
    logger.info("PleskMCP api %s listening on %s:%s (%d process(es)), public URL %s", __version__, settings.host, settings.port, workers, settings.public_base_url)
    options: dict[str, Any] = {
        "host": settings.host,
        "port": settings.port,
        "proxy_headers": True,
        "forwarded_allow_ips": settings.trusted_proxies,
        "log_level": "info",
        "log_config": None,
        "timeout_graceful_shutdown": int(settings.tool_sync_wait) + 5,
    }
    if workers > 1:
        uvicorn.run("pleskmcp.server:create_app", factory=True, workers=workers, **options)
    else:
        uvicorn.run(build_app(build_services(settings)), **options)


def main() -> None:  # pragma: no cover - entry point kept for `python -m pleskmcp.server`
    from .logging_setup import configure_logging

    configure_logging("api")
    run_api(Settings.load())


if __name__ == "__main__":
    main()
