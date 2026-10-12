"""Starlette application: MCP endpoint, OAuth endpoints, discovery documents, login page.

Layout for PUBLIC_BASE_URL=https://mcp.example.com/plesk:

    /.well-known/oauth-authorization-server/plesk   AS metadata (RFC 8414)
    /.well-known/openid-configuration/plesk         same document (OIDC discovery fallback)
    /.well-known/oauth-protected-resource/plesk/mcp protected resource metadata (RFC 9728)
    /plesk/.well-known/openid-configuration         issuer-path fallback some clients try
    /plesk/authorize /plesk/token /plesk/register /plesk/revoke   OAuth (MCP SDK)
    /plesk/login                                    this service's login page
    /plesk/mcp                                      MCP Streamable HTTP endpoint (bearer token)
    /plesk/healthz                                  health check
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
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
from .auth.login import LoginPages
from .auth.provider import PleskAuthProvider
from .auth.ratelimit import LoginRateLimiter
from .config import Settings
from .plesk_api import PleskClient
from .remote import RemoteExecutor
from .store import Store
from .tools import ToolRunner, register_tools

logger = logging.getLogger(__name__)

INSTRUCTIONS = (
    "Dieser Server gibt Zugriff auf die Webdateien der Plesk-Abonnements des angemeldeten Kunden. "
    "Zuerst list_domains aufrufen, dann mit list_dir/read_file arbeiten. Pfade sind immer relativ zum "
    "Document Root der Domain. Schreibende Tools legen Sicherungen an, delete_file verschiebt in den Papierkorb."
)


@dataclass
class Services:
    settings: Settings
    store: Store
    audit: AuditLog
    plesk: PleskClient
    accounts: AccountService
    provider: PleskAuthProvider
    limiter: LoginRateLimiter
    executor: RemoteExecutor
    mcp: MCPServer


def build_services(
    settings: Settings,
    *,
    plesk_transport: Any | None = None,
    cimd_transport: Any | None = None,
    executor: RemoteExecutor | None = None,
) -> Services:
    os.makedirs(settings.data_dir, exist_ok=True)
    store = Store(settings.db_path)
    audit = AuditLog(settings.audit_log_file)
    plesk = PleskClient(settings.plesk_url, verify_ssl=settings.plesk_verify_ssl, timeout=settings.plesk_timeout, transport=plesk_transport)
    accounts = AccountService(settings, store, plesk, audit)
    provider = PleskAuthProvider(settings, store, audit, cimd_transport=cimd_transport)
    limiter = LoginRateLimiter(settings, store)
    executor = executor or RemoteExecutor(settings)

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
    runner = ToolRunner(settings, accounts, executor, audit)
    register_tools(mcp, runner, settings)
    return Services(settings, store, audit, plesk, accounts, provider, limiter, executor, mcp)


def build_app(services: Services) -> Starlette:
    settings = services.settings
    mcp = services.mcp
    login = LoginPages(settings, services.provider, services.accounts, services.limiter, services.audit)

    @mcp.custom_route("/login", methods=["GET"])
    async def login_get(request: Request) -> Response:
        return await login.get(request)

    @mcp.custom_route("/login", methods=["POST"])
    async def login_post(request: Request) -> Response:
        return await login.post(request)

    @mcp.custom_route("/healthz", methods=["GET"])
    async def healthz(request: Request) -> Response:
        return JSONResponse({"status": "ok", "version": __version__})

    @mcp.custom_route("/", methods=["GET"])
    async def index(request: Request) -> Response:
        return JSONResponse({"service": settings.service_name, "mcp_endpoint": settings.resource_url, "version": __version__})

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

    # Replace the SDK's metadata route (relative to the mount) with the enriched document.
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


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    settings = Settings.load()
    services = build_services(settings)
    app = build_app(services)
    import uvicorn

    trusted = os.environ.get("TRUSTED_PROXIES", "127.0.0.1")
    logger.info("PleskMCP %s listening on %s:%s, public URL %s", __version__, settings.host, settings.port, settings.public_base_url)
    uvicorn.run(app, host=settings.host, port=settings.port, proxy_headers=True, forwarded_allow_ips=trusted, log_level="info")


if __name__ == "__main__":
    main()
