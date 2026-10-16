"""OAuthAuthorizationServerProvider implementation backed by the SQLite store.

The MCP SDK handles the HTTP endpoints (/authorize, /token, /register,
/revoke, metadata) and PKCE verification; this class supplies the storage and
the policy: which clients exist, where the user logs in, how codes are
exchanged and how tokens are rotated.
"""

from __future__ import annotations

import logging
import secrets
import time
from typing import Any

from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from ..audit import AuditLog
from ..config import Settings
from ..db import Store, hash_secret, new_token
from . import cimd

logger = logging.getLogger(__name__)


class PleskAccessToken(AccessToken):
    plesk_login: str = ""


class PleskRefreshToken(RefreshToken):
    plesk_login: str = ""
    token_hash: str = ""
    family_id: str = ""


class PleskAuthorizationCode(AuthorizationCode):
    plesk_login: str = ""
    code_hash: str = ""
    revoke_others: bool = False


class PleskAuthProvider:
    def __init__(self, settings: Settings, store: Store, audit: AuditLog, *, cimd_transport: Any | None = None):
        self._settings = settings
        self._store = store
        self._audit = audit
        self._cimd_transport = cimd_transport

    # ------------------------------------------------------------------ clients
    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        cached = await self._store.get_client(client_id)
        if cimd.is_cimd_client_id(client_id):
            if cached is not None and time.time() - cached[2] < cimd.CACHE_TTL:
                return OAuthClientInformationFull.model_validate(cached[1])
            try:
                record = await cimd.fetch_document(
                    client_id, valid_scopes=self._settings.valid_scopes, transport=self._cimd_transport
                )
            except cimd.CimdError as exc:
                logger.warning("client metadata document rejected for %s: %s", client_id, exc)
                if cached is not None:
                    # Keep serving a previously validated document for a while if the refetch fails.
                    if time.time() - cached[2] < cimd.CACHE_TTL * 24:
                        return OAuthClientInformationFull.model_validate(cached[1])
                return None
            await self._store.save_client(client_id, "cimd", record)
            self._audit.write("client_metadata_fetched", client=client_id, client_name=record.get("client_name"))
            return OAuthClientInformationFull.model_validate(record)
        if cached is None:
            return None
        return OAuthClientInformationFull.model_validate(cached[1])

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        if cimd.is_cimd_client_id(client_info.client_id):  # pragma: no cover - SDK mints UUIDs
            return
        from mcp.server.auth.provider import RegistrationError

        if not client_info.redirect_uris:
            raise RegistrationError("invalid_redirect_uri", "redirect_uris is required")
        for uri in client_info.redirect_uris:
            try:
                cimd.validate_redirect_uri(str(uri))
            except cimd.CimdError as exc:
                raise RegistrationError("invalid_redirect_uri", str(exc)) from exc
        if not client_info.scope:
            client_info.scope = " ".join(self._settings.valid_scopes)
        await self._store.save_client(client_info.client_id, "dcr", client_info.model_dump(mode="json", exclude_none=True))
        self._audit.write("client_registered", client=client_info.client_id, client_name=client_info.client_name)

    # ---------------------------------------------------------------- authorize
    async def authorize(self, client: OAuthClientInformationFull, params: AuthorizationParams) -> str:
        resource = self._validate_resource(params.resource)
        scopes = params.scopes or list(self._settings.valid_scopes)
        request_id = secrets.token_urlsafe(24)
        await self._store.save_auth_request(
            request_id,
            client.client_id,
            {
                "state": params.state,
                "scopes": scopes,
                "code_challenge": params.code_challenge,
                "redirect_uri": str(params.redirect_uri),
                "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
                "resource": resource,
            },
            self._settings.auth_request_ttl,
        )
        return f"{self._settings.public_base_url}/login?req={request_id}"

    def _validate_resource(self, resource: str | None) -> str:
        canonical = self._settings.resource_url
        if resource is None:
            return canonical
        if resource.rstrip("/").lower() != canonical.rstrip("/").lower():
            raise AuthorizeError("invalid_target", f"This authorization server only issues tokens for {canonical}")
        return canonical

    async def load_pending_request(self, request_id: str) -> tuple[str, dict[str, Any]] | None:
        return await self._store.get_auth_request(request_id)

    async def complete_login(self, request_id: str, client_id: str, params: dict[str, Any], plesk_login: str, *, revoke_others: bool = False) -> str:
        """Called by the login page after successful Plesk authentication. Returns the redirect URL.

        revoke_others: the customer ticked "Andere Verbindungen trennen"; every
        older token family of the login is revoked once the new one exists.
        """
        from mcp.server.auth.provider import construct_redirect_uri

        code = new_token()
        await self._store.save_auth_code(
            code,
            client_id=client_id,
            plesk_login=plesk_login,
            scopes=params["scopes"],
            code_challenge=params["code_challenge"],
            redirect_uri=params["redirect_uri"],
            redirect_uri_explicit=params["redirect_uri_provided_explicitly"],
            resource=params.get("resource"),
            ttl=self._settings.auth_code_ttl,
            revoke_others=revoke_others,
        )
        await self._store.delete_auth_request(request_id)
        return construct_redirect_uri(
            params["redirect_uri"], code=code, state=params.get("state"), iss=self._settings.issuer_url
        )

    async def deny_login(self, request_id: str, params: dict[str, Any]) -> str:
        from mcp.server.auth.provider import construct_redirect_uri

        await self._store.delete_auth_request(request_id)
        return construct_redirect_uri(
            params["redirect_uri"],
            error="access_denied",
            error_description="The user cancelled the authorization",
            state=params.get("state"),
            iss=self._settings.issuer_url,
        )

    # --------------------------------------------------------------------- codes
    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> PleskAuthorizationCode | None:
        row = await self._store.get_auth_code(authorization_code)
        if row is None or row.client_id != client.client_id:
            return None
        if row.used:
            # Replay of a consumed code: revoke what it produced (RFC 6749 4.1.2).
            logger.warning("authorization code replay for client %s", client.client_id)
            return None
        return PleskAuthorizationCode(
            code=authorization_code,
            scopes=row.scopes,
            expires_at=row.expires_at,
            client_id=row.client_id,
            code_challenge=row.code_challenge,
            redirect_uri=row.redirect_uri,  # type: ignore[arg-type]
            redirect_uri_provided_explicitly=row.redirect_uri_explicit,
            resource=row.resource,
            subject=row.plesk_login,
            plesk_login=row.plesk_login,
            code_hash=row.code_hash,
            revoke_others=row.revoke_others,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: PleskAuthorizationCode
    ) -> OAuthToken:
        if not await self._store.consume_auth_code(authorization_code.code_hash):
            raise TokenError("invalid_grant", "authorization code already used")
        family_id = secrets.token_urlsafe(16)
        token = await self._issue(
            client_id=client.client_id,
            plesk_login=authorization_code.plesk_login,
            scopes=authorization_code.scopes,
            resource=authorization_code.resource or self._settings.resource_url,
            family_id=family_id,
        )
        self._audit.write(
            "token_issued", login=authorization_code.plesk_login, client=client.client_id, grant="authorization_code"
        )
        if authorization_code.revoke_others:
            revoked = await self._store.revoke_login(authorization_code.plesk_login, except_family=family_id)
            self._audit.write("tokens_revoked", login=authorization_code.plesk_login, tokens_revoked=revoked, source="login_checkbox", client=client.client_id)
        return token

    async def _issue(self, *, client_id: str, plesk_login: str, scopes: list[str], resource: str, family_id: str) -> OAuthToken:
        access = new_token()
        refresh = new_token()
        await self._store.save_token(
            access,
            kind="access",
            client_id=client_id,
            plesk_login=plesk_login,
            scopes=scopes,
            resource=resource,
            family_id=family_id,
            ttl=self._settings.access_token_ttl,
        )
        await self._store.save_token(
            refresh,
            kind="refresh",
            client_id=client_id,
            plesk_login=plesk_login,
            scopes=scopes,
            resource=resource,
            family_id=family_id,
            ttl=self._settings.refresh_token_ttl,
        )
        return OAuthToken(
            access_token=access,
            token_type="Bearer",
            expires_in=self._settings.access_token_ttl,
            scope=" ".join(scopes),
            refresh_token=refresh,
        )

    # ------------------------------------------------------------ refresh tokens
    async def load_refresh_token(self, client: OAuthClientInformationFull, refresh_token: str) -> PleskRefreshToken | None:
        row = await self._store.get_token(refresh_token, "refresh")
        if row is None or row.client_id != client.client_id or row.revoked:
            return None
        if row.rotated:
            # Reuse of a rotated refresh token: the whole family is compromised (OAuth 2.1 4.3.1).
            revoked = await self._store.revoke_family(row.family_id)
            self._audit.write(
                "refresh_token_reuse", login=row.plesk_login, client=client.client_id, tokens_revoked=revoked
            )
            return None
        return PleskRefreshToken(
            token=refresh_token,
            client_id=row.client_id,
            scopes=row.scopes,
            expires_at=row.expires_at,
            resource=row.resource,
            subject=row.plesk_login,
            plesk_login=row.plesk_login,
            token_hash=row.token_hash,
            family_id=row.family_id,
        )

    async def exchange_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: PleskRefreshToken, scopes: list[str]
    ) -> OAuthToken:
        account = await self._store.get_account(refresh_token.plesk_login)
        if account is None or account.status != "active":
            await self._store.revoke_family(refresh_token.family_id)
            raise TokenError("invalid_grant", "account is no longer active")
        if not await self._store.mark_rotated(refresh_token.token_hash):
            raise TokenError("invalid_grant", "refresh token already used")
        token = await self._issue(
            client_id=client.client_id,
            plesk_login=refresh_token.plesk_login,
            scopes=scopes or refresh_token.scopes,
            resource=refresh_token.resource or self._settings.resource_url,
            family_id=refresh_token.family_id,
        )
        self._audit.write("token_issued", login=refresh_token.plesk_login, client=client.client_id, grant="refresh_token")
        return token

    # ------------------------------------------------------------- access tokens
    async def load_access_token(self, token: str) -> PleskAccessToken | None:
        row = await self._store.get_token(token, "access")
        if row is None or row.revoked or row.expires_at < int(time.time()):
            return None
        await self._store.touch_token(row.token_hash)
        return PleskAccessToken(
            token=token,
            client_id=row.client_id,
            scopes=row.scopes,
            expires_at=row.expires_at,
            resource=row.resource,
            subject=row.plesk_login,
            plesk_login=row.plesk_login,
        )

    async def revoke_token(self, token: PleskAccessToken | PleskRefreshToken) -> None:
        kind = "refresh" if isinstance(token, RefreshToken) else "access"
        row = await self._store.get_token(token.token, kind)
        if row is None:
            return
        revoked = await self._store.revoke_family(row.family_id)
        self._audit.write("tokens_revoked", login=row.plesk_login, client=row.client_id, tokens_revoked=revoked, source="client")

    async def exchange_identity_assertion(self, client: OAuthClientInformationFull, params: Any) -> OAuthToken:
        raise TokenError("unsupported_grant_type", "The JWT bearer grant is not supported")


__all__ = ["PleskAuthProvider", "PleskAccessToken", "PleskRefreshToken", "PleskAuthorizationCode", "hash_secret"]
