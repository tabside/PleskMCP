"""OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-document).

A client identifies itself with an HTTPS URL as client_id. The authorization
server fetches that URL, validates the JSON document and uses its
redirect_uris. Clients using this mechanism are public clients (no secret).
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

MAX_DOCUMENT_BYTES = 64 * 1024
FETCH_TIMEOUT = 10.0
CACHE_TTL = 3600


class CimdError(Exception):
    pass


def is_cimd_client_id(client_id: str) -> bool:
    return client_id.startswith("https://")


def validate_client_id_url(client_id: str) -> None:
    parsed = urlparse(client_id)
    if parsed.scheme != "https":
        raise CimdError("client_id must be an https URL")
    if not parsed.hostname:
        raise CimdError("client_id has no host")
    if parsed.username or parsed.password:
        raise CimdError("client_id must not contain credentials")
    if parsed.fragment:
        raise CimdError("client_id must not contain a fragment")
    if parsed.path in ("", "/"):
        raise CimdError("client_id must have a path component")
    try:
        ipaddress.ip_address(parsed.hostname)
        raise CimdError("client_id host must be a DNS name")
    except ValueError:
        pass
    if parsed.hostname in ("localhost",) or parsed.hostname.endswith(".localhost"):
        raise CimdError("client_id host must be public")


def _is_public_ip(address: str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def check_host_resolves_public(hostname: str, port: int) -> None:
    """Best effort SSRF guard: reject hosts that resolve to non-public addresses."""
    try:
        infos = socket.getaddrinfo(hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise CimdError("client_id host does not resolve") from exc
    addresses = {info[4][0] for info in infos}
    if not addresses or not all(_is_public_ip(a) for a in addresses):
        raise CimdError("client_id host resolves to a non-public address")


def validate_redirect_uri(uri: str) -> None:
    parsed = urlparse(uri)
    if parsed.scheme == "https":
        if not parsed.hostname:
            raise CimdError(f"invalid redirect_uri {uri!r}")
        return
    if parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1", "[::1]"):
        return  # loopback redirect for native clients (RFC 8252)
    if parsed.scheme and parsed.scheme not in ("http", "https") and "." in parsed.scheme:
        return  # private-use URI scheme (reverse domain name), RFC 8252 7.1
    raise CimdError(f"redirect_uri {uri!r} must be https, a loopback http URL or a private-use scheme")


def parse_document(client_id: str, raw: bytes, *, valid_scopes: list[str]) -> dict[str, Any]:
    """Validate a fetched document and return a client record (OAuthClientInformationFull fields)."""
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CimdError("client metadata document is not valid JSON") from exc
    if not isinstance(doc, dict):
        raise CimdError("client metadata document must be a JSON object")
    if doc.get("client_id") != client_id:
        raise CimdError("client_id in document does not match the document URL")
    redirect_uris = doc.get("redirect_uris")
    if not isinstance(redirect_uris, list) or not redirect_uris or not all(isinstance(u, str) for u in redirect_uris):
        raise CimdError("redirect_uris missing or invalid")
    for uri in redirect_uris:
        validate_redirect_uri(uri)
    auth_method = doc.get("token_endpoint_auth_method", "none")
    if auth_method != "none":
        raise CimdError("client metadata document clients must use token_endpoint_auth_method 'none'")
    grant_types = doc.get("grant_types") or ["authorization_code", "refresh_token"]
    if not isinstance(grant_types, list) or "authorization_code" not in grant_types:
        raise CimdError("grant_types must include authorization_code")
    if "refresh_token" not in grant_types:
        grant_types = list(grant_types) + ["refresh_token"]
    response_types = doc.get("response_types") or ["code"]
    if "code" not in response_types:
        raise CimdError("response_types must include code")
    client_name = doc.get("client_name")
    if client_name is not None and not isinstance(client_name, str):
        client_name = None
    record: dict[str, Any] = {
        "client_id": client_id,
        "client_name": (client_name or "")[:200] or None,
        "client_uri": doc.get("client_uri") if isinstance(doc.get("client_uri"), str) else None,
        "logo_uri": doc.get("logo_uri") if isinstance(doc.get("logo_uri"), str) else None,
        "redirect_uris": redirect_uris,
        "token_endpoint_auth_method": "none",
        "grant_types": grant_types,
        "response_types": response_types,
        "scope": " ".join(valid_scopes),
        "application_type": doc.get("application_type") if doc.get("application_type") in ("web", "native") else None,
    }
    return record


async def fetch_document(client_id: str, *, valid_scopes: list[str], transport: httpx.AsyncBaseTransport | None = None) -> dict[str, Any]:
    validate_client_id_url(client_id)
    parsed = urlparse(client_id)
    assert parsed.hostname
    if transport is None:
        check_host_resolves_public(parsed.hostname, parsed.port or 443)
    async with httpx.AsyncClient(timeout=FETCH_TIMEOUT, follow_redirects=False, transport=transport) as client:
        try:
            async with client.stream("GET", client_id, headers={"Accept": "application/json"}) as response:
                if response.status_code != 200:
                    raise CimdError(f"client metadata document returned HTTP {response.status_code}")
                content_type = response.headers.get("content-type", "")
                if "json" not in content_type:
                    raise CimdError("client metadata document must be served as application/json")
                chunks = bytearray()
                async for chunk in response.aiter_bytes():
                    chunks.extend(chunk)
                    if len(chunks) > MAX_DOCUMENT_BYTES:
                        raise CimdError("client metadata document too large")
        except httpx.HTTPError as exc:
            raise CimdError(f"fetching client metadata document failed: {exc.__class__.__name__}") from exc
    return parse_document(client_id, bytes(chunks), valid_scopes=valid_scopes)
