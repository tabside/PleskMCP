"""Customer accounts: login verification, domain mapping, access profiles, quota and liveness checks.

Three modes for the per-call status check (ACCOUNT_CHECK_MODE):

* customer_key: at login a Plesk secret key is created for the customer with
  the customer's own credentials and stored encrypted. Status checks, domain
  refreshes, plan and quota lookups run in the customer's own context.
* admin_key: an administrator secret key (read-only use) looks up the
  customer, its webspaces, plans and quotas.
* login_only: no re-check after login; the domain list from login time is kept
  until the next login. DNS and database tools are unavailable.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet, InvalidToken
from redis.asyncio import Redis

from .audit import AuditLog
from .config import Settings
from .db import AccountRow, Store
from .plesk_api import (
    ERR_ACCOUNT_SUSPENDED,
    ERR_PERMISSION_DENIED,
    ERR_WRONG_CREDENTIALS,
    DomainInfo,
    KeyAuth,
    PasswordAuth,
    PleskClient,
    PleskError,
    PleskResultError,
    PleskSystemError,
)
from .profiles import Profile, resolve_profile
from .redis_io import cache_get_json, cache_set_json

logger = logging.getLogger(__name__)


class LoginRejected(Exception):
    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


class AccountInactive(Exception):
    pass


class UnknownDomain(Exception):
    pass


class NoAccess(Exception):
    """The subscription has no plan or add-on with an access profile."""

    def __init__(self, domain: str):
        super().__init__(domain)
        self.domain = domain


@dataclass
class Account:
    login: str
    display_name: str | None
    domains: list[DomainInfo]

    def find_domain(self, name: str) -> DomainInfo | None:
        wanted = name.strip().lower().rstrip(".")
        for domain in self.domains:
            if domain.name.lower() == wanted and domain.status == 0:
                return domain
        return None


@dataclass
class Quota:
    quota_bytes: int | None  # None = unlimited/unknown
    used_bytes: int | None
    fetched_at: int


class AccountService:
    def __init__(self, settings: Settings, store: Store, plesk: PleskClient, audit: AuditLog, redis: Redis):
        self._settings = settings
        self._store = store
        self._plesk = plesk
        self._audit = audit
        self._redis = redis
        self._fernet = Fernet(settings.data_encryption_key.encode()) if settings.data_encryption_key else None

    # ------------------------------------------------------------------- helpers
    def encrypt(self, value: str) -> str:
        if self._fernet is None:
            raise RuntimeError("DATA_ENCRYPTION_KEY is not configured")
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt(self, value: str) -> str | None:
        if self._fernet is None:
            return None
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken:
            return None

    @property
    def can_encrypt(self) -> bool:
        return self._fernet is not None

    @staticmethod
    def _to_account(row: AccountRow) -> Account:
        return Account(login=row.plesk_login, display_name=row.display_name, domains=[DomainInfo.from_dict(d) for d in row.domains])

    # --------------------------------------------------------------------- login
    async def verify_password(self, login: str, password: str) -> Any:
        """Check Plesk credentials of a customer main login. Raises LoginRejected."""
        login = login.strip()
        if not login or not password:
            raise LoginRejected("invalid", "Benutzername und Passwort sind erforderlich.")
        try:
            return await self._plesk.verify_customer(login, password)
        except PleskSystemError as exc:
            if exc.code == ERR_WRONG_CREDENTIALS:
                raise LoginRejected("credentials", "Benutzername oder Passwort ist falsch.") from exc
            if exc.code == ERR_ACCOUNT_SUSPENDED:
                raise LoginRejected("suspended", "Dieses Konto ist gesperrt.") from exc
            logger.warning("plesk system error during login: %s", exc)
            raise LoginRejected("plesk_error", "Anmeldung derzeit nicht möglich.") from exc
        except PleskResultError as exc:
            raise LoginRejected("not_customer", "Nur Kunden-Hauptlogins sind zugelassen.") from exc
        except PleskError as exc:
            logger.error("plesk api error during login: %s", exc)
            raise LoginRejected("plesk_error", "Anmeldung derzeit nicht möglich.") from exc

    async def login(self, login: str, password: str, *, client_ip: str, client_id: str) -> Account:
        """Verify Plesk credentials, reject non-customers, store the domain mapping."""
        login = login.strip()
        info = await self.verify_password(login, password)
        creds = PasswordAuth(login, password)
        try:
            domains = await self._plesk.list_domains(creds)
        except PleskError as exc:
            logger.error("domain listing failed for %s: %s", login, exc)
            raise LoginRejected("plesk_error", "Anmeldung derzeit nicht möglich.") from exc

        secret_enc: str | None = None
        if self._settings.account_check_mode == "customer_key":
            secret_enc = await self._ensure_customer_key(login, creds)

        await self._store.save_account(
            login,
            display_name=info.name or None,
            secret_key_enc=secret_enc,
            domains=[d.as_dict() for d in domains],
            status="active",
        )
        await self.invalidate_caches(login)
        self._audit.write("login_success", login=login, ip=client_ip, client=client_id, domains=[d.name for d in domains])
        return Account(login=login, display_name=info.name or None, domains=domains)

    async def _ensure_customer_key(self, login: str, creds: PasswordAuth) -> str | None:
        existing = await self._store.get_account(login)
        if existing and existing.secret_key_enc:
            key = self.decrypt(existing.secret_key_enc)
            if key:
                try:
                    await self._plesk.get_customer(login, KeyAuth(key))
                    return None  # keep the stored value
                except PleskError:
                    await self._store.clear_account_secret(login)
        try:
            key = await self._plesk.create_secret_key(creds, ip_address=self._settings.customer_key_ip, description="PleskMCP connector")
        except PleskResultError as exc:
            logger.error(
                "customer %s may not create a secret key (%s). Switch ACCOUNT_CHECK_MODE to admin_key or login_only.", login, exc
            )
            raise LoginRejected("config", "Anmeldung derzeit nicht möglich (Serverkonfiguration).") from exc
        except PleskError as exc:
            raise LoginRejected("plesk_error", "Anmeldung derzeit nicht möglich.") from exc
        return self.encrypt(key)

    # ------------------------------------------------------------ status checks
    async def get_active_account(self, login: str) -> Account:
        row = await self._store.get_account(login)
        if row is None or row.status != "active":
            raise AccountInactive(login)
        if time.time() - row.checked_at < self._settings.account_check_ttl:
            return self._to_account(row)
        mode = self._settings.account_check_mode
        if mode == "login_only":
            await self._store.update_account_check(login, status="active", domains=None)
            return self._to_account(row)
        try:
            if mode == "customer_key":
                domains = await self._check_with_customer_key(login, row)
            else:
                domains = await self._check_with_admin_key(login)
        except AccountInactive:
            await self.deactivate(login, "status_check")
            raise
        except PleskError as exc:
            logger.warning("status check for %s failed, using cached mapping: %s", login, exc)
            if time.time() - row.checked_at > self._settings.account_check_ttl * 10:
                await self.deactivate(login, "status_check_unavailable")
                raise AccountInactive(login) from exc
            return self._to_account(row)
        await self._store.update_account_check(login, status="active", domains=[d.as_dict() for d in domains])
        row = await self._store.get_account(login)
        assert row is not None
        return self._to_account(row)

    async def _check_with_customer_key(self, login: str, row: AccountRow) -> list[DomainInfo]:
        key = self.decrypt(row.secret_key_enc) if row.secret_key_enc else None
        if not key:
            raise AccountInactive(login)
        auth = KeyAuth(key)
        try:
            info = await self._plesk.get_customer(login, auth)
        except PleskSystemError as exc:
            if exc.code in (ERR_WRONG_CREDENTIALS, ERR_ACCOUNT_SUSPENDED, ERR_PERMISSION_DENIED):
                raise AccountInactive(login) from exc
            raise
        except PleskResultError as exc:
            raise AccountInactive(login) from exc
        if info is None or info.login != login or info.status != 0:
            raise AccountInactive(login)
        return await self._plesk.list_domains(auth)

    async def _check_with_admin_key(self, login: str) -> list[DomainInfo]:
        assert self._settings.plesk_admin_api_key
        auth = KeyAuth(self._settings.plesk_admin_api_key)
        info = await self._plesk.get_customer(login, auth)
        if info is None or info.login != login or info.status != 0:
            raise AccountInactive(login)
        return await self._plesk.list_domains(auth, owner_login=login)

    async def deactivate(self, login: str, reason: str) -> None:
        await self._store.update_account_check(login, status="inactive", domains=None)
        revoked = await self._store.revoke_login(login)
        await self.invalidate_caches(login)
        self._audit.write("account_deactivated", login=login, reason=reason, tokens_revoked=revoked)

    # ---------------------------------------------------------------- revocation
    async def revoke_login(self, login: str, *, delete_secret_key: bool = True, source: str = "cli") -> int:
        revoked = await self._store.revoke_login(login)
        row = await self._store.get_account(login)
        if row and row.secret_key_enc and delete_secret_key:
            key = self.decrypt(row.secret_key_enc)
            if key:
                try:
                    await self._plesk.delete_secret_key(KeyAuth(key), key)
                except PleskError as exc:
                    logger.warning("could not delete Plesk secret key of %s: %s", login, exc)
            await self._store.clear_account_secret(login)
            await self._store.update_account_check(login, status="inactive", domains=None)
        self._audit.write("tokens_revoked", login=login, tokens_revoked=revoked, source=source)
        return revoked

    # ---------------------------------------------------------------- api auth
    async def api_auth_for(self, login: str) -> KeyAuth | None:
        mode = self._settings.account_check_mode
        if mode == "admin_key" and self._settings.plesk_admin_api_key:
            return KeyAuth(self._settings.plesk_admin_api_key)
        if mode == "customer_key":
            row = await self._store.get_account(login)
            if row is None or not row.secret_key_enc:
                return None
            key = self.decrypt(row.secret_key_enc)
            return KeyAuth(key) if key else None
        return None

    # ------------------------------------------------------- profiles and quota
    async def invalidate_caches(self, login: str) -> None:
        keys = []
        async for key in self._redis.scan_iter(match=f"plan:{login}:*", count=100):
            keys.append(key)
        async for key in self._redis.scan_iter(match=f"quota:{login}:*", count=100):
            keys.append(key)
        async for key in self._redis.scan_iter(match=f"dbs:{login}:*", count=100):
            keys.append(key)
        if keys:
            await self._redis.delete(*keys)

    async def customer_auth_for(self, login: str) -> KeyAuth | None:
        """The customer's own secret key only (never the administrator key): used for every write to Plesk."""
        row = await self._store.get_account(login)
        if row is None or not row.secret_key_enc:
            return None
        key = self.decrypt(row.secret_key_enc)
        return KeyAuth(key) if key else None

    async def forget_databases(self, login: str, webspace: str) -> None:
        await self._redis.delete(f"dbs:{login}:{webspace}")

    async def _plan_names(self, guids: list[str]) -> list[str]:
        """guid -> name via the administrator key (read-only), cached. Without it, names are unknown."""
        if not guids or not self._settings.plesk_admin_api_key:
            return []
        cached = await cache_get_json(self._redis, "plan:names")
        if cached is None:
            try:
                cached = await self._plesk.get_service_plan_names(KeyAuth(self._settings.plesk_admin_api_key))
            except PleskError as exc:
                logger.warning("service plan names unavailable: %s", exc)
                cached = {}
            await cache_set_json(self._redis, "plan:names", cached, self._settings.plan_cache_ttl)
        return [cached[g] for g in guids if g in cached]

    async def profile_for(self, login: str, domain: DomainInfo) -> Profile:
        """Effective access profile of the subscription a domain belongs to. Raises NoAccess."""
        ws_id = domain.webspace_id or domain.id
        cache_key = f"plan:{login}:{ws_id}"
        cached = await cache_get_json(self._redis, cache_key)
        if cached is None:
            guids: list[str] = [domain.plan_guid] if domain.plan_guid else []
            auth = await self.api_auth_for(login)
            if auth is not None and ws_id is not None:
                try:
                    guids = await self._plesk.get_subscription_plans(auth, ws_id)
                except PleskError as exc:
                    logger.warning("plan lookup failed for %s/%s: %s", login, domain.name, exc)
            names = await self._plan_names(guids)
            cached = {"guids": guids, "names": names}
            await cache_set_json(self._redis, cache_key, cached, self._settings.plan_cache_ttl)
        profile = resolve_profile(self._settings.profiles, list(cached.get("names", [])), list(cached.get("guids", [])))
        if profile is None and "*" in self._settings.profiles:
            profile = self._settings.profiles["*"]
        if profile is None:
            raise NoAccess(domain.name)
        return profile

    async def quota_for(self, login: str, domain: DomainInfo, *, refresh: bool = False) -> Quota:
        ws_id = domain.webspace_id or domain.id
        cache_key = f"quota:{login}:{ws_id}"
        if not refresh:
            cached = await cache_get_json(self._redis, cache_key)
            if cached is not None:
                return Quota(cached.get("quota_bytes"), cached.get("used_bytes"), int(cached.get("fetched_at", 0)))
        quota = Quota(None, None, int(time.time()))
        auth = await self.api_auth_for(login)
        if auth is not None and ws_id is not None:
            try:
                q, used, _plan = await self._plesk.get_webspace_quota(auth, ws_id)
                quota = Quota(q, used, int(time.time()))
            except PleskError as exc:
                logger.warning("quota lookup failed for %s/%s: %s", login, domain.name, exc)
        await cache_set_json(self._redis, cache_key, {"quota_bytes": quota.quota_bytes, "used_bytes": quota.used_bytes, "fetched_at": quota.fetched_at}, self._settings.quota_cache_ttl)
        return quota

    async def databases_for(self, login: str, domain: DomainInfo) -> list[dict[str, Any]]:
        auth = await self.api_auth_for(login)
        if auth is None:
            return []
        cache_key = f"dbs:{login}:{domain.webspace}"
        cached = await cache_get_json(self._redis, cache_key)
        if cached is not None:
            return list(cached)
        try:
            databases = await self._plesk.get_databases(auth, domain.webspace)
        except PleskError as exc:
            logger.warning("database listing failed for %s/%s: %s", login, domain.webspace, exc)
            databases = []
        await cache_set_json(self._redis, cache_key, databases, self._settings.plan_cache_ttl)
        return databases

    # ----------------------------------------------------------------- domains
    @staticmethod
    def resolve_domain(account: Account, name: str) -> DomainInfo:
        domain = account.find_domain(name)
        if domain is None:
            raise UnknownDomain(name)
        return domain
