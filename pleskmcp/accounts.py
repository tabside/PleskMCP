"""Customer accounts: login verification, domain mapping and liveness checks.

Three modes for the per-call status check (ACCOUNT_CHECK_MODE):

* customer_key: at login a Plesk secret key is created for the customer with
  the customer's own credentials and stored encrypted. Status checks and domain
  refreshes run in the customer's own context with that key.
* admin_key: an administrator secret key (read-only use) looks up the
  customer and its webspaces.
* login_only: no re-check after login; the domain list from login time is kept
  until the next login. Tokens still expire normally.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from cryptography.fernet import Fernet, InvalidToken

from .audit import AuditLog
from .config import Settings
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
from .store import AccountRow, Store

logger = logging.getLogger(__name__)


class LoginRejected(Exception):
    """The credentials were rejected. `reason` is a short machine readable code."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason
        self.message = message


class AccountInactive(Exception):
    pass


class UnknownDomain(Exception):
    pass


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


class AccountService:
    def __init__(self, settings: Settings, store: Store, plesk: PleskClient, audit: AuditLog):
        self._settings = settings
        self._store = store
        self._plesk = plesk
        self._audit = audit
        self._fernet = Fernet(settings.data_encryption_key.encode()) if settings.data_encryption_key else None

    # ------------------------------------------------------------------- helpers
    def _encrypt(self, value: str) -> str:
        assert self._fernet is not None
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def _decrypt(self, value: str) -> str | None:
        if self._fernet is None:
            return None
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except InvalidToken:
            return None

    @staticmethod
    def _to_account(row: AccountRow) -> Account:
        return Account(
            login=row.plesk_login,
            display_name=row.display_name,
            domains=[DomainInfo.from_dict(d) for d in row.domains],
        )

    # --------------------------------------------------------------------- login
    async def login(self, login: str, password: str, *, client_ip: str, client_id: str) -> Account:
        """Verify Plesk credentials, reject non-customers, store the domain mapping."""
        login = login.strip()
        if not login or not password:
            raise LoginRejected("invalid", "Benutzername und Passwort sind erforderlich.")
        try:
            info = await self._plesk.verify_customer(login, password)
        except PleskSystemError as exc:
            if exc.code == ERR_WRONG_CREDENTIALS:
                raise LoginRejected("credentials", "Benutzername oder Passwort ist falsch.") from exc
            if exc.code == ERR_ACCOUNT_SUSPENDED:
                raise LoginRejected("suspended", "Dieses Konto ist gesperrt.") from exc
            logger.warning("plesk system error during login: %s", exc)
            raise LoginRejected("plesk_error", "Anmeldung derzeit nicht möglich.") from exc
        except PleskResultError as exc:
            # 1013: admin/reseller (no customer with that login); 1006: additional user
            if exc.code in (ERR_PERMISSION_DENIED,):
                raise LoginRejected("not_customer", "Nur Kunden-Hauptlogins sind zugelassen.") from exc
            raise LoginRejected("not_customer", "Nur Kunden-Hauptlogins sind zugelassen.") from exc
        except PleskError as exc:
            logger.error("plesk api error during login: %s", exc)
            raise LoginRejected("plesk_error", "Anmeldung derzeit nicht möglich.") from exc

        creds = PasswordAuth(login, password)
        try:
            domains = await self._plesk.list_domains(creds)
        except PleskError as exc:
            logger.error("domain listing failed for %s: %s", login, exc)
            raise LoginRejected("plesk_error", "Anmeldung derzeit nicht möglich.") from exc

        secret_enc: str | None = None
        if self._settings.account_check_mode == "customer_key":
            secret_enc = await self._ensure_customer_key(login, creds)

        self._store.save_account(
            login,
            display_name=info.name or None,
            secret_key_enc=secret_enc,
            domains=[d.as_dict() for d in domains],
            status="active",
        )
        self._audit.write(
            "login_success",
            login=login,
            ip=client_ip,
            client=client_id,
            domains=[d.name for d in domains],
        )
        return Account(login=login, display_name=info.name or None, domains=domains)

    async def _ensure_customer_key(self, login: str, creds: PasswordAuth) -> str | None:
        """Reuse a stored, still working key or create a new one for this customer."""
        existing = self._store.get_account(login)
        if existing and existing.secret_key_enc:
            key = self._decrypt(existing.secret_key_enc)
            if key:
                try:
                    await self._plesk.get_customer(login, KeyAuth(key))
                    return None  # keep the stored value (COALESCE in save_account)
                except PleskError:
                    self._store.clear_account_secret(login)
        try:
            key = await self._plesk.create_secret_key(
                creds,
                ip_address=self._settings.customer_key_ip,
                description="PleskMCP connector",
            )
        except PleskResultError as exc:
            logger.error(
                "customer %s may not create a secret key (%s). Switch ACCOUNT_CHECK_MODE to admin_key or login_only.",
                login,
                exc,
            )
            raise LoginRejected("config", "Anmeldung derzeit nicht möglich (Serverkonfiguration).") from exc
        except PleskError as exc:
            raise LoginRejected("plesk_error", "Anmeldung derzeit nicht möglich.") from exc
        return self._encrypt(key)

    # ------------------------------------------------------------ status checks
    async def get_active_account(self, login: str) -> Account:
        """Account for a tool call. Re-validates against Plesk at most every ACCOUNT_CHECK_TTL seconds."""
        row = self._store.get_account(login)
        if row is None or row.status != "active":
            raise AccountInactive(login)
        if time.time() - row.checked_at < self._settings.account_check_ttl:
            return self._to_account(row)
        mode = self._settings.account_check_mode
        if mode == "login_only":
            self._store.update_account_check(login, status="active", domains=None)
            return self._to_account(row)
        try:
            if mode == "customer_key":
                domains = await self._check_with_customer_key(login, row)
            else:
                domains = await self._check_with_admin_key(login)
        except AccountInactive:
            self._deactivate(login, "status_check")
            raise
        except PleskError as exc:
            # Plesk unreachable: keep working with the cached mapping for a short grace period.
            logger.warning("status check for %s failed, using cached mapping: %s", login, exc)
            if time.time() - row.checked_at > self._settings.account_check_ttl * 10:
                self._deactivate(login, "status_check_unavailable")
                raise AccountInactive(login) from exc
            return self._to_account(row)
        self._store.update_account_check(login, status="active", domains=[d.as_dict() for d in domains])
        row = self._store.get_account(login)
        assert row is not None
        return self._to_account(row)

    async def _check_with_customer_key(self, login: str, row: AccountRow) -> list[DomainInfo]:
        key = self._decrypt(row.secret_key_enc) if row.secret_key_enc else None
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

    def _deactivate(self, login: str, reason: str) -> None:
        self._store.update_account_check(login, status="inactive", domains=None)
        revoked = self._store.revoke_login(login)
        self._audit.write("account_deactivated", login=login, reason=reason, tokens_revoked=revoked)

    # ---------------------------------------------------------------- revocation
    async def revoke_login(self, login: str, *, delete_secret_key: bool = True) -> int:
        """Revoke every token of a login and drop its stored secret key (CLI)."""
        revoked = self._store.revoke_login(login)
        row = self._store.get_account(login)
        if row and row.secret_key_enc and delete_secret_key:
            key = self._decrypt(row.secret_key_enc)
            if key:
                try:
                    await self._plesk.delete_secret_key(KeyAuth(key), key)
                except PleskError as exc:
                    logger.warning("could not delete Plesk secret key of %s: %s", login, exc)
            self._store.clear_account_secret(login)
        if row:
            self._store.update_account_check(login, status="inactive", domains=None)
        self._audit.write("tokens_revoked", login=login, tokens_revoked=revoked, source="cli")
        return revoked

    # ----------------------------------------------------------------- domains
    @staticmethod
    def resolve_domain(account: Account, name: str) -> DomainInfo:
        domain = account.find_domain(name)
        if domain is None:
            raise UnknownDomain(name)
        return domain
