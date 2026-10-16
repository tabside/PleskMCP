"""Shared relational state (PostgreSQL in production, SQLite in tests) via SQLAlchemy 2 async.

Tables: OAuth clients, pending authorization requests, authorization codes,
tokens (hashed), customer accounts and login attempts. Tokens and codes are
stored as SHA-256 hashes only; per-customer Plesk secret keys are stored
Fernet-encrypted.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import Boolean, Index, Integer, String, Text, delete, func, select, text, update
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token() -> str:
    return secrets.token_urlsafe(32)


class Base(DeclarativeBase):
    pass


class ClientRow(Base):
    __tablename__ = "clients"
    client_id: Mapped[str] = mapped_column(String(512), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    info_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    fetched_at: Mapped[int] = mapped_column(Integer, nullable=False)


class AuthRequestRow(Base):
    __tablename__ = "auth_requests"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(512), nullable=False)
    params_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False)


class AuthCodeRow(Base):
    __tablename__ = "auth_codes"
    code_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    client_id: Mapped[str] = mapped_column(String(512), nullable=False)
    plesk_login: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(255), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(Text, nullable=False)
    redirect_uri_explicit: Mapped[bool] = mapped_column(Boolean, nullable=False)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    revoke_others: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class TokenRowModel(Base):
    __tablename__ = "tokens"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(8), nullable=False)
    client_id: Mapped[str] = mapped_column(String(512), nullable=False)
    plesk_login: Mapped[str] = mapped_column(String(255), nullable=False)
    scopes: Mapped[str] = mapped_column(Text, nullable=False)
    resource: Mapped[str | None] = mapped_column(Text, nullable=True)
    family_id: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    rotated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_used_at: Mapped[int | None] = mapped_column(Integer, nullable=True)
    __table_args__ = (Index("tokens_login", "plesk_login"), Index("tokens_family", "family_id"))


class AccountRowModel(Base):
    __tablename__ = "accounts"
    plesk_login: Mapped[str] = mapped_column(String(255), primary_key=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    secret_key_enc: Mapped[str | None] = mapped_column(Text, nullable=True)
    domains_json: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    checked_at: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[int] = mapped_column(Integer, nullable=False)


class DbCredentialRow(Base):
    __tablename__ = "db_credentials"
    plesk_login: Mapped[str] = mapped_column(String(255), primary_key=True)
    database: Mapped[str] = mapped_column(String(255), primary_key=True)
    db_user: Mapped[str] = mapped_column(String(255), nullable=False)
    password_enc: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(16), nullable=False, default="stored")  # stored (account page) | service (db_create)
    webspace: Mapped[str | None] = mapped_column(String(255), nullable=True)
    plesk_db_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    plesk_user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[int] = mapped_column(Integer, nullable=False)
    updated_at: Mapped[int] = mapped_column(Integer, nullable=False)


class LoginAttemptRow(Base):
    __tablename__ = "login_attempts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ts: Mapped[int] = mapped_column(Integer, nullable=False)
    ip: Mapped[str] = mapped_column(String(64), nullable=False)
    login: Mapped[str] = mapped_column(String(255), nullable=False)
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    plesk_checked: Mapped[bool] = mapped_column(Boolean, nullable=False)
    __table_args__ = (Index("login_attempts_ts", "ts"),)


# ------------------------------------------------------------------ value objects
@dataclass
class TokenRow:
    token_hash: str
    kind: str
    client_id: str
    plesk_login: str
    scopes: list[str]
    resource: str | None
    family_id: str
    expires_at: int
    revoked: bool
    rotated: bool
    last_used_at: int | None = None


@dataclass
class CodeRow:
    code_hash: str
    client_id: str
    plesk_login: str
    scopes: list[str]
    code_challenge: str
    redirect_uri: str
    redirect_uri_explicit: bool
    resource: str | None
    expires_at: int
    used: bool
    revoke_others: bool = False


@dataclass
class AccountRow:
    plesk_login: str
    display_name: str | None
    secret_key_enc: str | None
    domains: list[dict[str, Any]]
    status: str
    checked_at: int


def make_engine(database_url: str) -> AsyncEngine:
    kwargs: dict[str, Any] = {"pool_pre_ping": True}
    if database_url.startswith("sqlite"):
        kwargs = {}
    return create_async_engine(database_url, **kwargs)


class Store:
    def __init__(self, engine: AsyncEngine):
        self._engine = engine
        self._sessions = async_sessionmaker(engine, expire_on_commit=False)

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    async def create_all(self) -> None:
        """Create tables directly (tests and first start without Alembic)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def close(self) -> None:
        await self._engine.dispose()

    async def ping(self) -> bool:
        async with self._sessions() as session:
            await session.execute(text("SELECT 1"))
        return True

    # ------------------------------------------------------------------ clients
    async def save_client(self, client_id: str, kind: str, info: dict[str, Any]) -> None:
        now = int(time.time())
        async with self._sessions() as session:
            row = await session.get(ClientRow, client_id)
            if row is None:
                session.add(ClientRow(client_id=client_id, kind=kind, info_json=json.dumps(info), created_at=now, fetched_at=now))
            else:
                row.info_json = json.dumps(info)
                row.fetched_at = now
            await session.commit()

    async def get_client(self, client_id: str) -> tuple[str, dict[str, Any], int] | None:
        async with self._sessions() as session:
            row = await session.get(ClientRow, client_id)
        if row is None:
            return None
        return row.kind, json.loads(row.info_json), row.fetched_at

    async def list_clients(self) -> list[dict[str, Any]]:
        async with self._sessions() as session:
            rows = (await session.execute(select(ClientRow).order_by(ClientRow.created_at))).scalars().all()
        return [
            {"client_id": r.client_id, "kind": r.kind, "client_name": json.loads(r.info_json).get("client_name"), "created_at": r.created_at}
            for r in rows
        ]

    async def client_names(self, client_ids: list[str]) -> dict[str, str | None]:
        if not client_ids:
            return {}
        async with self._sessions() as session:
            rows = (await session.execute(select(ClientRow).where(ClientRow.client_id.in_(client_ids)))).scalars().all()
        return {r.client_id: json.loads(r.info_json).get("client_name") for r in rows}

    # ------------------------------------------------------------ auth requests
    async def save_auth_request(self, request_id: str, client_id: str, params: dict[str, Any], ttl: int) -> None:
        now = int(time.time())
        async with self._sessions() as session:
            session.add(AuthRequestRow(id=request_id, client_id=client_id, params_json=json.dumps(params), created_at=now, expires_at=now + ttl))
            await session.commit()

    async def get_auth_request(self, request_id: str) -> tuple[str, dict[str, Any]] | None:
        async with self._sessions() as session:
            row = await session.get(AuthRequestRow, request_id)
        if row is None or row.expires_at <= int(time.time()):
            return None
        return row.client_id, json.loads(row.params_json)

    async def delete_auth_request(self, request_id: str) -> None:
        async with self._sessions() as session:
            await session.execute(delete(AuthRequestRow).where(AuthRequestRow.id == request_id))
            await session.commit()

    # --------------------------------------------------------------- auth codes
    async def save_auth_code(
        self,
        code: str,
        *,
        client_id: str,
        plesk_login: str,
        scopes: list[str],
        code_challenge: str,
        redirect_uri: str,
        redirect_uri_explicit: bool,
        resource: str | None,
        ttl: int,
        revoke_others: bool = False,
    ) -> None:
        async with self._sessions() as session:
            session.add(
                AuthCodeRow(
                    code_hash=hash_secret(code),
                    client_id=client_id,
                    plesk_login=plesk_login,
                    scopes=" ".join(scopes),
                    code_challenge=code_challenge,
                    redirect_uri=redirect_uri,
                    redirect_uri_explicit=redirect_uri_explicit,
                    resource=resource,
                    expires_at=int(time.time()) + ttl,
                    used=False,
                    revoke_others=revoke_others,
                )
            )
            await session.commit()

    async def get_auth_code(self, code: str) -> CodeRow | None:
        async with self._sessions() as session:
            row = await session.get(AuthCodeRow, hash_secret(code))
        if row is None:
            return None
        return CodeRow(
            code_hash=row.code_hash,
            client_id=row.client_id,
            plesk_login=row.plesk_login,
            scopes=row.scopes.split(),
            code_challenge=row.code_challenge,
            redirect_uri=row.redirect_uri,
            redirect_uri_explicit=row.redirect_uri_explicit,
            resource=row.resource,
            expires_at=row.expires_at,
            used=row.used,
            revoke_others=bool(row.revoke_others),
        )

    async def consume_auth_code(self, code_hash: str) -> bool:
        async with self._sessions() as session:
            result = await session.execute(
                update(AuthCodeRow).where(AuthCodeRow.code_hash == code_hash, AuthCodeRow.used.is_(False)).values(used=True)
            )
            await session.commit()
            return result.rowcount == 1

    # ------------------------------------------------------------------- tokens
    async def save_token(
        self,
        token: str,
        *,
        kind: str,
        client_id: str,
        plesk_login: str,
        scopes: list[str],
        resource: str | None,
        family_id: str,
        ttl: int,
    ) -> None:
        now = int(time.time())
        async with self._sessions() as session:
            session.add(
                TokenRowModel(
                    token_hash=hash_secret(token),
                    kind=kind,
                    client_id=client_id,
                    plesk_login=plesk_login,
                    scopes=" ".join(scopes),
                    resource=resource,
                    family_id=family_id,
                    expires_at=now + ttl,
                    created_at=now,
                    revoked=False,
                    rotated=False,
                )
            )
            await session.commit()

    @staticmethod
    def _token(row: TokenRowModel) -> TokenRow:
        return TokenRow(
            token_hash=row.token_hash,
            kind=row.kind,
            client_id=row.client_id,
            plesk_login=row.plesk_login,
            scopes=row.scopes.split(),
            resource=row.resource,
            family_id=row.family_id,
            expires_at=row.expires_at,
            revoked=row.revoked,
            rotated=row.rotated,
            last_used_at=row.last_used_at,
        )

    async def get_token(self, token: str, kind: str) -> TokenRow | None:
        async with self._sessions() as session:
            row = await session.get(TokenRowModel, hash_secret(token))
        if row is None or row.kind != kind:
            return None
        return self._token(row)

    async def touch_token(self, token_hash: str, *, min_interval: int = 60) -> None:
        now = int(time.time())
        async with self._sessions() as session:
            await session.execute(
                update(TokenRowModel)
                .where(TokenRowModel.token_hash == token_hash)
                .where((TokenRowModel.last_used_at.is_(None)) | (TokenRowModel.last_used_at < now - min_interval))
                .values(last_used_at=now)
            )
            await session.commit()

    async def mark_rotated(self, token_hash: str) -> bool:
        async with self._sessions() as session:
            result = await session.execute(
                update(TokenRowModel).where(TokenRowModel.token_hash == token_hash, TokenRowModel.rotated.is_(False)).values(rotated=True)
            )
            await session.commit()
            return result.rowcount == 1

    async def revoke_family(self, family_id: str) -> int:
        async with self._sessions() as session:
            result = await session.execute(
                update(TokenRowModel).where(TokenRowModel.family_id == family_id, TokenRowModel.revoked.is_(False)).values(revoked=True)
            )
            await session.commit()
            return result.rowcount

    async def revoke_login(self, plesk_login: str, *, client_id: str | None = None, except_family: str | None = None) -> int:
        stmt = update(TokenRowModel).where(TokenRowModel.plesk_login == plesk_login, TokenRowModel.revoked.is_(False))
        if client_id is not None:
            stmt = stmt.where(TokenRowModel.client_id == client_id)
        if except_family is not None:
            stmt = stmt.where(TokenRowModel.family_id != except_family)
        async with self._sessions() as session:
            result = await session.execute(stmt.values(revoked=True))
            await session.commit()
            return result.rowcount

    async def revoke_all(self) -> int:
        async with self._sessions() as session:
            result = await session.execute(update(TokenRowModel).where(TokenRowModel.revoked.is_(False)).values(revoked=True))
            await session.commit()
            return result.rowcount

    async def prune(self) -> dict[str, int]:
        now = int(time.time())
        async with self._sessions() as session:
            a = (await session.execute(delete(TokenRowModel).where((TokenRowModel.expires_at < now - 86400) | (TokenRowModel.revoked.is_(True))))).rowcount
            b = (await session.execute(delete(AuthCodeRow).where(AuthCodeRow.expires_at < now - 3600))).rowcount
            c = (await session.execute(delete(AuthRequestRow).where(AuthRequestRow.expires_at < now))).rowcount
            d = (await session.execute(delete(LoginAttemptRow).where(LoginAttemptRow.ts < now - 7 * 86400))).rowcount
            await session.commit()
        return {"tokens": a, "auth_codes": b, "auth_requests": c, "login_attempts": d}

    async def token_summary(self) -> list[dict[str, Any]]:
        now = int(time.time())
        async with self._sessions() as session:
            rows = (
                await session.execute(
                    select(TokenRowModel.plesk_login, TokenRowModel.client_id, TokenRowModel.kind, func.count().label("n"), func.max(TokenRowModel.expires_at).label("last_exp"))
                    .where(TokenRowModel.revoked.is_(False), TokenRowModel.expires_at > now)
                    .group_by(TokenRowModel.plesk_login, TokenRowModel.client_id, TokenRowModel.kind)
                    .order_by(TokenRowModel.plesk_login)
                )
            ).all()
        return [{"plesk_login": r[0], "client_id": r[1], "kind": r[2], "n": r[3], "last_exp": r[4]} for r in rows]

    async def connections_for_login(self, plesk_login: str) -> list[dict[str, Any]]:
        """Active connections (clients) of a login with last use, for the /account page."""
        now = int(time.time())
        async with self._sessions() as session:
            rows = (
                await session.execute(
                    select(
                        TokenRowModel.client_id,
                        func.count(func.distinct(TokenRowModel.family_id)).label("families"),
                        func.max(TokenRowModel.last_used_at).label("last_used"),
                        func.min(TokenRowModel.created_at).label("since"),
                    )
                    .where(TokenRowModel.plesk_login == plesk_login, TokenRowModel.revoked.is_(False), TokenRowModel.expires_at > now)
                    .group_by(TokenRowModel.client_id)
                    .order_by(func.max(TokenRowModel.last_used_at).desc())
                )
            ).all()
        names = await self.client_names([r[0] for r in rows])
        return [
            {"client_id": r[0], "client_name": names.get(r[0]), "families": r[1], "last_used": r[2], "since": r[3]}
            for r in rows
        ]

    # ----------------------------------------------------------------- accounts
    async def save_account(
        self,
        plesk_login: str,
        *,
        display_name: str | None,
        secret_key_enc: str | None,
        domains: list[dict[str, Any]],
        status: str,
    ) -> None:
        now = int(time.time())
        async with self._sessions() as session:
            row = await session.get(AccountRowModel, plesk_login)
            if row is None:
                session.add(
                    AccountRowModel(
                        plesk_login=plesk_login,
                        display_name=display_name,
                        secret_key_enc=secret_key_enc,
                        domains_json=json.dumps(domains),
                        status=status,
                        checked_at=now,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                row.display_name = display_name
                if secret_key_enc is not None:
                    row.secret_key_enc = secret_key_enc
                row.domains_json = json.dumps(domains)
                row.status = status
                row.checked_at = now
                row.updated_at = now
            await session.commit()

    async def update_account_check(self, plesk_login: str, *, status: str, domains: list[dict[str, Any]] | None) -> None:
        now = int(time.time())
        values: dict[str, Any] = {"status": status, "checked_at": now, "updated_at": now}
        if domains is not None:
            values["domains_json"] = json.dumps(domains)
        async with self._sessions() as session:
            await session.execute(update(AccountRowModel).where(AccountRowModel.plesk_login == plesk_login).values(**values))
            await session.commit()

    async def clear_account_secret(self, plesk_login: str) -> None:
        async with self._sessions() as session:
            await session.execute(update(AccountRowModel).where(AccountRowModel.plesk_login == plesk_login).values(secret_key_enc=None))
            await session.commit()

    async def get_account(self, plesk_login: str) -> AccountRow | None:
        async with self._sessions() as session:
            row = await session.get(AccountRowModel, plesk_login)
        if row is None:
            return None
        return AccountRow(
            plesk_login=row.plesk_login,
            display_name=row.display_name,
            secret_key_enc=row.secret_key_enc,
            domains=json.loads(row.domains_json),
            status=row.status,
            checked_at=row.checked_at,
        )

    async def list_accounts(self, *, active_only: bool = False) -> list[dict[str, Any]]:
        stmt = select(AccountRowModel).order_by(AccountRowModel.plesk_login)
        if active_only:
            stmt = stmt.where(AccountRowModel.status == "active")
        async with self._sessions() as session:
            rows = (await session.execute(stmt)).scalars().all()
        return [
            {
                "plesk_login": r.plesk_login,
                "display_name": r.display_name,
                "status": r.status,
                "checked_at": r.checked_at,
                "created_at": r.created_at,
                "has_key": r.secret_key_enc is not None,
                "domains": json.loads(r.domains_json),
            }
            for r in rows
        ]

    async def delete_account(self, plesk_login: str) -> None:
        async with self._sessions() as session:
            await session.execute(delete(AccountRowModel).where(AccountRowModel.plesk_login == plesk_login))
            await session.commit()

    # ------------------------------------------------------------ db credentials
    async def save_db_credential(
        self,
        plesk_login: str,
        database: str,
        db_user: str,
        password_enc: str,
        *,
        source: str = "stored",
        webspace: str | None = None,
        plesk_db_id: int | None = None,
        plesk_user_id: int | None = None,
    ) -> None:
        now = int(time.time())
        async with self._sessions() as session:
            row = await session.get(DbCredentialRow, (plesk_login, database))
            if row is None:
                session.add(
                    DbCredentialRow(
                        plesk_login=plesk_login,
                        database=database,
                        db_user=db_user,
                        password_enc=password_enc,
                        source=source,
                        webspace=webspace,
                        plesk_db_id=plesk_db_id,
                        plesk_user_id=plesk_user_id,
                        created_at=now,
                        updated_at=now,
                    )
                )
            else:
                row.db_user = db_user
                row.password_enc = password_enc
                row.updated_at = now
                if row.source == "service" and source != "service":
                    # replacing the credentials of a service-created database keeps its origin
                    pass
                else:
                    row.source = source
                if webspace is not None:
                    row.webspace = webspace
                if plesk_db_id is not None:
                    row.plesk_db_id = plesk_db_id
                if plesk_user_id is not None:
                    row.plesk_user_id = plesk_user_id
            await session.commit()

    async def get_db_credential(self, plesk_login: str, database: str) -> tuple[str, str] | None:
        async with self._sessions() as session:
            row = await session.get(DbCredentialRow, (plesk_login, database))
        if row is None:
            return None
        return row.db_user, row.password_enc

    async def get_db_credential_row(self, plesk_login: str, database: str) -> dict[str, Any] | None:
        async with self._sessions() as session:
            row = await session.get(DbCredentialRow, (plesk_login, database))
        if row is None:
            return None
        return self._cred_dict(row, with_secret=True)

    @staticmethod
    def _cred_dict(r: DbCredentialRow, with_secret: bool = False) -> dict[str, Any]:
        data = {
            "database": r.database,
            "db_user": r.db_user,
            "source": r.source,
            "webspace": r.webspace,
            "plesk_db_id": r.plesk_db_id,
            "plesk_user_id": r.plesk_user_id,
            "created_at": r.created_at,
            "updated_at": r.updated_at,
        }
        if with_secret:
            data["password_enc"] = r.password_enc
        return data

    async def list_db_credentials(self, plesk_login: str, *, with_secret: bool = False) -> list[dict[str, Any]]:
        async with self._sessions() as session:
            rows = (await session.execute(select(DbCredentialRow).where(DbCredentialRow.plesk_login == plesk_login).order_by(DbCredentialRow.database))).scalars().all()
        return [self._cred_dict(r, with_secret) for r in rows]

    async def count_service_databases(self, plesk_login: str, webspace: str) -> int:
        async with self._sessions() as session:
            return int(
                (
                    await session.execute(
                        select(func.count()).select_from(DbCredentialRow).where(
                            DbCredentialRow.plesk_login == plesk_login, DbCredentialRow.webspace == webspace, DbCredentialRow.source == "service"
                        )
                    )
                ).scalar_one()
            )

    async def delete_db_credential(self, plesk_login: str, database: str | None = None) -> int:
        stmt = delete(DbCredentialRow).where(DbCredentialRow.plesk_login == plesk_login)
        if database is not None:
            stmt = stmt.where(DbCredentialRow.database == database)
        async with self._sessions() as session:
            result = await session.execute(stmt)
            await session.commit()
            return result.rowcount

    # ------------------------------------------------------------ login attempts
    async def record_login_attempt(self, *, ip: str, login: str, success: bool, plesk_checked: bool) -> None:
        async with self._sessions() as session:
            session.add(LoginAttemptRow(ts=int(time.time()), ip=ip[:64], login=login[:255], success=success, plesk_checked=plesk_checked))
            await session.commit()

    async def count_failures(self, *, since: int, ip: str | None = None, login: str | None = None, plesk_only: bool = False) -> int:
        stmt = select(func.count()).select_from(LoginAttemptRow).where(LoginAttemptRow.success.is_(False), LoginAttemptRow.ts >= since)
        if ip is not None:
            stmt = stmt.where(LoginAttemptRow.ip == ip)
        if login is not None:
            stmt = stmt.where(LoginAttemptRow.login == login)
        if plesk_only:
            stmt = stmt.where(LoginAttemptRow.plesk_checked.is_(True))
        async with self._sessions() as session:
            return int((await session.execute(stmt)).scalar_one())

    # ------------------------------------------------------------- bulk import
    async def import_rows(self, table: str, rows: list[dict[str, Any]]) -> int:
        """Used by `pleskmcp migrate-sqlite` to copy rows from the old SQLite store."""
        model = {
            "clients": ClientRow,
            "auth_requests": AuthRequestRow,
            "auth_codes": AuthCodeRow,
            "tokens": TokenRowModel,
            "accounts": AccountRowModel,
            "login_attempts": LoginAttemptRow,
            "db_credentials": DbCredentialRow,
        }[table]
        count = 0
        async with self._sessions() as session:
            for data in rows:
                data = {k: v for k, v in data.items() if hasattr(model, k)}
                for key in ("used", "revoked", "rotated", "success", "plesk_checked", "redirect_uri_explicit"):
                    if key in data and data[key] is not None:
                        data[key] = bool(data[key])
                await session.merge(model(**data))
                count += 1
            await session.commit()
        return count
