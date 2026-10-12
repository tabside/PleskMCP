"""SQLite persistence: OAuth clients, pending authorizations, codes, tokens, accounts.

Tokens and authorization codes are stored as SHA-256 hashes only. Per-customer
Plesk secret keys (customer_key mode) are stored encrypted with Fernet.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                 -- 'dcr' or 'cimd'
    info_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    fetched_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_requests (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    params_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    plesk_login TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    redirect_uri_explicit INTEGER NOT NULL,
    resource TEXT,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS tokens (
    token_hash TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                 -- 'access' or 'refresh'
    client_id TEXT NOT NULL,
    plesk_login TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT,
    family_id TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    rotated INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tokens_login ON tokens(plesk_login);
CREATE INDEX IF NOT EXISTS tokens_family ON tokens(family_id);
CREATE TABLE IF NOT EXISTS accounts (
    plesk_login TEXT PRIMARY KEY,
    display_name TEXT,
    secret_key_enc TEXT,
    domains_json TEXT NOT NULL,
    status TEXT NOT NULL,               -- 'active' or 'inactive'
    checked_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    ip TEXT NOT NULL,
    login TEXT NOT NULL,
    success INTEGER NOT NULL,
    plesk_checked INTEGER NOT NULL      -- 1 if the attempt reached the Plesk API
);
CREATE INDEX IF NOT EXISTS login_attempts_ts ON login_attempts(ts);
"""


def hash_secret(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def new_token() -> str:
    # 256 bits of entropy, URL safe
    return secrets.token_urlsafe(32)


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


@dataclass
class AccountRow:
    plesk_login: str
    display_name: str | None
    secret_key_enc: str | None
    domains: list[dict[str, Any]]
    status: str
    checked_at: int


class Store:
    def __init__(self, path: str):
        self._path = path
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ clients
    def save_client(self, client_id: str, kind: str, info: dict[str, Any]) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "INSERT INTO clients(client_id, kind, info_json, created_at, fetched_at) VALUES (?,?,?,?,?) "
                "ON CONFLICT(client_id) DO UPDATE SET info_json=excluded.info_json, fetched_at=excluded.fetched_at",
                (client_id, kind, json.dumps(info), now, now),
            )

    def get_client(self, client_id: str) -> tuple[str, dict[str, Any], int] | None:
        with self._lock:
            row = self._conn.execute("SELECT kind, info_json, fetched_at FROM clients WHERE client_id=?", (client_id,)).fetchone()
        if row is None:
            return None
        return row["kind"], json.loads(row["info_json"]), int(row["fetched_at"])

    def list_clients(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute("SELECT client_id, kind, info_json, created_at FROM clients ORDER BY created_at").fetchall()
        result = []
        for row in rows:
            info = json.loads(row["info_json"])
            result.append(
                {
                    "client_id": row["client_id"],
                    "kind": row["kind"],
                    "client_name": info.get("client_name"),
                    "created_at": int(row["created_at"]),
                }
            )
        return result

    # ------------------------------------------------------------ auth requests
    def save_auth_request(self, request_id: str, client_id: str, params: dict[str, Any], ttl: int) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "INSERT INTO auth_requests(id, client_id, params_json, created_at, expires_at) VALUES (?,?,?,?,?)",
                (request_id, client_id, json.dumps(params), now, now + ttl),
            )

    def get_auth_request(self, request_id: str) -> tuple[str, dict[str, Any]] | None:
        now = int(time.time())
        with self._lock:
            row = self._conn.execute(
                "SELECT client_id, params_json FROM auth_requests WHERE id=? AND expires_at>?", (request_id, now)
            ).fetchone()
        if row is None:
            return None
        return row["client_id"], json.loads(row["params_json"])

    def delete_auth_request(self, request_id: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM auth_requests WHERE id=?", (request_id,))

    # --------------------------------------------------------------- auth codes
    def save_auth_code(
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
    ) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO auth_codes(code_hash, client_id, plesk_login, scopes, code_challenge, redirect_uri, "
                "redirect_uri_explicit, resource, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    hash_secret(code),
                    client_id,
                    plesk_login,
                    " ".join(scopes),
                    code_challenge,
                    redirect_uri,
                    1 if redirect_uri_explicit else 0,
                    resource,
                    int(time.time()) + ttl,
                ),
            )

    def get_auth_code(self, code: str) -> CodeRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM auth_codes WHERE code_hash=?", (hash_secret(code),)).fetchone()
        if row is None:
            return None
        return CodeRow(
            code_hash=row["code_hash"],
            client_id=row["client_id"],
            plesk_login=row["plesk_login"],
            scopes=row["scopes"].split(),
            code_challenge=row["code_challenge"],
            redirect_uri=row["redirect_uri"],
            redirect_uri_explicit=bool(row["redirect_uri_explicit"]),
            resource=row["resource"],
            expires_at=int(row["expires_at"]),
            used=bool(row["used"]),
        )

    def consume_auth_code(self, code_hash: str) -> bool:
        """Mark the code used. Returns False if it was already used (replay)."""
        with self._lock:
            cur = self._conn.execute("UPDATE auth_codes SET used=1 WHERE code_hash=? AND used=0", (code_hash,))
            return cur.rowcount == 1

    # ------------------------------------------------------------------- tokens
    def save_token(
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
        with self._lock:
            self._conn.execute(
                "INSERT INTO tokens(token_hash, kind, client_id, plesk_login, scopes, resource, family_id, expires_at, "
                "created_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (hash_secret(token), kind, client_id, plesk_login, " ".join(scopes), resource, family_id, now + ttl, now),
            )

    def get_token(self, token: str, kind: str) -> TokenRow | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM tokens WHERE token_hash=? AND kind=?", (hash_secret(token), kind)
            ).fetchone()
        if row is None:
            return None
        return TokenRow(
            token_hash=row["token_hash"],
            kind=row["kind"],
            client_id=row["client_id"],
            plesk_login=row["plesk_login"],
            scopes=row["scopes"].split(),
            resource=row["resource"],
            family_id=row["family_id"],
            expires_at=int(row["expires_at"]),
            revoked=bool(row["revoked"]),
            rotated=bool(row["rotated"]),
        )

    def mark_rotated(self, token_hash: str) -> bool:
        with self._lock:
            cur = self._conn.execute("UPDATE tokens SET rotated=1 WHERE token_hash=? AND rotated=0", (token_hash,))
            return cur.rowcount == 1

    def revoke_family(self, family_id: str) -> int:
        with self._lock:
            cur = self._conn.execute("UPDATE tokens SET revoked=1 WHERE family_id=? AND revoked=0", (family_id,))
            return cur.rowcount

    def revoke_login(self, plesk_login: str) -> int:
        with self._lock:
            cur = self._conn.execute("UPDATE tokens SET revoked=1 WHERE plesk_login=? AND revoked=0", (plesk_login,))
            return cur.rowcount

    def revoke_all(self) -> int:
        with self._lock:
            cur = self._conn.execute("UPDATE tokens SET revoked=1 WHERE revoked=0")
            return cur.rowcount

    def prune(self) -> dict[str, int]:
        now = int(time.time())
        with self._lock:
            a = self._conn.execute("DELETE FROM tokens WHERE expires_at<? OR revoked=1", (now - 86400,)).rowcount
            b = self._conn.execute("DELETE FROM auth_codes WHERE expires_at<?", (now - 3600,)).rowcount
            c = self._conn.execute("DELETE FROM auth_requests WHERE expires_at<?", (now,)).rowcount
            d = self._conn.execute("DELETE FROM login_attempts WHERE ts<?", (now - 7 * 86400,)).rowcount
        return {"tokens": a, "auth_codes": b, "auth_requests": c, "login_attempts": d}

    def token_summary(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT plesk_login, client_id, kind, COUNT(*) AS n, MAX(expires_at) AS last_exp FROM tokens "
                "WHERE revoked=0 AND expires_at>? GROUP BY plesk_login, client_id, kind ORDER BY plesk_login",
                (int(time.time()),),
            ).fetchall()
        return [dict(row) for row in rows]

    # ----------------------------------------------------------------- accounts
    def save_account(
        self,
        plesk_login: str,
        *,
        display_name: str | None,
        secret_key_enc: str | None,
        domains: list[dict[str, Any]],
        status: str,
    ) -> None:
        now = int(time.time())
        with self._lock:
            self._conn.execute(
                "INSERT INTO accounts(plesk_login, display_name, secret_key_enc, domains_json, status, checked_at, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?) "
                "ON CONFLICT(plesk_login) DO UPDATE SET display_name=excluded.display_name, "
                "secret_key_enc=COALESCE(excluded.secret_key_enc, accounts.secret_key_enc), "
                "domains_json=excluded.domains_json, status=excluded.status, checked_at=excluded.checked_at, "
                "updated_at=excluded.updated_at",
                (plesk_login, display_name, secret_key_enc, json.dumps(domains), status, now, now, now),
            )

    def update_account_check(self, plesk_login: str, *, status: str, domains: list[dict[str, Any]] | None) -> None:
        now = int(time.time())
        with self._lock:
            if domains is None:
                self._conn.execute(
                    "UPDATE accounts SET status=?, checked_at=?, updated_at=? WHERE plesk_login=?",
                    (status, now, now, plesk_login),
                )
            else:
                self._conn.execute(
                    "UPDATE accounts SET status=?, domains_json=?, checked_at=?, updated_at=? WHERE plesk_login=?",
                    (status, json.dumps(domains), now, now, plesk_login),
                )

    def clear_account_secret(self, plesk_login: str) -> None:
        with self._lock:
            self._conn.execute("UPDATE accounts SET secret_key_enc=NULL WHERE plesk_login=?", (plesk_login,))

    def get_account(self, plesk_login: str) -> AccountRow | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM accounts WHERE plesk_login=?", (plesk_login,)).fetchone()
        if row is None:
            return None
        return AccountRow(
            plesk_login=row["plesk_login"],
            display_name=row["display_name"],
            secret_key_enc=row["secret_key_enc"],
            domains=json.loads(row["domains_json"]),
            status=row["status"],
            checked_at=int(row["checked_at"]),
        )

    def list_accounts(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT plesk_login, display_name, status, checked_at, created_at, "
                "(secret_key_enc IS NOT NULL) AS has_key FROM accounts ORDER BY plesk_login"
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_account(self, plesk_login: str) -> None:
        with self._lock:
            self._conn.execute("DELETE FROM accounts WHERE plesk_login=?", (plesk_login,))

    # ------------------------------------------------------------ login attempts
    def record_login_attempt(self, *, ip: str, login: str, success: bool, plesk_checked: bool) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO login_attempts(ts, ip, login, success, plesk_checked) VALUES (?,?,?,?,?)",
                (int(time.time()), ip, login, 1 if success else 0, 1 if plesk_checked else 0),
            )

    def count_failures(self, *, since: int, ip: str | None = None, login: str | None = None, plesk_only: bool = False) -> int:
        sql = "SELECT COUNT(*) FROM login_attempts WHERE success=0 AND ts>=?"
        args: list[Any] = [since]
        if ip is not None:
            sql += " AND ip=?"
            args.append(ip)
        if login is not None:
            sql += " AND login=?"
            args.append(login)
        if plesk_only:
            sql += " AND plesk_checked=1"
        with self._lock:
            return int(self._conn.execute(sql, args).fetchone()[0])
