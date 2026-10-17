"""Operator CLI and service entry points (`pleskmcp <command>` inside the container).

Services:
  api                        MCP HTTP server, OAuth, /account page (stateless, scale by replicas)
  worker                     runs helper calls over SSH for queued jobs (scale by replicas)
  scheduler                  periodic maintenance, one active instance (Redis leader lock)

Operations:
  migrate                    apply Alembic migrations (run once per deploy, before api/worker)
  migrate-sqlite <path>      import clients, tokens, accounts and login attempts from the 0.1 SQLite file
  revoke --login LOGIN|--all revoke tokens (per login also drops the stored Plesk secret key)
  accounts | clients | tokens | connections --login LOGIN
  prune                      delete expired rows now
  report-ownership --domain X | --all   files in the docroot not owned by the system user (read-only helper op)
  generate-key               print a new DATA_ENCRYPTION_KEY
  signup-orders [--status S] orders of the self-signup (one JSON object per line, no tokens)
  check                      check Plesk API, database, Redis and (optionally) the SSH helper
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sqlite3
import sys
from typing import Any

from cryptography.fernet import Fernet

from .config import ConfigError, Settings


def _settings() -> Settings:
    return Settings.load()


# ------------------------------------------------------------------- services
def cmd_api(args: argparse.Namespace) -> int:
    from .logging_setup import configure_logging
    from .server import run_api

    configure_logging("api")
    run_api(_settings())
    return 0


def cmd_worker(args: argparse.Namespace) -> int:
    from .logging_setup import configure_logging
    from .queue import Worker
    from .remote import SSHPool
    from .server import build_core

    configure_logging("worker")
    settings = _settings()

    async def run() -> None:
        store, redis, audit, plesk, accounts, queue, limiter = build_core(settings)
        worker = Worker(settings, queue, redis, SSHPool(settings))
        worker.install_signal_handlers()
        try:
            await worker.run_forever()
        finally:
            await plesk.aclose()
            await redis.aclose()
            await store.close()

    asyncio.run(run())
    return 0


def cmd_scheduler(args: argparse.Namespace) -> int:
    from .logging_setup import configure_logging
    from .scheduler import Scheduler
    from .server import build_core

    configure_logging("scheduler")
    settings = _settings()

    async def run() -> None:
        from .signup.build import build_signup

        store, redis, audit, plesk, accounts, queue, limiter = build_core(settings)
        signup = build_signup(settings, store, redis, plesk, audit)
        scheduler = Scheduler(settings, store, redis, queue, accounts, signup)
        scheduler.install_signal_handlers()
        try:
            await scheduler.run_forever()
        finally:
            if signup is not None:
                await signup.aclose()
            await plesk.aclose()
            await redis.aclose()
            await store.close()

    asyncio.run(run())
    return 0


# ------------------------------------------------------------------ migration
def _alembic_config(settings: Settings) -> Any:
    from alembic.config import Config

    here = os.path.dirname(os.path.abspath(__file__))
    # alembic.ini only carries logging settings; the migrations ship inside the package
    candidates = [os.path.join(os.path.dirname(here), "alembic.ini"), os.path.join(os.getcwd(), "alembic.ini")]
    ini = next((c for c in candidates if os.path.isfile(c)), None)
    cfg = Config(ini) if ini else Config()
    cfg.set_main_option("script_location", os.path.join(here, "migrations"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)
    return cfg


def cmd_migrate(args: argparse.Namespace) -> int:
    from alembic import command

    settings = Settings.load(require_runtime=False)
    command.upgrade(_alembic_config(settings), args.revision)
    print("database schema is up to date")
    return 0


# Tables copied by migrate-sqlite. Column names are identical in both schemas; new
# columns (tokens.last_used_at, auth_codes.revoke_others) keep their defaults.
SQLITE_TABLES = ("clients", "tokens", "accounts", "login_attempts")


def cmd_migrate_sqlite(args: argparse.Namespace) -> int:
    """One-off import of the 0.1 SQLite store into Postgres. Auth codes and pending requests are not migrated."""
    from .db import Store, make_engine

    settings = Settings.load(require_runtime=False)
    if not os.path.isfile(args.path):
        print(f"not found: {args.path}", file=sys.stderr)
        return 2
    src = sqlite3.connect(f"file:{args.path}?mode=ro", uri=True)
    src.row_factory = sqlite3.Row

    async def run() -> int:
        store = Store(make_engine(settings.database_url))
        total = 0
        try:
            for table in SQLITE_TABLES:
                try:
                    cur = src.execute(f"SELECT * FROM {table}")
                except sqlite3.DatabaseError as exc:
                    print(f"{table}: skipped ({exc})")
                    continue
                columns = [d[0] for d in cur.description]
                rows: list[dict[str, Any]] = [dict(zip(columns, r)) for r in cur.fetchall()]
                if table == "login_attempts":
                    for row in rows:
                        row.pop("id", None)
                n = await store.import_rows(table, rows)
                total += n
                print(f"{table}: {n} rows imported")
        finally:
            await store.close()
        print(f"done, {total} rows")
        return 0

    return asyncio.run(run())


# ------------------------------------------------------------------ operators
def _core():
    from .server import build_core

    return build_core(_settings())


def cmd_revoke(args: argparse.Namespace) -> int:
    async def run() -> int:
        store, redis, audit, plesk, accounts, queue, limiter = _core()
        try:
            if args.all:
                n = await store.revoke_all()
                audit.write("tokens_revoked", login="*", tokens_revoked=n, source="cli")
                print(f"revoked {n} tokens")
            else:
                n = await accounts.revoke_login(args.login)
                print(f"revoked {n} tokens of {args.login}")
        finally:
            await plesk.aclose()
            await redis.aclose()
            await store.close()
        return 0

    return asyncio.run(run())


def _dump_rows(coro_factory) -> int:
    async def run() -> int:
        store, redis, audit, plesk, accounts, queue, limiter = _core()
        try:
            for row in await coro_factory(store):
                print(json.dumps(row))
        finally:
            await plesk.aclose()
            await redis.aclose()
            await store.close()
        return 0

    return asyncio.run(run())


def cmd_accounts(args: argparse.Namespace) -> int:
    return _dump_rows(lambda store: store.list_accounts())


def cmd_clients(args: argparse.Namespace) -> int:
    return _dump_rows(lambda store: store.list_clients())


def cmd_tokens(args: argparse.Namespace) -> int:
    return _dump_rows(lambda store: store.token_summary())


def cmd_connections(args: argparse.Namespace) -> int:
    return _dump_rows(lambda store: store.connections_for_login(args.login))


def cmd_prune(args: argparse.Namespace) -> int:
    async def run() -> int:
        store, redis, audit, plesk, accounts, queue, limiter = _core()
        try:
            print(json.dumps(await store.prune()))
        finally:
            await plesk.aclose()
            await redis.aclose()
            await store.close()
        return 0

    return asyncio.run(run())


def cmd_signup_orders(args: argparse.Namespace) -> int:
    from .signup.store import SignupStore
    from .signup.web import admin_json

    async def run() -> int:
        store, redis, audit, plesk, accounts, queue, limiter = _core()
        try:
            orders = await SignupStore(store.engine).list(status=args.status)
            if orders:
                print(admin_json(orders))
        finally:
            await plesk.aclose()
            await redis.aclose()
            await store.close()
        return 0

    return asyncio.run(run())


def cmd_generate_key(args: argparse.Namespace) -> int:
    print(Fernet.generate_key().decode())
    return 0


def cmd_report_ownership(args: argparse.Namespace) -> int:
    """Files and directories in a docroot that do not belong to the system user (read-only helper op, run directly over SSH)."""
    from .plesk_api import DomainInfo
    from .remote import HelperError, RemoteError, SSHPool

    async def run() -> int:
        store, redis, audit, plesk, accounts, queue, limiter = _core()
        settings = accounts._settings  # noqa: SLF001 - same object as _settings()
        pool = SSHPool(settings)
        rc = 0
        try:
            targets: list[tuple[str, DomainInfo]] = []
            for acc in await store.list_accounts(active_only=True):
                for raw in acc.get("domains") or []:
                    d = DomainInfo.from_dict(raw)
                    if d.status != 0:
                        continue
                    if args.all or d.name == args.domain.lower():
                        targets.append((acc["plesk_login"], d))
            if not targets:
                print("no matching active domain known to the service", file=sys.stderr)
                return 1
            for login, d in targets:
                request = {"v": 2, "op": "report_ownership", "domain": d.name, "docroot": d.docroot, "limits": dict(settings.helper_limits), "args": {}, "tool": "report_ownership"}
                request["limits"]["time_limit"] = settings.job_time_limit
                try:
                    result = await pool.run(d.sysuser, request, timeout=settings.job_time_limit + 10)
                except (HelperError, RemoteError) as exc:
                    print(json.dumps({"login": login, "domain": d.name, "error": str(exc)}))
                    rc = 1
                    continue
                print(json.dumps({"login": login, "domain": d.name, "webspace": d.webspace, **result}))
        finally:
            await pool.close()
            await plesk.aclose()
            await redis.aclose()
            await store.close()
        return rc

    return asyncio.run(run())


def cmd_check(args: argparse.Namespace) -> int:
    from .plesk_api import PasswordAuth, PleskSystemError
    from .remote import SSHPool

    async def run() -> int:
        store, redis, audit, plesk, accounts, queue, limiter = _core()
        rc = 0
        try:
            try:
                await plesk.call("<server><get><gen_info/></get></server>", PasswordAuth("pleskmcp-check", "x"))
            except PleskSystemError as exc:
                if exc.code == 1001:
                    print("Plesk XML API reachable (test login rejected as expected)")
                else:
                    print(f"Plesk XML API answered with system error {exc.code}: {exc.text}")
            except Exception as exc:  # noqa: BLE001
                print(f"Plesk XML API NOT reachable: {exc}")
                rc = 1
            try:
                print("database OK" if await store.ping() else "database NOT reachable")
            except Exception as exc:  # noqa: BLE001
                print(f"database NOT reachable: {exc}")
                rc = 1
            try:
                await redis.ping()
                print("redis OK")
            except Exception as exc:  # noqa: BLE001
                print(f"redis NOT reachable: {exc}")
                rc = 1
            pool = SSHPool(accounts._settings)  # noqa: SLF001
            try:
                ok, message = await pool.preflight()
                print(f"SSH preflight {'OK' if ok else 'FAILED'}: {message}")
                if not ok:
                    rc = 1
                if args.sysuser and args.docroot and args.domain:
                    try:
                        result = await pool.run(args.sysuser, {"v": 2, "op": "ping", "domain": args.domain, "docroot": args.docroot, "args": {}})
                        print(f"SSH helper OK: {json.dumps(result)}")
                    except Exception as exc:  # noqa: BLE001
                        print(f"SSH helper FAILED [{getattr(exc, 'code', 'error')}]: {exc}")
                        rc = 1
            finally:
                await pool.close()
        finally:
            await plesk.aclose()
            await redis.aclose()
            await store.close()
        return rc

    return asyncio.run(run())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pleskmcp")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("api", help="run the MCP HTTP api").set_defaults(func=cmd_api)
    sub.add_parser("worker", help="run a job worker (SSH helper calls)").set_defaults(func=cmd_worker)
    sub.add_parser("scheduler", help="run the scheduler (one active instance)").set_defaults(func=cmd_scheduler)

    p = sub.add_parser("migrate", help="apply database migrations")
    p.add_argument("revision", nargs="?", default="head")
    p.set_defaults(func=cmd_migrate)

    p = sub.add_parser("migrate-sqlite", help="import the 0.1 SQLite store")
    p.add_argument("path")
    p.set_defaults(func=cmd_migrate_sqlite)

    p = sub.add_parser("revoke", help="revoke tokens")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--login")
    group.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_revoke)

    sub.add_parser("accounts").set_defaults(func=cmd_accounts)
    sub.add_parser("clients").set_defaults(func=cmd_clients)
    sub.add_parser("tokens").set_defaults(func=cmd_tokens)
    p = sub.add_parser("connections", help="active connections of one login")
    p.add_argument("--login", required=True)
    p.set_defaults(func=cmd_connections)
    sub.add_parser("prune").set_defaults(func=cmd_prune)
    sub.add_parser("generate-key").set_defaults(func=cmd_generate_key)
    p = sub.add_parser("signup-orders", help="orders of the self-signup")
    p.add_argument("--status")
    p.set_defaults(func=cmd_signup_orders)

    p = sub.add_parser("report-ownership", help="files in a docroot not owned by the system user")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--domain")
    group.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_report_ownership)

    p = sub.add_parser("check", help="check Plesk API, database, Redis and SSH helper connectivity")
    p.add_argument("--sysuser")
    p.add_argument("--domain")
    p.add_argument("--docroot")
    p.set_defaults(func=cmd_check)

    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
