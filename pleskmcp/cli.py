"""Operator CLI (run inside the container: `pleskmcp <command>`).

Commands:
  revoke --login LOGIN     revoke every token of one Plesk login (and drop its stored secret key)
  revoke --all             revoke every token
  accounts                 list known accounts
  clients                  list registered OAuth clients
  tokens                   list active tokens per login and client
  prune                    delete expired rows
  generate-key             print a new DATA_ENCRYPTION_KEY
  check                    check the Plesk API and (optionally) the SSH helper
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from cryptography.fernet import Fernet

from .config import ConfigError, Settings


def _services():
    from .server import build_services

    settings = Settings.load()
    return build_services(settings)


def cmd_revoke(args: argparse.Namespace) -> int:
    services = _services()
    if args.all:
        n = services.store.revoke_all()
        services.audit.write("tokens_revoked", login="*", tokens_revoked=n, source="cli")
        print(f"revoked {n} tokens")
        return 0
    n = asyncio.run(services.accounts.revoke_login(args.login))
    print(f"revoked {n} tokens of {args.login}")
    return 0


def cmd_accounts(args: argparse.Namespace) -> int:
    services = _services()
    for row in services.store.list_accounts():
        print(json.dumps(row))
    return 0


def cmd_clients(args: argparse.Namespace) -> int:
    services = _services()
    for row in services.store.list_clients():
        print(json.dumps(row))
    return 0


def cmd_tokens(args: argparse.Namespace) -> int:
    services = _services()
    for row in services.store.token_summary():
        print(json.dumps(row))
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    services = _services()
    print(json.dumps(services.store.prune()))
    return 0


def cmd_generate_key(args: argparse.Namespace) -> int:
    print(Fernet.generate_key().decode())
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    from .plesk_api import PasswordAuth, PleskSystemError

    services = _services()

    async def run() -> int:
        try:
            await services.plesk.call("<server><get><gen_info/></get></server>", PasswordAuth("pleskmcp-check", "x"))
        except PleskSystemError as exc:
            if exc.code == 1001:
                print("Plesk XML API reachable (test login rejected as expected)")
            else:
                print(f"Plesk XML API answered with system error {exc.code}: {exc.text}")
        except Exception as exc:  # noqa: BLE001
            print(f"Plesk XML API NOT reachable: {exc}")
            return 1
        if args.sysuser and args.docroot and args.domain:
            try:
                result = await services.executor.run(
                    args.sysuser,
                    {"v": 1, "op": "ping", "domain": args.domain, "docroot": args.docroot, "args": {}},
                )
                print(f"SSH helper OK: {json.dumps(result)}")
            except Exception as exc:  # noqa: BLE001
                print(f"SSH helper FAILED: {exc}")
                return 1
        return 0

    return asyncio.run(run())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="pleskmcp")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("revoke", help="revoke tokens")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--login")
    group.add_argument("--all", action="store_true")
    p.set_defaults(func=cmd_revoke)

    sub.add_parser("accounts").set_defaults(func=cmd_accounts)
    sub.add_parser("clients").set_defaults(func=cmd_clients)
    sub.add_parser("tokens").set_defaults(func=cmd_tokens)
    sub.add_parser("prune").set_defaults(func=cmd_prune)
    sub.add_parser("generate-key").set_defaults(func=cmd_generate_key)

    p = sub.add_parser("check", help="check Plesk API and SSH helper connectivity")
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
