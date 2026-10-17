"""Run the helper script on the Plesk server over SSH as the subscription's system user.

The SSH user is unprivileged. sudoers allows exactly one command:
`sudo -n -u <sysuser> /usr/local/bin/pleskmcp-helper` for members of the
psacln group. All parameters travel as JSON on stdin, never as arguments.

`SSHPool` keeps one connection per worker and runs several helper calls as
parallel channels on it (asyncssh multiplexes sessions). A timed out call
closes its channel; the helper additionally enforces its own time limit.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shlex
from typing import Any

import asyncssh

from .config import Settings

logger = logging.getLogger(__name__)

SYSUSER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
_SUDO_REFUSED = re.compile(r"a password is required|not allowed to execute|command not allowed|sudo: .*not permitted|sudoers", re.I)


class RemoteError(Exception):
    """Transport problem (SSH) or helper crash.

    `code` is machine readable and reaches the client (never the message, which
    may name files or hosts): ssh_config (key or host key unusable), ssh_auth
    (server refused the key), ssh_unreachable (connection failed or timed out),
    sudo_refused (sudoers rule missing), helper_crash (no valid JSON from the
    helper), helper_timeout.
    """

    def __init__(self, message: str, code: str = "ssh_unreachable"):
        super().__init__(message)
        self.code = code


class HelperError(Exception):
    """The helper refused the operation. `code` is machine readable."""

    def __init__(self, code: str, message: str, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details or {}


def validate_sysuser(sysuser: str) -> str:
    if not SYSUSER_RE.match(sysuser) or sysuser == "root":
        raise HelperError("bad_sysuser", "invalid system user name")
    return sysuser


def parse_helper_output(stdout: str, stderr: str, exit_status: int | None) -> dict[str, Any]:
    if not stdout.strip():
        logger.error("helper exited with %s without output: %s", exit_status, stderr.strip()[:500])
        if _SUDO_REFUSED.search(stderr):
            raise RemoteError("sudo refused the helper call; check the sudoers rule on the Plesk server", "sudo_refused")
        raise RemoteError(f"helper failed (exit {exit_status}) without output", "helper_crash")
    try:
        data = json.loads(stdout)
    except ValueError as exc:
        logger.error("helper returned invalid JSON (exit %s): %s", exit_status, stdout[:300])
        raise RemoteError("helper returned invalid output", "helper_crash") from exc
    if not isinstance(data, dict):
        raise RemoteError("helper returned invalid output", "helper_crash")
    if not data.get("ok"):
        details = data.get("details") if isinstance(data.get("details"), dict) else None
        raise HelperError(str(data.get("error", "helper_error")), str(data.get("message", "operation failed")), details)
    return data.get("result", {})


class SSHPool:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._conn: asyncssh.SSHClientConnection | None = None
        self._connect_lock = asyncio.Lock()

    def _known_hosts(self) -> Any:
        s = self._settings
        if s.ssh_known_hosts:
            return s.ssh_known_hosts
        if not s.ssh_host_key:
            raise RemoteError("neither PLESK_SSH_HOST_KEY nor PLESK_SSH_KNOWN_HOSTS is set", "ssh_config")
        host = s.ssh_host if s.ssh_port == 22 else f"[{s.ssh_host}]:{s.ssh_port}"
        try:
            asyncssh.import_public_key(s.ssh_host_key)  # known_hosts parsing is lazy; validate the key itself now
            return asyncssh.import_known_hosts(f"{host} {s.ssh_host_key}\n")
        except (ValueError, asyncssh.Error) as exc:
            raise RemoteError(f"PLESK_SSH_HOST_KEY is not usable: {exc.__class__.__name__}: {exc}", "ssh_config") from exc

    def _client_keys(self) -> list[Any]:
        """Load the private key up front so a missing, unreadable or passphrase-protected key is reported as ssh_config."""
        path = self._settings.ssh_key_path
        try:
            return [asyncssh.read_private_key(path)]
        except (asyncssh.KeyImportError, asyncssh.KeyEncryptionError, ValueError) as exc:
            raise RemoteError(f"SSH private key at PLESK_SSH_KEY_PATH cannot be used: {exc.__class__.__name__}: {exc}", "ssh_config") from exc
        except OSError as exc:
            raise RemoteError(f"SSH private key at PLESK_SSH_KEY_PATH cannot be read: {exc.__class__.__name__}: {exc.strerror or exc}", "ssh_config") from exc

    async def preflight(self) -> tuple[bool, str]:
        """Check key file and host key without connecting. Returns (ok, operator message without secrets)."""
        try:
            self._client_keys()
            self._known_hosts()
        except RemoteError as exc:
            return False, f"[{exc.code}] {exc}"
        return True, "ssh key and host key loaded"

    async def _connect(self) -> asyncssh.SSHClientConnection:
        s = self._settings
        client_keys = self._client_keys()
        known_hosts = self._known_hosts()
        try:
            return await asyncio.wait_for(
                asyncssh.connect(
                    s.ssh_host,
                    port=s.ssh_port,
                    username=s.ssh_user,
                    client_keys=client_keys,
                    known_hosts=known_hosts,
                    agent_path=None,
                    keepalive_interval=30,
                ),
                timeout=s.ssh_timeout,
            )
        except asyncssh.PermissionDenied as exc:
            raise RemoteError(f"SSH authentication as {s.ssh_user} refused: {exc}", "ssh_auth") from exc
        except (asyncssh.HostKeyNotVerifiable, asyncssh.KeyExchangeFailed) as exc:
            raise RemoteError(f"SSH host key check failed: {exc.__class__.__name__}: {exc}", "ssh_config") from exc
        except (OSError, asyncssh.Error, asyncio.TimeoutError, ValueError) as exc:
            raise RemoteError(f"SSH connection failed: {exc.__class__.__name__}: {exc}", "ssh_unreachable") from exc

    async def _get_conn(self) -> asyncssh.SSHClientConnection:
        async with self._connect_lock:
            if self._conn is None or self._conn.is_closed():
                self._conn = await self._connect()
            return self._conn

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    async def run(self, sysuser: str, request: dict[str, Any], *, timeout: float | None = None) -> dict[str, Any]:
        validate_sysuser(sysuser)
        command = shlex.join(["sudo", "-n", "-u", sysuser, self._settings.helper_path])
        payload = json.dumps(request, ensure_ascii=False)
        timeout = timeout or self._settings.ssh_timeout
        last_exc: Exception | None = None
        for attempt in (1, 2):
            conn = await self._get_conn()
            process: asyncssh.SSHClientProcess[str] | None = None
            try:
                process = await conn.create_process(command, encoding="utf-8")
                process.stdin.write(payload)
                process.stdin.write_eof()
                result = await asyncio.wait_for(process.wait(), timeout=timeout)
                return parse_helper_output(result.stdout or "", result.stderr or "", result.exit_status)
            except asyncio.TimeoutError as exc:
                if process is not None:
                    process.kill()
                    process.close()
                raise RemoteError(f"helper call timed out after {timeout}s", "helper_timeout") from exc
            except (asyncssh.Error, OSError, ValueError) as exc:
                last_exc = exc
                await self.close()
                if attempt == 2:
                    raise RemoteError(f"SSH command failed: {exc.__class__.__name__}", "ssh_unreachable") from exc
        raise RemoteError(f"SSH command failed: {last_exc}", "ssh_unreachable")  # pragma: no cover


# Backwards compatible name used by the CLI check command.
RemoteExecutor = SSHPool
