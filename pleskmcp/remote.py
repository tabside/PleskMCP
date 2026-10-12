"""Run the helper script on the Plesk server over SSH as the subscription's system user.

The SSH user is unprivileged. sudoers allows exactly one command:
`sudo -n -u <sysuser> /usr/local/bin/pleskmcp-helper` for members of the
psacln group. All parameters travel as JSON on stdin, never as arguments.
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


class RemoteError(Exception):
    """Transport problem (SSH) or helper crash."""


class HelperError(Exception):
    """The helper refused the operation. `code` is machine readable."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def validate_sysuser(sysuser: str) -> str:
    if not SYSUSER_RE.match(sysuser) or sysuser == "root":
        raise HelperError("bad_sysuser", "invalid system user name")
    return sysuser


class RemoteExecutor:
    def __init__(self, settings: Settings):
        self._settings = settings
        self._conn: asyncssh.SSHClientConnection | None = None
        self._lock = asyncio.Lock()

    def _known_hosts(self) -> Any:
        s = self._settings
        if s.ssh_known_hosts:
            return s.ssh_known_hosts
        assert s.ssh_host_key
        host = s.ssh_host if s.ssh_port == 22 else f"[{s.ssh_host}]:{s.ssh_port}"
        return asyncssh.import_known_hosts(f"{host} {s.ssh_host_key}\n")

    async def _connect(self) -> asyncssh.SSHClientConnection:
        s = self._settings
        try:
            return await asyncio.wait_for(
                asyncssh.connect(
                    s.ssh_host,
                    port=s.ssh_port,
                    username=s.ssh_user,
                    client_keys=[s.ssh_key_path],
                    known_hosts=self._known_hosts(),
                    agent_path=None,
                    keepalive_interval=30,
                ),
                timeout=s.ssh_timeout,
            )
        except (OSError, asyncssh.Error, asyncio.TimeoutError) as exc:
            raise RemoteError(f"SSH connection failed: {exc.__class__.__name__}: {exc}") from exc

    async def _get_conn(self) -> asyncssh.SSHClientConnection:
        if self._conn is not None and not self._conn.is_closed():
            return self._conn
        self._conn = await self._connect()
        return self._conn

    async def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    async def run(self, sysuser: str, request: dict[str, Any]) -> dict[str, Any]:
        validate_sysuser(sysuser)
        command = shlex.join(["sudo", "-n", "-u", sysuser, self._settings.helper_path])
        payload = json.dumps(request, ensure_ascii=False)
        async with self._lock:
            for attempt in (1, 2):
                conn = await self._get_conn()
                try:
                    result = await asyncio.wait_for(
                        conn.run(command, input=payload, check=False, encoding="utf-8"),
                        timeout=self._settings.ssh_timeout,
                    )
                    break
                except (asyncssh.Error, OSError, asyncio.TimeoutError) as exc:
                    await self.close()
                    if attempt == 2:
                        raise RemoteError(f"SSH command failed: {exc.__class__.__name__}") from exc
        stdout = result.stdout if isinstance(result.stdout, str) else ""
        stderr = result.stderr if isinstance(result.stderr, str) else ""
        if result.exit_status != 0 and not stdout.strip():
            logger.error("helper exited with %s: %s", result.exit_status, stderr.strip()[:500])
            if "sudo" in stderr and ("password" in stderr or "not allowed" in stderr):
                raise RemoteError("sudo refused the helper call; check the sudoers rule on the Plesk server")
            raise RemoteError(f"helper failed (exit {result.exit_status})")
        try:
            data = json.loads(stdout)
        except ValueError as exc:
            logger.error("helper returned invalid JSON: %s", stdout[:300])
            raise RemoteError("helper returned invalid output") from exc
        if not isinstance(data, dict):
            raise RemoteError("helper returned invalid output")
        if not data.get("ok"):
            raise HelperError(str(data.get("error", "helper_error")), str(data.get("message", "operation failed")))
        return data.get("result", {})
