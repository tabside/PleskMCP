"""Configuration from environment variables.

Nothing in here has defaults for secrets or hostnames. The HTTP server refuses
to start when a required variable is missing (see `Settings.load`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse

VALID_SCOPES = ["files:read", "files:write", "dns:read", "dns:write"]
ACCOUNT_CHECK_MODES = ("customer_key", "admin_key", "login_only")


class ConfigError(RuntimeError):
    pass


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    # Public URL of this service as seen by MCP clients, e.g. https://mcp.example.com/plesk
    public_base_url: str
    base_path: str  # "/plesk" or "" (derived from public_base_url)
    public_host: str  # "mcp.example.com" (derived)

    # Plesk XML API endpoint, e.g. https://plesk.example.com:8443
    plesk_url: str
    plesk_verify_ssl: bool
    plesk_timeout: float

    # SSH access to the Plesk server (dedicated unprivileged user, key only)
    ssh_host: str
    ssh_port: int
    ssh_user: str
    ssh_key_path: str
    ssh_host_key: str | None  # "ssh-ed25519 AAAA..." (type + base64, no hostname)
    ssh_known_hosts: str | None  # path to a known_hosts file
    ssh_timeout: float
    helper_path: str

    # Account status checks
    account_check_mode: str  # customer_key | admin_key | login_only
    account_check_ttl: int  # seconds a status check result is cached
    plesk_admin_api_key: str | None  # admin_key mode only
    customer_key_ip: str | None  # IP the per-customer secret keys are bound to (customer_key mode)
    data_encryption_key: str | None  # Fernet key for secret keys at rest (customer_key mode)

    # Storage
    data_dir: str
    audit_log_file: str

    # Token lifetimes (seconds)
    access_token_ttl: int
    refresh_token_ttl: int
    auth_code_ttl: int
    auth_request_ttl: int

    # Limits
    read_max_bytes: int
    write_max_bytes: int
    list_max_entries: int
    log_max_lines: int

    # Login rate limits
    login_fail_limit_ip: int
    login_fail_limit_login: int
    login_fail_window: int
    plesk_fail_budget: int  # max failed Plesk authentications per window from this service
    plesk_fail_budget_window: int

    # HTTP bind
    host: str
    port: int

    # Name shown to customers on the login page
    service_name: str

    valid_scopes: list[str] = field(default_factory=lambda: list(VALID_SCOPES))

    @property
    def resource_url(self) -> str:
        return self.public_base_url + "/mcp"

    @property
    def issuer_url(self) -> str:
        return self.public_base_url

    @property
    def db_path(self) -> str:
        return os.path.join(self.data_dir, "pleskmcp.sqlite3")

    @staticmethod
    def load(*, require_runtime: bool = True) -> "Settings":
        missing: list[str] = []

        def req(name: str) -> str:
            value = _env(name)
            if value is None:
                missing.append(name)
                return ""
            return value

        public_base_url = req("PUBLIC_BASE_URL").rstrip("/")
        plesk_url = req("PLESK_URL").rstrip("/")
        ssh_host = req("PLESK_SSH_HOST")
        ssh_user = req("PLESK_SSH_USER")
        ssh_key_path = req("PLESK_SSH_KEY_PATH")
        ssh_host_key = _env("PLESK_SSH_HOST_KEY")
        ssh_known_hosts = _env("PLESK_SSH_KNOWN_HOSTS")
        mode = _env("ACCOUNT_CHECK_MODE", "customer_key") or "customer_key"
        admin_key = _env("PLESK_ADMIN_API_KEY")
        enc_key = _env("DATA_ENCRYPTION_KEY")

        if require_runtime:
            if not ssh_host_key and not ssh_known_hosts:
                missing.append("PLESK_SSH_HOST_KEY or PLESK_SSH_KNOWN_HOSTS")
            if mode not in ACCOUNT_CHECK_MODES:
                raise ConfigError(f"ACCOUNT_CHECK_MODE must be one of {ACCOUNT_CHECK_MODES}, got {mode!r}")
            if mode == "admin_key" and not admin_key:
                missing.append("PLESK_ADMIN_API_KEY (required for ACCOUNT_CHECK_MODE=admin_key)")
            if mode == "customer_key" and not enc_key:
                missing.append("DATA_ENCRYPTION_KEY (required for ACCOUNT_CHECK_MODE=customer_key)")
            if missing:
                raise ConfigError("Missing required environment variables: " + ", ".join(missing))

        parsed = urlparse(public_base_url or "https://localhost")
        if require_runtime:
            if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
                raise ConfigError("PUBLIC_BASE_URL must use https")
            if parsed.query or parsed.fragment:
                raise ConfigError("PUBLIC_BASE_URL must not contain a query string or fragment")
        base_path = parsed.path.rstrip("/")
        if base_path and not base_path.startswith("/"):
            base_path = "/" + base_path
        public_host = parsed.netloc

        data_dir = _env("DATA_DIR", "/data") or "/data"
        return Settings(
            public_base_url=public_base_url,
            base_path=base_path,
            public_host=public_host,
            plesk_url=plesk_url,
            plesk_verify_ssl=_env_bool("PLESK_VERIFY_SSL", True),
            plesk_timeout=float(_env_int("PLESK_TIMEOUT", 20)),
            ssh_host=ssh_host,
            ssh_port=_env_int("PLESK_SSH_PORT", 22),
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
            ssh_host_key=ssh_host_key,
            ssh_known_hosts=ssh_known_hosts,
            ssh_timeout=float(_env_int("PLESK_SSH_TIMEOUT", 60)),
            helper_path=_env("PLESK_HELPER_PATH", "/usr/local/bin/pleskmcp-helper") or "/usr/local/bin/pleskmcp-helper",
            account_check_mode=mode,
            account_check_ttl=_env_int("ACCOUNT_CHECK_TTL", 60),
            plesk_admin_api_key=admin_key,
            customer_key_ip=_env("CUSTOMER_KEY_IP"),
            data_encryption_key=enc_key,
            data_dir=data_dir,
            audit_log_file=_env("AUDIT_LOG_FILE", os.path.join(data_dir, "audit.log")) or "",
            access_token_ttl=_env_int("ACCESS_TOKEN_TTL", 1800),
            refresh_token_ttl=_env_int("REFRESH_TOKEN_TTL", 30 * 24 * 3600),
            auth_code_ttl=_env_int("AUTH_CODE_TTL", 300),
            auth_request_ttl=_env_int("AUTH_REQUEST_TTL", 600),
            read_max_bytes=_env_int("READ_MAX_BYTES", 2 * 1024 * 1024),
            write_max_bytes=_env_int("WRITE_MAX_BYTES", 5 * 1024 * 1024),
            list_max_entries=_env_int("LIST_MAX_ENTRIES", 2000),
            log_max_lines=_env_int("LOG_MAX_LINES", 500),
            login_fail_limit_ip=_env_int("LOGIN_FAIL_LIMIT_IP", 10),
            login_fail_limit_login=_env_int("LOGIN_FAIL_LIMIT_LOGIN", 5),
            login_fail_window=_env_int("LOGIN_FAIL_WINDOW", 900),
            plesk_fail_budget=_env_int("PLESK_FAIL_BUDGET", 4),
            plesk_fail_budget_window=_env_int("PLESK_FAIL_BUDGET_WINDOW", 600),
            host=_env("MCP_HOST", "0.0.0.0") or "0.0.0.0",
            port=_env_int("MCP_PORT", 8000),
            service_name=_env("SERVICE_NAME", "Plesk Files MCP") or "Plesk Files MCP",
        )
