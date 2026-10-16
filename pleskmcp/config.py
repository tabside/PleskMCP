"""Configuration from environment variables.

Nothing in here has defaults for secrets or hostnames. The services refuse to
start when a required variable is missing (see `Settings.load`).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

VALID_SCOPES = ["files:read", "files:write", "dns:read", "dns:write", "db:read", "db:write", "db:admin"]
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


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if raw is None:
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None:
        return default
    return raw.lower() in ("1", "true", "yes", "on")


DEFAULT_PROTECTED_FILES = [
    "wp-config.php",
    ".env",
    ".env.*",
    "config/database.php",
    "configuration.php",
    "app/etc/env.php",
    "*.pem",
    "*.key",
    ".htpasswd",
    ".git/config",
]
DEFAULT_DB_CONFIG_SOURCES = ["wp-config.php", ".env", "configuration.php", "app/etc/env.php", "config/database.php"]
DEFAULT_DB_REDACT_COLUMNS = ["user_pass", "password", "passwd", "pass", "api_key", "apikey", "secret", "token", "access_token", "refresh_token", "private_key", "auth_key", "salt"]


def _env_list(name: str, default: list[str]) -> list[str]:
    raw = _env(name)
    if raw is None:
        return list(default)
    return [item.strip() for item in raw.split(",") if item.strip()]


def _load_profiles_env() -> str | None:
    path = _env("ACCESS_PROFILES_FILE")
    if path:
        try:
            with open(path, encoding="utf-8") as fh:
                return fh.read()
        except OSError as exc:
            raise ConfigError(f"ACCESS_PROFILES_FILE cannot be read: {exc}") from exc
    return _env("ACCESS_PROFILES")


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
    ssh_max_concurrency: int  # parallel helper runs per worker
    helper_path: str

    # Shared state
    database_url: str  # postgresql+asyncpg://user:pass@postgres/pleskmcp
    redis_url: str  # redis://:password@redis:6379/0

    # Account status checks
    account_check_mode: str  # customer_key | admin_key | login_only
    account_check_ttl: int  # seconds a status check result is cached
    plesk_admin_api_key: str | None  # admin_key mode, optionally plan-name resolution
    customer_key_ip: str | None  # IP the per-customer secret keys are bound to (customer_key mode)
    data_encryption_key: str | None  # Fernet key for secret keys at rest (customer_key mode)

    # Access profiles per Plesk service plan / add-on (see profiles.py)
    profiles: dict[str, Any]
    plan_cache_ttl: int

    # Secret protection and database access
    protected_files: list[str]
    db_config_sources: list[str]
    db_redact_columns: list[str]
    db_max_rows: int
    db_max_affected_rows: int
    db_query_time_limit: int
    max_databases_created: int
    db_management_enabled: bool  # db_create / db_drop via the Plesk XML API (see README, verification)

    # Storage
    data_dir: str
    audit_log_file: str

    # Token lifetimes (seconds)
    access_token_ttl: int
    refresh_token_ttl: int
    auth_code_ttl: int
    auth_request_ttl: int
    account_session_ttl: int

    # Limits
    read_max_bytes: int
    write_max_bytes: int
    list_max_entries: int
    log_max_lines: int
    log_max_scan_bytes: int
    backup_max_file_bytes: int

    # Jobs
    tool_sync_wait: float
    job_result_ttl: int
    login_max_concurrency: int
    helper_time_limit: int
    job_time_limit: int

    # Per-login tool rate limits
    tool_calls_per_minute: int
    tool_writes_per_minute: int
    write_bytes_per_hour: int

    # Retention / quota
    trash_retention_days: int
    backup_retention_days: int
    backup_min_keep_days: int
    store_max_percent: int
    store_max_bytes: int
    retention_interval_hours: int
    quota_cache_ttl: int

    # Login rate limits
    login_fail_limit_ip: int
    login_fail_limit_login: int
    login_fail_window: int
    plesk_fail_budget: int  # max failed Plesk authentications per window from this service; 0 disables
    plesk_fail_budget_window: int

    # HTTP bind
    host: str
    port: int
    trusted_proxies: str
    metrics_enabled: bool

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
    def helper_limits(self) -> dict[str, int]:
        """Limits handed to the helper with every request."""
        return {
            "read_max_bytes": self.read_max_bytes,
            "write_max_bytes": self.write_max_bytes,
            "list_max_entries": self.list_max_entries,
            "log_max_lines": self.log_max_lines,
            "log_max_scan_bytes": self.log_max_scan_bytes,
            "backup_max_file_bytes": self.backup_max_file_bytes,
            "trash_retention_days": self.trash_retention_days,
            "backup_retention_days": self.backup_retention_days,
            "backup_min_keep_days": self.backup_min_keep_days,
            "store_max_percent": self.store_max_percent,
            "store_max_bytes": self.store_max_bytes,
            "time_limit": self.helper_time_limit,
            "protected_files": list(self.protected_files),
            "db_config_sources": list(self.db_config_sources),
            "db_redact_columns": list(self.db_redact_columns),
            "db_max_rows": self.db_max_rows,
            "db_max_affected_rows": self.db_max_affected_rows,
            "db_query_time_limit": self.db_query_time_limit,
        }

    @property
    def profile_defaults(self) -> dict[str, int]:
        return {
            "store_max_percent": self.store_max_percent,
            "store_max_bytes": self.store_max_bytes,
            "backup_retention_days": self.backup_retention_days,
            "trash_retention_days": self.trash_retention_days,
            "tool_calls_per_minute": self.tool_calls_per_minute,
            "tool_writes_per_minute": self.tool_writes_per_minute,
            "write_bytes_per_hour": self.write_bytes_per_hour,
            "max_databases_created": self.max_databases_created,
        }

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
        database_url = req("DATABASE_URL")
        redis_url = req("REDIS_URL")
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

        from .profiles import ProfileError, parse_profiles

        try:
            profiles = parse_profiles(_load_profiles_env())
        except ProfileError as exc:
            raise ConfigError(str(exc)) from exc

        data_dir = _env("DATA_DIR", "/data") or "/data"
        return Settings(
            public_base_url=public_base_url,
            base_path=base_path,
            public_host=public_host,
            plesk_url=plesk_url,
            plesk_verify_ssl=_env_bool("PLESK_VERIFY_SSL", True),
            plesk_timeout=_env_float("PLESK_TIMEOUT", 20),
            ssh_host=ssh_host,
            ssh_port=_env_int("PLESK_SSH_PORT", 22),
            ssh_user=ssh_user,
            ssh_key_path=ssh_key_path,
            ssh_host_key=ssh_host_key,
            ssh_known_hosts=ssh_known_hosts,
            ssh_timeout=_env_float("PLESK_SSH_TIMEOUT", 60),
            ssh_max_concurrency=_env_int("SSH_MAX_CONCURRENCY", 8),
            helper_path=_env("PLESK_HELPER_PATH", "/usr/local/bin/pleskmcp-helper") or "/usr/local/bin/pleskmcp-helper",
            database_url=database_url,
            redis_url=redis_url,
            account_check_mode=mode,
            account_check_ttl=_env_int("ACCOUNT_CHECK_TTL", 60),
            plesk_admin_api_key=admin_key,
            customer_key_ip=_env("CUSTOMER_KEY_IP"),
            data_encryption_key=enc_key,
            profiles=profiles,
            plan_cache_ttl=_env_int("PLAN_CACHE_TTL", 600),
            protected_files=_env_list("PROTECTED_FILES", DEFAULT_PROTECTED_FILES),
            db_config_sources=_env_list("DB_CONFIG_SOURCES", DEFAULT_DB_CONFIG_SOURCES),
            db_redact_columns=_env_list("DB_REDACT_COLUMNS", DEFAULT_DB_REDACT_COLUMNS),
            db_max_rows=_env_int("DB_MAX_ROWS", 500),
            db_max_affected_rows=_env_int("DB_MAX_AFFECTED_ROWS", 1000),
            db_query_time_limit=_env_int("DB_QUERY_TIME_LIMIT", 20),
            max_databases_created=_env_int("MAX_DATABASES_CREATED", 3),
            db_management_enabled=_env_bool("DB_MANAGEMENT_ENABLED", False),
            data_dir=data_dir,
            audit_log_file=_env("AUDIT_LOG_FILE", os.path.join(data_dir, "audit.log")) or "",
            access_token_ttl=_env_int("ACCESS_TOKEN_TTL", 1800),
            refresh_token_ttl=_env_int("REFRESH_TOKEN_TTL", 30 * 24 * 3600),
            auth_code_ttl=_env_int("AUTH_CODE_TTL", 300),
            auth_request_ttl=_env_int("AUTH_REQUEST_TTL", 600),
            account_session_ttl=_env_int("ACCOUNT_SESSION_TTL", 900),
            read_max_bytes=_env_int("READ_MAX_BYTES", 2 * 1024 * 1024),
            write_max_bytes=_env_int("WRITE_MAX_BYTES", 5 * 1024 * 1024),
            list_max_entries=_env_int("LIST_MAX_ENTRIES", 2000),
            log_max_lines=_env_int("LOG_MAX_LINES", 500),
            log_max_scan_bytes=_env_int("LOG_MAX_SCAN_BYTES", 200 * 1024 * 1024),
            backup_max_file_bytes=_env_int("BACKUP_MAX_FILE_BYTES", 20 * 1024 * 1024),
            tool_sync_wait=_env_float("TOOL_SYNC_WAIT", 25),
            job_result_ttl=_env_int("JOB_RESULT_TTL", 3600),
            login_max_concurrency=_env_int("LOGIN_MAX_CONCURRENCY", 2),
            helper_time_limit=_env_int("HELPER_TIME_LIMIT", 30),
            job_time_limit=_env_int("JOB_TIME_LIMIT", 300),
            tool_calls_per_minute=_env_int("TOOL_CALLS_PER_MINUTE", 60),
            tool_writes_per_minute=_env_int("TOOL_WRITES_PER_MINUTE", 30),
            write_bytes_per_hour=_env_int("WRITE_BYTES_PER_HOUR", 200 * 1024 * 1024),
            trash_retention_days=_env_int("TRASH_RETENTION_DAYS", 30),
            backup_retention_days=_env_int("BACKUP_RETENTION_DAYS", 30),
            backup_min_keep_days=_env_int("BACKUP_MIN_KEEP_DAYS", 7),
            store_max_percent=_env_int("STORE_MAX_PERCENT", 10),
            store_max_bytes=_env_int("STORE_MAX_BYTES", 1024 * 1024 * 1024),
            retention_interval_hours=_env_int("RETENTION_INTERVAL_HOURS", 6),
            quota_cache_ttl=_env_int("QUOTA_CACHE_TTL", 600),
            login_fail_limit_ip=_env_int("LOGIN_FAIL_LIMIT_IP", 10),
            login_fail_limit_login=_env_int("LOGIN_FAIL_LIMIT_LOGIN", 5),
            login_fail_window=_env_int("LOGIN_FAIL_WINDOW", 900),
            plesk_fail_budget=_env_int("PLESK_FAIL_BUDGET", 4),
            plesk_fail_budget_window=_env_int("PLESK_FAIL_BUDGET_WINDOW", 600),
            host=_env("MCP_HOST", "0.0.0.0") or "0.0.0.0",
            port=_env_int("MCP_PORT", 8000),
            trusted_proxies=_env("TRUSTED_PROXIES", "127.0.0.1") or "127.0.0.1",
            metrics_enabled=_env_bool("METRICS_ENABLED", True),
            service_name=_env("SERVICE_NAME", "Plesk Files MCP") or "Plesk Files MCP",
        )
