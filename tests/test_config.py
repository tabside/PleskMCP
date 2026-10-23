from __future__ import annotations

import pytest
from cryptography.fernet import Fernet

from pleskmcp.config import ConfigError, Settings

REQUIRED = {
    "PUBLIC_BASE_URL": "https://mcp.example.com/plesk",
    "PLESK_URL": "https://plesk.example.com:8443",
    "PLESK_SSH_HOST": "plesk.example.com",
    "PLESK_SSH_USER": "pleskmcp",
    "PLESK_SSH_KEY_PATH": "/run/secrets/key",
    "PLESK_SSH_HOST_KEY": "ssh-ed25519 AAAA",
    "DATA_ENCRYPTION_KEY": "x",
    "DATABASE_URL": "postgresql+asyncpg://pleskmcp:pw@postgres/pleskmcp",
    "REDIS_URL": "redis://:pw@redis:6379/0",
}


def test_missing_variables_refuse_start(monkeypatch: pytest.MonkeyPatch):
    for key in REQUIRED:
        monkeypatch.delenv(key, raising=False)
    with pytest.raises(ConfigError, match="PUBLIC_BASE_URL"):
        Settings.load()
    for key, value in REQUIRED.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("PLESK_SSH_HOST_KEY")
    with pytest.raises(ConfigError, match="PLESK_SSH_HOST_KEY"):
        Settings.load()
    monkeypatch.setenv("PLESK_SSH_HOST_KEY", "ssh-ed25519 AAAA")
    monkeypatch.setenv("ACCOUNT_CHECK_MODE", "admin_key")
    with pytest.raises(ConfigError, match="PLESK_ADMIN_API_KEY"):
        Settings.load()
    monkeypatch.setenv("ACCOUNT_CHECK_MODE", "bogus")
    with pytest.raises(ConfigError, match="ACCOUNT_CHECK_MODE"):
        Settings.load()


def test_base_path_derived(monkeypatch: pytest.MonkeyPatch):
    for key, value in REQUIRED.items():
        monkeypatch.setenv(key, value)
    settings = Settings.load()
    assert settings.base_path == "/plesk"
    assert settings.resource_url == "https://mcp.example.com/plesk/mcp"
    assert settings.issuer_url == "https://mcp.example.com/plesk"
    monkeypatch.setenv("PUBLIC_BASE_URL", "https://files.example.com")
    settings = Settings.load()
    assert settings.base_path == "" and settings.resource_url == "https://files.example.com/mcp"
    monkeypatch.setenv("PUBLIC_BASE_URL", "http://mcp.example.com/plesk")
    with pytest.raises(ConfigError, match="https"):
        Settings.load()


def test_startup_warnings_for_wildcard_profile_and_login_only(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path):
    import json
    import logging

    for key, value in REQUIRED.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("AUDIT_LOG_FILE", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DATA_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("ACCESS_PROFILES", json.dumps({"AI Hosting": {"scopes": ["files:read"]}}))
    assert Settings.load().startup_warnings() == []

    monkeypatch.setenv("ACCESS_PROFILES", json.dumps({"*": {"scopes": ["files:read", "db:read"]}}))
    monkeypatch.setenv("ACCOUNT_CHECK_MODE", "login_only")
    settings = Settings.load()
    warnings = settings.startup_warnings()
    assert len(warnings) == 2
    assert 'wildcard profile "*"' in warnings[0] and "files:read, db:read" in warnings[0]
    assert "login_only" in warnings[1]

    # build_core logs them, so api, worker and scheduler all show them at start
    from pleskmcp.server import build_core

    settings = settings.__class__(**{**settings.__dict__, "plesk_verify_ssl": False})  # no CA bundle needed in the test
    with caplog.at_level(logging.WARNING, logger="pleskmcp.server"):
        build_core(settings)
    assert sum('wildcard profile "*"' in r.getMessage() for r in caplog.records) == 1
    assert sum("login_only" in r.getMessage() for r in caplog.records) == 1
