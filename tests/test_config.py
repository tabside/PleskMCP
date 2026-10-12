from __future__ import annotations

import pytest

from pleskmcp.config import ConfigError, Settings

REQUIRED = {
    "PUBLIC_BASE_URL": "https://mcp.example.com/plesk",
    "PLESK_URL": "https://plesk.example.com:8443",
    "PLESK_SSH_HOST": "plesk.example.com",
    "PLESK_SSH_USER": "pleskmcp",
    "PLESK_SSH_KEY_PATH": "/run/secrets/key",
    "PLESK_SSH_HOST_KEY": "ssh-ed25519 AAAA",
    "DATA_ENCRYPTION_KEY": "x",
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
