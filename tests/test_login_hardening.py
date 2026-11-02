"""Login and account pages: redirect target shown, warning for unknown clients, no framing."""

from __future__ import annotations

import re

import pytest

from conftest import Env, OAuthFlow

pytestmark = pytest.mark.anyio


async def _login_page(flow: OAuthFlow) -> str:
    location, _ = await flow.authorize()
    page = await flow.client.get(location)
    assert page.status_code == 200, page.text
    assert page.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
    return page.text


async def test_known_client_shows_target_without_warning(env: Env, flow: OAuthFlow):
    await flow.register()
    text = await _login_page(flow)
    assert "weiter zu <strong>127.0.0.1</strong>" in text
    assert "nicht als bekannter KI-Dienst" not in text


async def test_unknown_redirect_target_is_warned_even_with_a_trusted_name(env: Env):
    evil = OAuthFlow(env)
    evil.redirect_uri = "https://claude.ai.evil.example/callback"
    await evil.register(client_name="Claude")
    text = await _login_page(evil)
    assert "weiter zu <strong>claude.ai.evil.example</strong>" in text
    assert "nicht als bekannter KI-Dienst" in text and "«Claude»" in text


async def test_account_page_not_frameable(env: Env):
    page = await env.client.get("/plesk/account")
    assert page.headers["x-frame-options"] == "DENY"


def test_known_redirect_hosts():
    from pleskmcp.auth.login import known_redirect

    assert known_redirect("https://claude.ai/api/mcp/auth_callback")
    assert known_redirect("http://localhost:6274/oauth/callback")
    assert not known_redirect("https://claude.ai.evil.example/cb")
    assert not known_redirect("https://evilclaude.ai/cb")
    assert not known_redirect("not a url")
