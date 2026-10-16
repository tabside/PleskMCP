"""Access profiles per plan / add-on: parsing, merging, rejection without a profile, effective scopes."""

from __future__ import annotations

import json

import pytest

from conftest import Env, OAuthFlow, call_tool, structured, tool_text
from pleskmcp.profiles import ProfileError, merge_profiles, parse_profiles, resolve_profile

pytestmark = pytest.mark.anyio


def test_parse_and_merge():
    profiles = parse_profiles(
        json.dumps(
            {
                "AI Hosting": {"scopes": ["files:read", "files:write", "dns:read"], "store_max_bytes": 100, "backup_retention_days": 7},
                "KI-Zugang": {"scopes": ["files:read", "db:read", "db:admin"], "store_max_bytes": 500, "max_databases_created": 2},
            }
        )
    )
    assert set(profiles) == {"ai hosting", "ki-zugang"}
    merged = resolve_profile(profiles, ["ai hosting", "KI-Zugang"], [])
    assert merged is not None
    assert set(merged.scopes) == {"files:read", "files:write", "dns:read", "db:read", "db:admin"}
    # the more generous value wins per field
    assert merged.store_max_bytes == 500 and merged.backup_retention_days == 7 and merged.max_databases_created == 2
    assert merged.matched == ("AI Hosting", "KI-Zugang")
    defaults = {"store_max_percent": 10, "store_max_bytes": 1, "backup_retention_days": 30, "trash_retention_days": 30, "tool_calls_per_minute": 60, "tool_writes_per_minute": 30, "write_bytes_per_hour": 1, "max_databases_created": 3}
    limits = merged.limits(defaults)
    assert limits["trash_retention_days"] == 30 and limits["store_max_bytes"] == 500
    assert resolve_profile(profiles, ["Other"], ["guid-x"]) is None
    assert merge_profiles([]) is None
    with pytest.raises(ProfileError, match="unknown scope"):
        parse_profiles(json.dumps({"x": {"scopes": ["root"]}}))
    with pytest.raises(ProfileError, match="JSON"):
        parse_profiles("{nope")
    with pytest.raises(ProfileError, match="negative"):
        parse_profiles(json.dumps({"x": {"scopes": [], "store_max_bytes": -1}}))
    assert parse_profiles("") == {}


async def test_subscription_without_profile_is_rejected(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    domains = structured(await call_tool(env.client, access, "list_domains", {}))["domains"]
    assert "plain.example" not in [d["name"] for d in domains]
    result = await call_tool(env.client, access, "list_dir", {"domain": "plain.example", "path": ""})
    assert result["isError"] and "KI-Zugang für dieses Abo nicht gebucht" in tool_text(result)
    assert all(c["domain"] != "plain.example" for c in env.pool.calls)
    # the add-on unlocks access: the data.example subscription only has a profile through "KI-Zugang"
    by_name = {d["name"]: d for d in domains}
    # "KI-Zugang" matched by name (administrator key resolves the GUID), the plan by its GUID key
    assert by_name["data.example"]["profile"] == "KI-Zugang + guid-plan-standard"
    assert "db:admin" in by_name["data.example"]["scopes"]
    assert "db:read" not in by_name["example.com"]["scopes"]


async def test_effective_scopes_are_the_intersection(env: Env, flow: OAuthFlow):
    # token with every scope, profile of example.com without db scopes
    tokens = await flow.full_login()
    result = await call_tool(env.client, tokens["access_token"], "db_list", {"domain": "example.com"})
    assert result["isError"] and "erlaubt db:read nicht" in tool_text(result)
    # token with files:read only, profile with everything: the token is the limit
    narrow = await flow.full_login(scope="files:read")
    result = await call_tool(env.client, narrow["access_token"], "db_list", {"domain": "data.example"})
    assert result["isError"] and "fehlt die Berechtigung db:read" in tool_text(result)
    result = await call_tool(env.client, narrow["access_token"], "write_file", {"domain": "data.example", "path": "x", "content": "x"})
    assert result["isError"] and "files:write" in tool_text(result)
    assert not (await call_tool(env.client, narrow["access_token"], "list_dir", {"domain": "data.example"})).get("isError")


async def test_plan_change_is_picked_up_after_cache_expiry(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    assert not (await call_tool(env.client, access, "list_dir", {"domain": "example.com"})).get("isError")
    # the hoster removes the plan from the subscription
    env.plesk.users["kunde"].domains[0]["plan_guids"] = ["guid-plan-none"]
    await env.services.accounts.invalidate_caches("kunde")
    # the domain list of the account is refreshed by the status check (ACCOUNT_CHECK_TTL=0)
    result = await call_tool(env.client, access, "list_dir", {"domain": "example.com"})
    assert result["isError"] and "nicht gebucht" in tool_text(result)


async def test_profile_limits_reach_the_helper(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    status = structured(await call_tool(env.client, tokens["access_token"], "storage_status", {"domain": "example.com"}))
    assert status["profile"] == "AI Hosting"
    # 10 % of 5 GB is larger than the profile's 64 MB cap, so the cap applies
    assert status["store_limit_bytes"] == 64 * 1024 * 1024
    assert status["retention"]["backup_retention_days"] == 14
    assert status["quota_bytes"] == 5 * 1024**3 and status["webspace_used_bytes"] == 1 * 1024**3
    assert "calls_this_minute" in status["rate_limits"]
