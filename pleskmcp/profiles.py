"""Access profiles: what a subscription may do, by Plesk service plan or add-on plan.

ACCESS_PROFILES is a JSON object (environment variable, or a file path in
ACCESS_PROFILES_FILE). Keys are plan or add-on names, or their GUIDs. A
subscription gets access only when its plan or one of its add-ons matches a
profile; with several matches, every value takes the most generous one.

    {
      "AI Hosting": {"scopes": ["files:read", "files:write", "dns:read"],
                      "store_max_percent": 10, "store_max_bytes": 268435456,
                      "backup_retention_days": 14, "trash_retention_days": 14,
                      "tool_calls_per_minute": 60, "tool_writes_per_minute": 30,
                      "write_bytes_per_hour": 104857600},
      "KI-Zugang":  {"scopes": ["files:read", "files:write", "dns:read", "db:read", "db:admin"],
                      "max_databases_created": 3}
    }

A profile keyed "*" is the fallback for every subscription whose plan and
add-ons match nothing else, i.e. it opens every subscription of a logged-in
customer whatever plan it has; Settings.startup_warnings() flags it.

Scopes: files:read, files:write, dns:read, dns:write, db:read (db_list,
db_schema, db_query), db:write (db_execute, db_restore of table dumps),
db:admin (db_apply_schema, db_create, db_drop, full-dump restores),
ssl:write (ssl_issue: Let's Encrypt for the own domain; ssl_status only needs files:read).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

ALL_SCOPES = ["files:read", "files:write", "dns:read", "dns:write", "db:read", "db:write", "db:admin", "ssl:write"]

_INT_FIELDS = (
    "store_max_percent",
    "store_max_bytes",
    "backup_retention_days",
    "trash_retention_days",
    "tool_calls_per_minute",
    "tool_writes_per_minute",
    "write_bytes_per_hour",
    "max_databases_created",
)


class ProfileError(ValueError):
    pass


@dataclass(frozen=True)
class Profile:
    name: str
    scopes: tuple[str, ...]
    store_max_percent: int | None = None
    store_max_bytes: int | None = None
    backup_retention_days: int | None = None
    trash_retention_days: int | None = None
    tool_calls_per_minute: int | None = None
    tool_writes_per_minute: int | None = None
    write_bytes_per_hour: int | None = None
    max_databases_created: int | None = None
    matched: tuple[str, ...] = field(default_factory=tuple)  # profile names that contributed

    def limits(self, defaults: dict[str, int]) -> dict[str, int]:
        """Effective numeric limits, falling back to the service defaults."""
        out: dict[str, int] = {}
        for key in _INT_FIELDS:
            value = getattr(self, key)
            out[key] = int(value) if value is not None else int(defaults[key])
        return out


def parse_profiles(raw: str | None) -> dict[str, Profile]:
    if not raw or not raw.strip():
        return {}
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise ProfileError(f"ACCESS_PROFILES is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError("ACCESS_PROFILES must be a JSON object keyed by plan or add-on name")
    profiles: dict[str, Profile] = {}
    for name, spec in data.items():
        if not isinstance(spec, dict):
            raise ProfileError(f"ACCESS_PROFILES[{name!r}] must be an object")
        scopes = spec.get("scopes", [])
        if not isinstance(scopes, list) or not all(isinstance(s, str) for s in scopes):
            raise ProfileError(f"ACCESS_PROFILES[{name!r}].scopes must be a list of strings")
        for scope in scopes:
            if scope not in ALL_SCOPES:
                raise ProfileError(f"ACCESS_PROFILES[{name!r}]: unknown scope {scope!r}")
        values: dict[str, Any] = {}
        for key in _INT_FIELDS:
            if key in spec:
                try:
                    values[key] = int(spec[key])
                except (TypeError, ValueError) as exc:
                    raise ProfileError(f"ACCESS_PROFILES[{name!r}].{key} must be an integer") from exc
                if values[key] < 0:
                    raise ProfileError(f"ACCESS_PROFILES[{name!r}].{key} must not be negative")
        profiles[name.strip().lower()] = Profile(name=name.strip(), scopes=tuple(dict.fromkeys(scopes)), matched=(name.strip(),), **values)
    return profiles


def merge_profiles(matches: list[Profile]) -> Profile | None:
    """Combine every matching profile: union of scopes, the larger value per limit."""
    if not matches:
        return None
    scopes: list[str] = []
    for p in matches:
        for s in p.scopes:
            if s not in scopes:
                scopes.append(s)
    values: dict[str, Any] = {}
    for key in _INT_FIELDS:
        present = [getattr(p, key) for p in matches if getattr(p, key) is not None]
        values[key] = max(present) if present else None
    names = tuple(dict.fromkeys(n for p in matches for n in p.matched))
    return Profile(name=" + ".join(names), scopes=tuple(scopes), matched=names, **values)


def resolve_profile(profiles: dict[str, Profile], plan_names: list[str], plan_guids: list[str]) -> Profile | None:
    """Find the profiles matching any of the subscription's plan/add-on names or GUIDs."""
    keys: list[str] = []
    for value in list(plan_names) + list(plan_guids):
        key = (value or "").strip().lower()
        if key and key not in keys:
            keys.append(key)
    matches = [profiles[k] for k in keys if k in profiles]
    return merge_profiles(matches)
