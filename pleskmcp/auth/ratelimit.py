"""Login rate limiting backed by the login_attempts table.

Three independent limits:
* failures per client IP,
* failures per Plesk login name,
* a global budget of failed Plesk authentications per window. Plesk's
  Fail2ban (jail plesk-panel) counts failed XML API logins from this
  service's IP; the budget keeps the service below the ban threshold even if
  the service's IP is not on Plesk's trusted list.
"""

from __future__ import annotations

import time

from ..config import Settings
from ..store import Store


class RateLimited(Exception):
    def __init__(self, scope: str):
        super().__init__(f"rate limited ({scope})")
        self.scope = scope


class LoginRateLimiter:
    def __init__(self, settings: Settings, store: Store):
        self._settings = settings
        self._store = store

    def check(self, *, ip: str, login: str) -> None:
        now = int(time.time())
        since = now - self._settings.login_fail_window
        if self._store.count_failures(since=since, ip=ip) >= self._settings.login_fail_limit_ip:
            raise RateLimited("ip")
        if login and self._store.count_failures(since=since, login=login) >= self._settings.login_fail_limit_login:
            raise RateLimited("login")
        budget_since = now - self._settings.plesk_fail_budget_window
        if self._store.count_failures(since=budget_since, plesk_only=True) >= self._settings.plesk_fail_budget:
            raise RateLimited("plesk_budget")

    def record(self, *, ip: str, login: str, success: bool, plesk_checked: bool) -> None:
        self._store.record_login_attempt(ip=ip, login=login, success=success, plesk_checked=plesk_checked)
