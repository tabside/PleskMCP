"""Audit log: one JSON object per line.

Never log file contents, passwords, tokens or secret keys. Callers pass only
identifiers (Plesk login, domain, path, tool, client).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any

logger = logging.getLogger("pleskmcp.audit")

_SENSITIVE_KEYS = {"password", "passwd", "token", "secret", "key", "content", "old_str", "new_str", "data"}


class AuditLog:
    def __init__(self, path: str | None):
        self._path = path or None
        self._lock = threading.Lock()
        if self._path:
            os.makedirs(os.path.dirname(self._path) or ".", exist_ok=True)

    def write(self, event: str, **fields: Any) -> None:
        record: dict[str, Any] = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event}
        for key, value in fields.items():
            if key in _SENSITIVE_KEYS:
                continue
            if value is None:
                continue
            record[key] = value
        line = json.dumps(record, ensure_ascii=False, sort_keys=False)
        logger.info("%s", line)
        if not self._path:
            return
        with self._lock:
            try:
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except OSError as exc:  # pragma: no cover - disk problems must not break requests
                logger.error("audit log write failed: %s", exc)
