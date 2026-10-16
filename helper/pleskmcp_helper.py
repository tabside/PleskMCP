#!/usr/libexec/platform-python
# -*- coding: utf-8 -*-
"""PleskMCP helper: file, log and database operations inside one subscription, run as its system user.

Installed on the Plesk server as /usr/local/bin/pleskmcp-helper (root owned,
0755) and started by the worker via
    sudo -n -u <sysuser> /usr/local/bin/pleskmcp-helper
with a JSON request on stdin. It prints one JSON object to stdout.

Must stay compatible with Python 3.6 (CloudLinux 8 platform-python) and use
only the standard library.

Security model:
* runs with the uid/gid of the subscription's system user, never root;
* only operates below the document root passed in the request, after
  checking that the document root is inside the user's own home
  (/var/www/vhosts/<subscription>) and owned by the user;
* paths are normalised, must stay below the document root and must not
  traverse any symbolic link;
* versions (file backups), the trash, DNS exports and database dumps live
  in <home>/.pleskmcp, outside every document root, and are kept within a
  size budget derived from the subscription's disk quota;
* values of credentials in protected files are redacted before they leave
  the server; database credentials found in site configuration never leave
  the helper.
"""

import base64
import calendar
import errno
import fnmatch
import gzip
import json
import os
import pwd
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

VHOSTS_BASE = "/var/www/vhosts"
STORE_DIRNAME = ".pleskmcp"
ID_RE = re.compile(r"^[0-9]{14}-[A-Za-z0-9_-]{6,16}$")
TRASH_ID_RE = ID_RE
LEGACY_BACKUP_RE = re.compile(r"^(?P<safe>.+)\.(?P<stamp>[0-9]{14})(?:\.(?P<n>[0-9]+))?$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,64}$")
DB_NAME_RE = re.compile(r"^[A-Za-z0-9_$][A-Za-z0-9_$.-]{0,63}$")
IDENT_RE = re.compile(r"^[A-Za-z0-9_$]{1,64}$")
LOG_NAME_RE = re.compile(
    r"^(access_log|access_ssl_log|error_log|proxy_access_log|proxy_access_ssl_log|proxy_error_log)"
    r"(\.processed|\.[0-9]+|-[0-9]{8})?(\.gz)?$"
)
REDACTED = "***"

DEFAULT_LIMITS = {
    "read_max_bytes": 2 * 1024 * 1024,
    "write_max_bytes": 5 * 1024 * 1024,
    "list_max_entries": 2000,
    "log_max_lines": 500,
    "log_max_scan_bytes": 200 * 1024 * 1024,
    "backup_max_file_bytes": 20 * 1024 * 1024,
    "trash_retention_days": 30,
    "backup_retention_days": 30,
    "backup_min_keep_days": 7,
    "store_max_percent": 10,
    "store_max_bytes": 1024 * 1024 * 1024,
    "time_limit": 30,
    "db_max_rows": 500,
    "db_max_affected_rows": 1000,
    "db_query_time_limit": 20,
}
DEFAULT_PROTECTED = ["wp-config.php", ".env", ".env.*", "config/database.php", "configuration.php", "app/etc/env.php", "*.pem", "*.key", ".htpasswd", ".git/config"]
DEFAULT_DB_SOURCES = ["wp-config.php", ".env", "configuration.php", "app/etc/env.php", "config/database.php"]
DEFAULT_REDACT_COLUMNS = ["user_pass", "password", "passwd", "pass", "api_key", "apikey", "secret", "token", "access_token", "refresh_token", "private_key", "auth_key", "salt"]
REFUSE_READ_PATTERNS = ["*.pem", "*.key"]

WRITE_OPS = ("write_file", "replace_in_file", "move_file", "delete_file", "restore_file", "restore_version", "store_write", "purge_store", "db_execute", "db_restore", "db_apply_schema", "db_dump", "db_credentials_file", "db_credentials_remove")
DB_CREDS_DIRNAME = "pleskmcp-db"


class HelperError(Exception):
    def __init__(self, code, message, details=None):
        Exception.__init__(self, message)
        self.code = code
        self.message = message
        self.details = details


class TimeLimit(Exception):
    pass


def _alarm(signum, frame):
    raise TimeLimit()


# ------------------------------------------------------------------ redaction
SECRET_WORDS = r"(?:pass(?:word|wd)?|secret|salt|token|auth[_a-z]*key|api[_a-z]*key|private[_a-z]*key|[a-z_]*_key)"
_RE_PHP_DEFINE = re.compile(r"""(define\s*\(\s*['"][A-Za-z0-9_]*(?i:%s)[A-Za-z0-9_]*['"]\s*,\s*['"])([^'"]*)(['"])""" % SECRET_WORDS)
_RE_PHP_VAR = re.compile(r"""(\$[A-Za-z0-9_]*(?i:%s)[A-Za-z0-9_]*\s*=\s*['"])([^'"]*)(['"])""" % SECRET_WORDS)
_RE_PHP_ARRAY = re.compile(r"""(['"][A-Za-z0-9_]*(?i:%s)[A-Za-z0-9_]*['"]\s*=>\s*['"])([^'"]*)(['"])""" % SECRET_WORDS)
_RE_ENV = re.compile(r"""^([A-Za-z0-9_]*(?i:%s)[A-Za-z0-9_]*\s*=\s*)(.*)$""" % SECRET_WORDS, re.M)
_RE_URL_CRED = re.compile(r"""(://[^:/\s'"@]+:)([^@\s'"]+)(@)""")
_RE_HTPASSWD = re.compile(r"^([^:\s]+:)(.+)$", re.M)
_RE_LOG_SECRET = re.compile(r"""((?:password|passwd|pwd|pass|token|secret|api_key|apikey|key|auth)\s*[=:]\s*)([^\s&;'"]+)""", re.I)
_RE_LOG_AUTH = re.compile(r"""((?:Authorization|Cookie|Set-Cookie)\s*:\s*)(.+)""", re.I)


def _sub_middle(regex, text):
    """Replace group 2 of every match with REDACTED. Returns (text, count)."""
    count = [0]

    def repl(m):
        if m.group(2) == "" or m.group(2) == REDACTED:
            return m.group(0)
        count[0] += 1
        return m.group(1) + REDACTED + (m.group(3) if m.lastindex and m.lastindex >= 3 else "")

    return regex.sub(repl, text), count[0]


def redact_config(text, name):
    """Redact credential values in a protected file. Returns (text, count)."""
    total = 0
    base = os.path.basename(name)
    if base == ".htpasswd":
        text, n = _sub_middle(_RE_HTPASSWD, text)
        return text, n
    for regex in (_RE_PHP_DEFINE, _RE_PHP_VAR, _RE_PHP_ARRAY, _RE_URL_CRED):
        text, n = _sub_middle(regex, text)
        total += n
    if base.startswith(".env") or base.endswith(".ini") or base == "config" or "=" in text:
        text, n = _sub_middle_env(text)
        total += n
    return text, total


def _sub_middle_env(text):
    count = [0]

    def repl(m):
        value = m.group(2).strip()
        if value == "" or value.strip("\"'") == REDACTED:
            return m.group(0)
        count[0] += 1
        return m.group(1) + REDACTED

    return _RE_ENV.sub(repl, text), count[0]


def contains_redacted_secret(text, name):
    """True if a secret position in `text` holds the placeholder (would write '***' back)."""
    base = os.path.basename(name)
    regexes = [_RE_PHP_DEFINE, _RE_PHP_VAR, _RE_PHP_ARRAY, _RE_URL_CRED, _RE_ENV]
    if base == ".htpasswd":
        regexes = [_RE_HTPASSWD]
    for regex in regexes:
        for m in regex.finditer(text):
            if m.group(2).strip().strip("\"'") == REDACTED:
                return True
    return False


def redact_log_line(line):
    line, _ = _sub_middle(_RE_LOG_AUTH, line)
    line, _ = _sub_middle(_RE_LOG_SECRET, line)
    return line


# --------------------------------------------------------------------------- paths
class Workspace(object):
    """One (domain, docroot) pair validated against the current user."""

    def __init__(self, domain, docroot, limits, request_id=None, tool=None):
        self.uid = os.getuid()
        if self.uid == 0:
            raise HelperError("refused", "helper must not run as root")
        self.gid = os.getgid()
        try:
            self.home = os.path.realpath(pwd.getpwuid(self.uid).pw_dir)
        except KeyError:
            raise HelperError("refused", "unknown system user")
        base = os.path.realpath(VHOSTS_BASE)
        if not self.home.startswith(base + "/") or os.sep in self.home[len(base) + 1:]:
            raise HelperError("refused", "home directory is not a subscription directory")
        home_st = os.lstat(self.home)
        if not stat.S_ISDIR(home_st.st_mode) or home_st.st_uid != self.uid:
            raise HelperError("refused", "home directory is not owned by the system user")

        if not isinstance(domain, str) or not re.match(r"^[a-z0-9.-]{1,253}$", domain):
            raise HelperError("bad_request", "invalid domain")
        self.domain = domain
        self.domain_dir = domain.replace("/", "_")
        self.request_id = request_id if isinstance(request_id, str) and REQUEST_ID_RE.match(request_id) else None
        self.tool = tool if isinstance(tool, str) and re.match(r"^[a-z_]{1,40}$", tool) else None

        if not isinstance(docroot, str) or not docroot.startswith("/"):
            raise HelperError("bad_request", "docroot must be an absolute path")
        real = os.path.realpath(docroot)
        if not (real == self.home or real.startswith(self.home + "/")):
            raise HelperError("refused", "document root is outside the subscription directory")
        if real == self.home:
            raise HelperError("refused", "document root must not be the subscription directory itself")
        st = os.lstat(real)
        if not stat.S_ISDIR(st.st_mode):
            raise HelperError("refused", "document root is not a directory")
        if st.st_uid != self.uid:
            raise HelperError("refused", "document root is not owned by the system user")
        if os.path.basename(real) == STORE_DIRNAME or real.startswith(self.store_dir + "/"):
            raise HelperError("refused", "document root must not be the helper store")
        self.docroot = real

        self.limits = dict(DEFAULT_LIMITS)
        self.quota_bytes = None
        self.used_bytes = None
        self.protected = list(DEFAULT_PROTECTED)
        self.db_sources = list(DEFAULT_DB_SOURCES)
        self.redact_columns = list(DEFAULT_REDACT_COLUMNS)
        if isinstance(limits, dict):
            for key in DEFAULT_LIMITS:
                value = limits.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    self.limits[key] = value
            if isinstance(limits.get("quota_bytes"), int) and limits["quota_bytes"] > 0:
                self.quota_bytes = limits["quota_bytes"]
            if isinstance(limits.get("used_bytes"), int) and limits["used_bytes"] >= 0:
                self.used_bytes = limits["used_bytes"]
            for key, attr in (("protected_files", "protected"), ("db_config_sources", "db_sources"), ("db_redact_columns", "redact_columns")):
                value = limits.get(key)
                if isinstance(value, list) and all(isinstance(v, str) for v in value):
                    setattr(self, attr, list(value))

    # ---------------------------------------------------------------- store dirs
    @property
    def store_dir(self):
        return os.path.join(self.home, STORE_DIRNAME)

    def _ensure_store(self, *parts):
        path = self.store_dir
        _mkdir_private(path)
        for part in parts:
            path = os.path.join(path, part)
            _mkdir_private(path)
        return path

    def store_limit_bytes(self):
        limit = self.limits["store_max_bytes"]
        if self.quota_bytes:
            by_percent = self.quota_bytes * self.limits["store_max_percent"] // 100
            limit = min(limit, by_percent) if limit > 0 else by_percent
        return max(limit, 1024 * 1024)

    def ensure_quota(self, extra_bytes):
        """Refuse a write that would push the subscription over its disk quota.

        Plesk's plans allow overuse, so the service enforces the limit itself:
        the store is cleaned down to its minimum once, then the usage is
        re-checked; a write that still does not fit is rejected.
        """
        if not self.quota_bytes or self.used_bytes is None or extra_bytes <= 0:
            return
        if self.used_bytes + extra_bytes <= self.quota_bytes:
            return
        freed = self.run_retention(aggressive=True).get("freed_bytes", 0)
        self.used_bytes = max(0, self.used_bytes - freed)
        if self.used_bytes + extra_bytes <= self.quota_bytes:
            return
        raise HelperError(
            "quota_exceeded",
            "disk quota exceeded: %d of %d bytes are used, the write needs %d more bytes" % (self.used_bytes, self.quota_bytes, extra_bytes),
            {"usage_bytes": self.used_bytes, "limit_bytes": self.quota_bytes, "needed_bytes": extra_bytes},
        )

    def account_written(self, nbytes):
        if self.used_bytes is not None and nbytes > 0:
            self.used_bytes += nbytes

    # ----------------------------------------------------------------- paths
    def normalize(self, rel):
        if rel is None:
            rel = ""
        if not isinstance(rel, str):
            raise HelperError("bad_request", "path must be a string")
        if "\x00" in rel:
            raise HelperError("bad_request", "path contains a NUL byte")
        if len(rel) > 4096:
            raise HelperError("bad_request", "path too long")
        rel = rel.replace("\\", "/")
        if rel.startswith("/"):
            raise HelperError("bad_request", "path must be relative to the document root")
        clean = os.path.normpath(rel) if rel not in ("", ".") else ""
        if clean == ".":
            clean = ""
        parts = clean.split("/") if clean else []
        for part in parts:
            if part in ("", ".", ".."):
                raise HelperError("bad_request", "path must not contain '..'")
            if len(part) > 255:
                raise HelperError("bad_request", "path component too long")
        if parts and parts[0] == STORE_DIRNAME:
            raise HelperError("refused", "path is reserved")
        return "/".join(parts)

    def resolve(self, rel, must_exist=True):
        """Map a relative path to an absolute path below the docroot.

        Every existing component is checked with lstat and must not be a
        symbolic link. The final realpath must stay inside the docroot.
        Returns (absolute_path, clean_relative_path, lstat_result_or_None).
        """
        clean = self.normalize(rel)
        current = self.docroot
        st = os.lstat(self.docroot)
        parts = clean.split("/") if clean else []
        for index, part in enumerate(parts):
            current = os.path.join(current, part)
            try:
                st = os.lstat(current)
            except OSError as exc:
                if exc.errno == errno.ENOENT:
                    if must_exist:
                        raise HelperError("not_found", "path does not exist: " + clean)
                    current = os.path.join(current, *parts[index + 1:]) if index + 1 < len(parts) else current
                    st = None
                    break
                if exc.errno in (errno.EACCES, errno.EPERM):
                    raise HelperError("not_owner", "no permission to access: " + clean, {"path": clean})
                raise HelperError("io_error", "cannot access path: " + clean)
            if stat.S_ISLNK(st.st_mode):
                raise HelperError("refused", "symbolic links are not allowed: " + clean)
        real = os.path.realpath(current)
        if not (real == self.docroot or real.startswith(self.docroot + "/")):
            raise HelperError("refused", "path escapes the document root")
        return current, clean, st

    def is_protected(self, clean):
        base = os.path.basename(clean)
        for pattern in self.protected:
            if fnmatch.fnmatch(clean, pattern) or fnmatch.fnmatch(base, pattern):
                return True
        return False

    @staticmethod
    def refuse_read(clean):
        base = os.path.basename(clean)
        return any(fnmatch.fnmatch(base, p) for p in REFUSE_READ_PATTERNS)

    def ensure_parents(self, clean):
        parts = clean.split("/")[:-1]
        current = ""
        for part in parts:
            current = part if not current else current + "/" + part
            abs_path, _, st = self.resolve(current, must_exist=False)
            if st is None:
                _call_write(lambda: os.mkdir(abs_path, 0o755), current, self)
            elif not stat.S_ISDIR(st.st_mode):
                raise HelperError("not_dir", "not a directory: " + current)

    # ----------------------------------------------------------- versions
    def versions_dir(self):
        return self._ensure_store("versions")

    def backup_file(self, abs_path, clean, st, tool=None):
        """Copy an existing regular file into the versions store. Returns (version_id, skipped_reason)."""
        if st.st_size > self.limits["backup_max_file_bytes"]:
            return None, "too_large"
        vdir = self.versions_dir()
        version_id = _new_id()
        entry = os.path.join(vdir, version_id)
        _mkdir_private(entry)
        payload = os.path.join(entry, "payload")
        fd = os.open(abs_path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            with os.fdopen(fd, "rb") as src:
                with open(payload, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        except BaseException:
            shutil.rmtree(entry, ignore_errors=True)
            raise
        os.chmod(payload, 0o600)
        meta = {
            "kind": "version",
            "domain": self.domain,
            "docroot": self.docroot,
            "path": clean,
            "size": st.st_size,
            "mode": "%04o" % stat.S_IMODE(st.st_mode),
            "mtime": _iso(st.st_mtime),
            "created_at": _iso(time.time()),
            "tool": tool or self.tool,
            "request_id": self.request_id,
        }
        _write_json(os.path.join(entry, "meta.json"), meta)
        return version_id, None

    def list_versions(self, clean=None):
        self.migrate_legacy_backups()
        vdir = self.versions_dir()
        items = []
        for name in os.listdir(vdir):
            if not ID_RE.match(name):
                continue
            meta = _read_json(os.path.join(vdir, name, "meta.json"))
            if not meta or meta.get("docroot") != self.docroot:
                continue
            if clean is not None and meta.get("path") != clean:
                continue
            meta["id"] = name
            items.append(meta)
        items.sort(key=lambda m: m.get("created_at", ""), reverse=True)
        return items

    def migrate_legacy_backups(self):
        """Move backups of the 0.1 layout (backups/<domain>/<path__with__underscores>.<stamp>) into versions/."""
        legacy = os.path.join(self.store_dir, "backups", self.domain_dir)
        if not os.path.isdir(legacy):
            return 0
        vdir = self.versions_dir()
        moved = 0
        for name in sorted(os.listdir(legacy)):
            m = LEGACY_BACKUP_RE.match(name)
            src = os.path.join(legacy, name)
            if not m or os.path.islink(src) or not os.path.isfile(src):
                continue
            guessed = m.group("safe").replace("__", "/") if m.group("safe") != "_" else ""
            stamp = m.group("stamp")
            created = "%s-%s-%sT%s:%s:%sZ" % (stamp[0:4], stamp[4:6], stamp[6:8], stamp[8:10], stamp[10:12], stamp[12:14])
            version_id = "%s-%s" % (stamp, _random_token(6))
            entry = os.path.join(vdir, version_id)
            _mkdir_private(entry)
            os.rename(src, os.path.join(entry, "payload"))
            st = os.lstat(os.path.join(entry, "payload"))
            _write_json(
                os.path.join(entry, "meta.json"),
                {
                    "kind": "version",
                    "domain": self.domain,
                    "docroot": self.docroot,
                    "path": guessed,
                    "size": st.st_size,
                    "created_at": created,
                    "tool": "legacy",
                    "request_id": None,
                    "migrated": True,
                    "legacy_name": name,
                },
            )
            moved += 1
        try:
            os.rmdir(legacy)
        except OSError:
            pass
        return moved

    def read_version(self, version_id):
        if not isinstance(version_id, str) or not ID_RE.match(version_id):
            raise HelperError("bad_request", "invalid version id")
        entry = os.path.join(self.versions_dir(), version_id)
        meta = _read_json(os.path.join(entry, "meta.json"))
        if not meta or meta.get("docroot") != self.docroot:
            raise HelperError("not_found", "version not found")
        meta["id"] = version_id
        return entry, meta

    # ----------------------------------------------------------------- trash
    def trash_dir(self):
        return self._ensure_store("trash")

    def move_to_trash(self, abs_path, clean, st):
        tdir = self.trash_dir()
        trash_id = _new_id()
        entry = os.path.join(tdir, trash_id)
        _mkdir_private(entry)
        kind = "dir" if stat.S_ISDIR(st.st_mode) else ("symlink" if stat.S_ISLNK(st.st_mode) else "file")
        payload = os.path.join(entry, "payload")
        _call_write(lambda: os.rename(abs_path, payload), clean, self)
        meta = {
            "kind": "trash",
            "domain": self.domain,
            "docroot": self.docroot,
            "path": clean,
            "type": kind,
            "deleted_at": _iso(time.time()),
            "created_at": _iso(time.time()),
            "size": st.st_size if kind == "file" else _dir_size(payload),
            "tool": self.tool or "delete_file",
            "request_id": self.request_id,
        }
        _write_json(os.path.join(entry, "meta.json"), meta)
        return trash_id, meta

    def list_trash(self):
        tdir = self.trash_dir()
        items = []
        for name in sorted(os.listdir(tdir)):
            if not TRASH_ID_RE.match(name):
                continue
            meta = _read_json(os.path.join(tdir, name, "meta.json"))
            if not meta or meta.get("domain") != self.domain:
                continue
            meta["id"] = name
            items.append(meta)
        return items

    def restore_from_trash(self, trash_id):
        if not isinstance(trash_id, str) or not TRASH_ID_RE.match(trash_id):
            raise HelperError("bad_request", "invalid trash id")
        entry = os.path.join(self.trash_dir(), trash_id)
        meta = _read_json(os.path.join(entry, "meta.json"))
        if not meta:
            raise HelperError("not_found", "trash entry not found")
        if meta.get("domain") != self.domain or meta.get("docroot") != self.docroot:
            raise HelperError("refused", "trash entry belongs to another domain")
        target, clean, st = self.resolve(meta.get("path", ""), must_exist=False)
        if st is not None or os.path.lexists(target):
            raise HelperError("exists", "target already exists: " + clean)
        if not os.path.isdir(os.path.dirname(target)):
            self.ensure_parents(clean)
        _call_write(lambda: os.rename(os.path.join(entry, "payload"), target), clean, self)
        try:
            os.unlink(os.path.join(entry, "meta.json"))
            os.rmdir(entry)
        except OSError:
            pass
        return {"path": clean, "type": meta.get("type")}

    # ----------------------------------------------------------------- writing
    def write_atomic(self, abs_path, clean, data, existing_st):
        parent = os.path.dirname(abs_path)
        mode = stat.S_IMODE(existing_st.st_mode) if existing_st is not None else 0o644

        def do_write():
            fd, tmp = tempfile.mkstemp(prefix=".pleskmcp-", dir=parent)
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(data)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.chmod(tmp, mode)
                try:
                    st = os.lstat(abs_path)
                    if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
                        raise HelperError("refused", "target is not a regular file: " + clean)
                except OSError:
                    pass
                os.rename(tmp, abs_path)
            except BaseException:
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise

        _call_write(do_write, clean, self)

    # ----------------------------------------------------------- idempotency
    def idem_path(self):
        if not self.request_id:
            return None
        return os.path.join(self._ensure_store("idem"), self.request_id + ".json")

    def idem_lookup(self, op):
        path = self.idem_path()
        if not path:
            return None
        data = _read_json(path)
        if data and data.get("op") == op and data.get("domain") == self.domain:
            result = data.get("result")
            if isinstance(result, dict):
                result = dict(result)
                result["replayed"] = True
            return result
        return None

    def idem_store(self, op, result):
        path = self.idem_path()
        if not path:
            return
        _write_json(path, {"op": op, "domain": self.domain, "result": result, "ts": _iso(time.time())})

    # ----------------------------------------------------------------- store
    def store_inventory(self):
        """Every retention-managed entry: list of dicts with category, id, path, size, created_at, key (for newest-per-key)."""
        entries = []
        sd = self.store_dir
        if not os.path.isdir(sd):
            return entries
        for category in ("versions", "trash"):
            cdir = os.path.join(sd, category)
            if not os.path.isdir(cdir):
                continue
            for name in os.listdir(cdir):
                if not ID_RE.match(name):
                    continue
                entry = os.path.join(cdir, name)
                meta = _read_json(os.path.join(entry, "meta.json")) or {}
                size = _dir_size(entry)
                key = "%s:%s:%s" % (category, meta.get("docroot", ""), meta.get("path", ""))
                entries.append({"category": category, "id": name, "path": entry, "size": size, "created_at": meta.get("created_at") or _iso(os.lstat(entry).st_mtime), "key": key, "domain": meta.get("domain")})
        dnsdir = os.path.join(sd, "dns")
        if os.path.isdir(dnsdir):
            for domain_dir in os.listdir(dnsdir):
                ddir = os.path.join(dnsdir, domain_dir)
                if not os.path.isdir(ddir):
                    continue
                for name in os.listdir(ddir):
                    if not name.endswith(".json"):
                        continue
                    path = os.path.join(ddir, name)
                    st = os.lstat(path)
                    entries.append({"category": "dns", "id": name[:-5], "path": path, "size": st.st_size, "created_at": _iso(st.st_mtime), "key": "dns:" + domain_dir, "domain": domain_dir})
        dbdir = os.path.join(sd, "db")
        if os.path.isdir(dbdir):
            for database in os.listdir(dbdir):
                bdir = os.path.join(dbdir, database)
                if not os.path.isdir(bdir):
                    continue
                for name in os.listdir(bdir):
                    if not name.endswith(".json"):
                        continue
                    meta = _read_json(os.path.join(bdir, name)) or {}
                    dump_id = name[:-5]
                    size = 0
                    for ext in (".sql.gz", ".json"):
                        try:
                            size += os.lstat(os.path.join(bdir, dump_id + ext)).st_size
                        except OSError:
                            pass
                    entries.append({"category": "db", "id": dump_id, "path": os.path.join(bdir, dump_id), "size": size, "created_at": meta.get("created_at") or "", "key": "db:" + database + ":" + ",".join(meta.get("tables") or []), "domain": meta.get("domain"), "database": database})
        return entries

    def store_usage(self):
        usage = {"versions": 0, "trash": 0, "dns": 0, "db": 0, "other": 0}
        for e in self.store_inventory():
            usage[e["category"]] = usage.get(e["category"], 0) + e["size"]
        sd = self.store_dir
        for name in ("idem", "tmp"):
            d = os.path.join(sd, name)
            if os.path.isdir(d):
                usage["other"] += _dir_size(d)
        usage["total"] = sum(usage.values())
        return usage

    def delete_entry(self, entry):
        category = entry["category"]
        if category in ("versions", "trash"):
            shutil.rmtree(entry["path"], ignore_errors=True)
        elif category == "dns":
            _unlink_quiet(entry["path"])
        elif category == "db":
            _unlink_quiet(entry["path"] + ".sql.gz")
            _unlink_quiet(entry["path"] + ".json")

    def run_retention(self, aggressive=False, dry_run=False):
        """Apply age limits and the size budget. Returns a summary."""
        now = time.time()
        entries = self.store_inventory()
        newest = {}
        for e in entries:
            if e["created_at"] > newest.get(e["key"], ""):
                newest[e["key"]] = e["created_at"]
        min_keep = self.limits["backup_min_keep_days"] * 86400
        deleted = []
        kept = []
        for e in entries:
            age = now - _parse_iso(e["created_at"])
            is_newest = newest.get(e["key"]) == e["created_at"]
            if e["category"] == "trash":
                limit = self.limits["trash_retention_days"] * 86400
            else:
                limit = self.limits["backup_retention_days"] * 86400
            if limit > 0 and age > limit and not (is_newest and age < min_keep):
                deleted.append(e)
            else:
                e["protected"] = is_newest and age < min_keep
                kept.append(e)
        budget = self.store_limit_bytes()
        total = sum(e["size"] for e in kept)
        if total > budget or aggressive:
            order = sorted(kept, key=lambda e: (1 if e.get("protected") else 0, e["created_at"]))
            for e in order:
                if aggressive:
                    if e.get("protected"):
                        continue
                elif total <= budget:
                    break
                if e.get("protected") and not aggressive:
                    continue
                deleted.append(e)
                total -= e["size"]
        if not dry_run:
            for e in deleted:
                self.delete_entry(e)
            idem = os.path.join(self.store_dir, "idem")
            if os.path.isdir(idem):
                for name in os.listdir(idem):
                    p = os.path.join(idem, name)
                    try:
                        if now - os.lstat(p).st_mtime > 2 * 86400:
                            os.unlink(p)
                    except OSError:
                        pass
        return {
            "deleted": len(deleted),
            "freed_bytes": sum(e["size"] for e in deleted),
            "remaining_bytes": total,
            "budget_bytes": budget,
            "dry_run": dry_run,
        }


# --------------------------------------------------------------------- utilities
def _mkdir_private(path):
    try:
        os.mkdir(path, 0o700)
    except OSError as exc:
        if exc.errno != errno.EEXIST:
            raise
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise HelperError("refused", "store path is not a directory")


def _random_token(length):
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    raw = os.urandom(length)
    return "".join(alphabet[b % len(alphabet)] for b in bytearray(raw))


def _new_id():
    return "%s-%s" % (time.strftime("%Y%m%d%H%M%S", time.gmtime()), _random_token(6))


def _iso(ts):
    """ISO 8601 UTC with milliseconds, so that entries written within the same second keep their order."""
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + ".%03dZ" % (int((ts - int(ts)) * 1000) % 1000)


def _parse_iso(value):
    try:
        base = calendar.timegm(time.strptime(value[:19], "%Y-%m-%dT%H:%M:%S"))
    except (ValueError, TypeError):
        return 0
    frac = 0.0
    if isinstance(value, str) and len(value) > 20 and value[19] == ".":
        digits = ""
        for ch in value[20:]:
            if not ch.isdigit():
                break
            digits += ch
        if digits:
            frac = int(digits[:3].ljust(3, "0")) / 1000.0
    return base + frac


def _read_json(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _write_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.rename(tmp, path)


def _unlink_quiet(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def _dir_size(path):
    total = 0
    try:
        st = os.lstat(path)
    except OSError:
        return 0
    if not stat.S_ISDIR(st.st_mode):
        return st.st_size
    for root, dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.lstat(os.path.join(root, name)).st_size
            except OSError:
                pass
    return total


def _entry_type(st):
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISREG(st.st_mode):
        return "file"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    return "other"


def _owner_hint(ws, clean, exc):
    """Translate a permission error into not_owner when the file or parent is not ours."""
    candidates = []
    abs_path = os.path.join(ws.docroot, clean) if clean else ws.docroot
    candidates.append((clean, abs_path))
    candidates.append((os.path.dirname(clean), os.path.dirname(abs_path)))
    for rel, path in candidates:
        try:
            st = os.lstat(path)
        except OSError:
            continue
        if st.st_uid != ws.uid:
            try:
                owner = pwd.getpwuid(st.st_uid).pw_name
            except KeyError:
                owner = str(st.st_uid)
            return HelperError(
                "not_owner",
                "no permission: %s belongs to user %s, not to the subscription's system user. Ask the hoster to fix the ownership (see pleskmcp report-ownership)." % (rel or ".", owner),
                {"path": rel, "owner": owner},
            )
    return HelperError("io_error", "permission denied: " + (clean or "."))


def _call_write(fn, clean, ws):
    """Run a filesystem write; map EDQUOT/ENOSPC (after one cleanup retry) and EACCES to helper errors."""
    for attempt in (1, 2):
        try:
            return fn()
        except HelperError:
            raise
        except OSError as exc:
            if exc.errno in (errno.EDQUOT, errno.ENOSPC):
                if attempt == 1:
                    ws.run_retention(aggressive=True)
                    continue
                usage = ws.store_usage()
                raise HelperError(
                    "quota_exceeded",
                    "disk quota exceeded; the helper store was cleaned up but the write still failed",
                    {"limit_bytes": ws.quota_bytes, "usage_bytes": ws.used_bytes, "store_bytes": usage.get("total")},
                )
            if exc.errno in (errno.EACCES, errno.EPERM):
                raise _owner_hint(ws, clean, exc)
            raise


def _open_nofollow_read(path):
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))


def _read_regular(abs_path, clean, st, max_bytes, offset=0):
    if not stat.S_ISREG(st.st_mode):
        raise HelperError("not_file", "not a regular file: " + clean)
    try:
        fd = _open_nofollow_read(abs_path)
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            raise HelperError("not_owner", "no permission to read: " + clean, {"path": clean})
        raise
    try:
        if offset:
            os.lseek(fd, offset, os.SEEK_SET)
        chunks = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
    finally:
        os.close(fd)
    data = b"".join(chunks)
    truncated = len(data) > max_bytes
    return data[:max_bytes], truncated


def _decode_content(args, limit):
    content = args.get("content")
    if not isinstance(content, str):
        raise HelperError("bad_request", "content must be a string")
    encoding = args.get("encoding", "text")
    if encoding == "base64":
        try:
            data = base64.b64decode(content, validate=True)
        except (ValueError, TypeError):
            raise HelperError("bad_request", "content is not valid base64")
    elif encoding == "text":
        data = content.encode("utf-8")
    else:
        raise HelperError("bad_request", "encoding must be text or base64")
    if len(data) > limit:
        raise HelperError("too_large", "content exceeds the write limit of %d bytes" % limit)
    return data


def _check_no_redacted(ws, clean, data):
    """Refuse to write the redaction placeholder into a protected file's secret position."""
    if not ws.is_protected(clean):
        return
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return
    if contains_redacted_secret(text, clean):
        raise HelperError("redacted_value", "the content contains the placeholder '***' where a credential belongs; re-read the file is not possible unredacted, keep the original value or edit only the other lines with replace_in_file")


# ------------------------------------------------------------------- file ops
def op_list_dir(ws, args):
    abs_path, clean, st = ws.resolve(args.get("path", ""))
    if not stat.S_ISDIR(st.st_mode):
        raise HelperError("not_dir", "not a directory: " + (clean or "."))
    limit = ws.limits["list_max_entries"]
    try:
        names = sorted(os.listdir(abs_path))
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EPERM):
            raise _owner_hint(ws, clean, exc)
        raise
    entries = []
    for name in names[:limit]:
        try:
            est = os.lstat(os.path.join(abs_path, name))
        except OSError:
            continue
        rel = name if not clean else clean + "/" + name
        entries.append(
            {
                "name": name,
                "type": _entry_type(est),
                "size": est.st_size if stat.S_ISREG(est.st_mode) else None,
                "mtime": _iso(est.st_mtime),
                "mode": "%04o" % stat.S_IMODE(est.st_mode),
                "owner_ok": est.st_uid == ws.uid,
                "protected": ws.is_protected(rel) if stat.S_ISREG(est.st_mode) else False,
            }
        )
    return {"path": clean, "entries": entries, "truncated": len(names) > limit, "total": len(names)}


def op_stat(ws, args):
    abs_path, clean, st = ws.resolve(args.get("path", ""))
    return {"path": clean, "type": _entry_type(st), "size": st.st_size, "mtime": _iso(st.st_mtime), "mode": "%04o" % stat.S_IMODE(st.st_mode), "owner_ok": st.st_uid == ws.uid}


def op_read_file(ws, args):
    abs_path, clean, st = ws.resolve(args.get("path"))
    encoding = args.get("encoding", "text")
    offset = args.get("offset", 0)
    if not isinstance(offset, int) or offset < 0:
        raise HelperError("bad_request", "offset must be a non-negative integer")
    if ws.refuse_read(clean):
        raise HelperError("protected", "this file holds key material and cannot be read through this service: " + clean)
    protected = ws.is_protected(clean)
    if protected and (encoding != "text" or offset):
        raise HelperError("protected", "protected files can only be read as whole text (credentials are redacted): " + clean)
    max_bytes = ws.limits["read_max_bytes"]
    requested = args.get("max_bytes")
    if isinstance(requested, int) and 0 < requested < max_bytes:
        max_bytes = requested
    data, truncated = _read_regular(abs_path, clean, st, max_bytes, offset)
    result = {"path": clean, "size": st.st_size, "offset": offset, "returned": len(data), "truncated": truncated, "protected": protected}
    if encoding == "base64":
        result["encoding"] = "base64"
        result["content"] = base64.b64encode(data).decode("ascii")
    elif encoding == "text":
        if b"\x00" in data:
            raise HelperError("binary", "file looks binary; read it with encoding=base64")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise HelperError("not_utf8", "file is not valid UTF-8; read it with encoding=base64")
        if protected:
            text, count = redact_config(text, clean)
            result["redacted"] = count
        result["encoding"] = "text"
        result["content"] = text
    else:
        raise HelperError("bad_request", "encoding must be text or base64")
    return result


def op_write_file(ws, args):
    data = _decode_content(args, ws.limits["write_max_bytes"])
    abs_path, clean, st = ws.resolve(args.get("path"), must_exist=False)
    if not clean:
        raise HelperError("bad_request", "path must name a file")
    _check_no_redacted(ws, clean, data)
    if st is None:
        if args.get("create_dirs"):
            ws.ensure_parents(clean)
        elif not os.path.isdir(os.path.dirname(abs_path)):
            raise HelperError("not_found", "parent directory does not exist (use create_dirs)")
    elif not stat.S_ISREG(st.st_mode):
        raise HelperError("not_file", "target exists and is not a regular file: " + clean)
    backup_id = None
    skipped = None
    old_size = st.st_size if st is not None else 0
    want_backup = st is not None and args.get("backup", True) and old_size <= ws.limits["backup_max_file_bytes"]
    ws.ensure_quota(len(data) - old_size + (old_size if want_backup else 0))
    if st is not None and args.get("backup", True):
        backup_id, skipped = ws.backup_file(abs_path, clean, st)
    ws.write_atomic(abs_path, clean, data, st)
    ws.account_written(len(data) - old_size + (old_size if backup_id else 0))
    result = {"path": clean, "size": len(data), "created": st is None, "backup": backup_id}
    if skipped:
        result["backup_skipped"] = skipped
    ws.run_retention()
    return result


def op_replace_in_file(ws, args):
    old = args.get("old_str")
    new = args.get("new_str")
    if not isinstance(old, str) or not old:
        raise HelperError("bad_request", "old_str must be a non-empty string")
    if not isinstance(new, str):
        raise HelperError("bad_request", "new_str must be a string")
    replace_all = bool(args.get("replace_all", False))
    abs_path, clean, st = ws.resolve(args.get("path"))
    limit = ws.limits["write_max_bytes"]
    if st.st_size > limit:
        raise HelperError("too_large", "file exceeds the replace limit of %d bytes" % limit)
    data, _ = _read_regular(abs_path, clean, st, limit)
    if b"\x00" in data:
        raise HelperError("binary", "file looks binary")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise HelperError("not_utf8", "file is not valid UTF-8")
    crlf = "\r\n" in text and "\n" not in text.replace("\r\n", "")
    if crlf:
        old_eff, new_eff = old.replace("\r\n", "\n").replace("\n", "\r\n"), new.replace("\r\n", "\n").replace("\n", "\r\n")
    else:
        old_eff, new_eff = old, new
    count = text.count(old_eff)
    if count == 0:
        raise HelperError("no_match", "old_str not found in file" + (" (note: credentials in this file are shown redacted)" if ws.is_protected(clean) else ""))
    if count > 1 and not replace_all:
        raise HelperError("ambiguous", "old_str occurs %d times; set replace_all=true to replace every occurrence" % count)
    updated = text.replace(old_eff, new_eff) if replace_all else text.replace(old_eff, new_eff, 1)
    encoded = updated.encode("utf-8")
    if len(encoded) > limit:
        raise HelperError("too_large", "result exceeds the write limit")
    _check_no_redacted(ws, clean, encoded)
    ws.ensure_quota(len(encoded) - st.st_size + (st.st_size if st.st_size <= ws.limits["backup_max_file_bytes"] else 0))
    backup_id, skipped = ws.backup_file(abs_path, clean, st)
    ws.write_atomic(abs_path, clean, encoded, st)
    ws.account_written(len(encoded) - st.st_size + (st.st_size if backup_id else 0))
    result = {"path": clean, "replacements": count if replace_all else 1, "size": len(encoded), "backup": backup_id}
    if skipped:
        result["backup_skipped"] = skipped
    ws.run_retention()
    return result


def op_move_file(ws, args):
    src_abs, src_clean, src_st = ws.resolve(args.get("src"))
    dst_abs, dst_clean, dst_st = ws.resolve(args.get("dst"), must_exist=False)
    if not src_clean or not dst_clean:
        raise HelperError("bad_request", "src and dst must name a file or directory")
    if stat.S_ISLNK(src_st.st_mode):
        raise HelperError("refused", "symbolic links cannot be moved")
    if dst_clean == src_clean or dst_clean.startswith(src_clean + "/"):
        raise HelperError("bad_request", "dst must not be inside src")
    if args.get("create_dirs"):
        ws.ensure_parents(dst_clean)
    elif not os.path.isdir(os.path.dirname(dst_abs)):
        raise HelperError("not_found", "destination directory does not exist (use create_dirs)")
    backup_id = None
    if dst_st is not None:
        if not args.get("overwrite"):
            raise HelperError("exists", "destination exists: " + dst_clean + " (use overwrite)")
        if not (stat.S_ISREG(dst_st.st_mode) and stat.S_ISREG(src_st.st_mode)):
            raise HelperError("refused", "overwrite is only allowed for regular files")
        backup_id, _ = ws.backup_file(dst_abs, dst_clean, dst_st)
    _call_write(lambda: os.rename(src_abs, dst_abs), dst_clean, ws)
    return {"src": src_clean, "dst": dst_clean, "backup": backup_id}


def op_delete_file(ws, args):
    abs_path, clean, st = ws.resolve(args.get("path"))
    if not clean:
        raise HelperError("refused", "the document root itself cannot be deleted")
    if stat.S_ISDIR(st.st_mode) and not args.get("recursive"):
        raise HelperError("is_dir", "path is a directory; set recursive=true to move it to the trash")
    backup_id = None
    if stat.S_ISREG(st.st_mode):
        backup_id, _ = ws.backup_file(abs_path, clean, st)
    trash_id, meta = ws.move_to_trash(abs_path, clean, st)
    ws.run_retention()
    return {"path": clean, "type": meta["type"], "trash_id": trash_id, "backup": backup_id}


def op_restore_file(ws, args):
    trash_id = args.get("trash_id")
    if not trash_id:
        return {"entries": ws.list_trash()}
    return ws.restore_from_trash(trash_id)


def op_list_versions(ws, args):
    path = args.get("path")
    clean = ws.normalize(path) if path else None
    items = ws.list_versions(clean)
    return {
        "path": clean,
        "versions": [
            {"id": m["id"], "path": m.get("path"), "size": m.get("size"), "created_at": m.get("created_at"), "tool": m.get("tool"), "request_id": m.get("request_id"), "migrated": bool(m.get("migrated"))}
            for m in items
        ],
    }


def op_restore_version(ws, args):
    entry, meta = ws.read_version(args.get("version_id"))
    wanted = ws.normalize(args.get("path")) if args.get("path") else meta.get("path")
    if meta.get("path") != wanted:
        raise HelperError("refused", "version %s belongs to %s, not to %s" % (meta["id"], meta.get("path"), wanted))
    abs_path, clean, st = ws.resolve(wanted, must_exist=False)
    if not clean:
        raise HelperError("bad_request", "path must name a file")
    if st is not None and not stat.S_ISREG(st.st_mode):
        raise HelperError("not_file", "target exists and is not a regular file: " + clean)
    payload = os.path.join(entry, "payload")
    pst = os.lstat(payload)
    if pst.st_size > ws.limits["write_max_bytes"]:
        raise HelperError("too_large", "version is larger than the write limit")
    with open(payload, "rb") as fh:
        data = fh.read()
    _check_no_redacted(ws, clean, data)
    old_size = st.st_size if st is not None else 0
    ws.ensure_quota(len(data) - old_size + (old_size if old_size <= ws.limits["backup_max_file_bytes"] else 0))
    if st is None:
        ws.ensure_parents(clean)
    current_backup = None
    if st is not None:
        current_backup, _ = ws.backup_file(abs_path, clean, st, tool="restore_version")
    ws.write_atomic(abs_path, clean, data, st)
    ws.account_written(len(data) - old_size + (old_size if current_backup else 0))
    ws.run_retention()
    return {"path": clean, "restored_version": meta["id"], "size": len(data), "backup_of_previous": current_backup, "created": st is None}


def op_list_changes(ws, args):
    since = args.get("since")
    limit = args.get("limit", 50)
    if not isinstance(limit, int) or limit <= 0:
        limit = 50
    limit = min(limit, 500)
    since_ts = 0
    if since:
        if isinstance(since, (int, float)):
            since_ts = float(since)
        elif isinstance(since, str):
            since_ts = _parse_iso(since)
    changes = []
    for m in ws.list_versions():
        changes.append({"time": m.get("created_at"), "kind": "file_backup", "tool": m.get("tool"), "path": m.get("path"), "id": m["id"], "request_id": m.get("request_id"), "size": m.get("size")})
    for m in ws.list_trash():
        changes.append({"time": m.get("deleted_at"), "kind": "trash", "tool": m.get("tool"), "path": m.get("path"), "id": m["id"], "request_id": m.get("request_id"), "size": m.get("size")})
    for e in ws.store_inventory():
        if e["category"] == "dns" and e.get("domain") == ws.domain_dir:
            changes.append({"time": e["created_at"], "kind": "dns_export", "tool": "dns", "path": None, "id": e["id"], "request_id": None, "size": e["size"]})
        elif e["category"] == "db" and e.get("domain") == ws.domain:
            changes.append({"time": e["created_at"], "kind": "db_dump", "tool": "db_execute", "path": e.get("database"), "id": e["id"], "request_id": None, "size": e["size"]})
    changes = [c for c in changes if c["time"] and _parse_iso(c["time"]) >= since_ts]
    changes.sort(key=lambda c: c["time"], reverse=True)
    return {"changes": changes[:limit], "total": len(changes)}


# ------------------------------------------------------------------- logs
def op_search_log(ws, args):
    name = args.get("log", "access_log")
    if not isinstance(name, str) or not LOG_NAME_RE.match(name):
        raise HelperError("bad_request", "unknown log name")
    kind = args.get("kind", "webspace")
    logs_dir = os.path.join(ws.home, "logs")
    if kind != "webspace":
        logs_dir = os.path.join(logs_dir, ws.domain)
    real_dir = os.path.realpath(logs_dir)
    allowed = (os.path.join(ws.home, "logs"), os.path.join(os.path.realpath(VHOSTS_BASE), "system", ws.domain, "logs"))
    if not any(real_dir == a or real_dir.startswith(a + "/") for a in allowed):
        raise HelperError("refused", "log directory is outside the allowed locations")
    path = os.path.join(real_dir, name)
    try:
        st = os.lstat(path)
    except OSError:
        raise HelperError("not_found", "log file not found: " + name)
    if not stat.S_ISREG(st.st_mode):
        raise HelperError("not_file", "log is not a regular file")
    pattern = args.get("pattern") or ""
    if not isinstance(pattern, str) or len(pattern) > 200:
        raise HelperError("bad_request", "pattern too long")
    try:
        regex = re.compile(pattern) if pattern else None
    except re.error as exc:
        raise HelperError("bad_request", "invalid pattern: %s" % exc)
    wanted = args.get("lines", 200)
    if not isinstance(wanted, int) or wanted <= 0:
        wanted = 200
    wanted = min(wanted, ws.limits["log_max_lines"])
    scan_limit = ws.limits["log_max_scan_bytes"]
    opener = gzip.open if name.endswith(".gz") else open
    matches = []
    scanned = 0
    scanned_bytes = 0
    truncated = False
    with opener(path, "rb") as fh:
        for raw in fh:
            scanned += 1
            scanned_bytes += len(raw)
            if scanned_bytes > scan_limit:
                truncated = True
                break
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if regex is None or regex.search(line):
                matches.append(redact_log_line(line))
                if len(matches) > wanted:
                    del matches[0]
    return {"log": name, "lines": matches, "returned": len(matches), "scanned": scanned, "scanned_bytes": scanned_bytes, "size": st.st_size, "truncated": truncated}


# ------------------------------------------------------------------- store ops
def op_store_write(ws, args):
    category = args.get("category")
    if category not in ("dns",):
        raise HelperError("bad_request", "unknown store category")
    content = args.get("content")
    if not isinstance(content, str) or len(content) > ws.limits["write_max_bytes"]:
        raise HelperError("bad_request", "content missing or too large")
    ws.ensure_quota(len(content.encode("utf-8")))
    sdir = ws._ensure_store(category, ws.domain_dir)
    export_id = _new_id()
    target = os.path.join(sdir, export_id + ".json")

    def do_write():
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(target, 0o600)

    _call_write(do_write, "", ws)
    ws.run_retention()
    return {"backup": os.path.relpath(target, ws.home), "id": export_id}


def op_store_list(ws, args):
    category = args.get("category")
    if category not in ("dns",):
        raise HelperError("bad_request", "unknown store category")
    sdir = os.path.join(ws.store_dir, category, ws.domain_dir)
    items = []
    if os.path.isdir(sdir):
        for name in sorted(os.listdir(sdir), reverse=True):
            if not name.endswith(".json"):
                continue
            st = os.lstat(os.path.join(sdir, name))
            items.append({"id": name[:-5], "size": st.st_size, "created_at": _iso(st.st_mtime)})
    return {"entries": items}


def op_store_read(ws, args):
    category = args.get("category")
    export_id = args.get("id")
    if category not in ("dns",):
        raise HelperError("bad_request", "unknown store category")
    if not isinstance(export_id, str) or not re.match(r"^[0-9A-Za-z_-]{1,64}$", export_id):
        raise HelperError("bad_request", "invalid export id")
    path = os.path.join(ws.store_dir, category, ws.domain_dir, export_id + ".json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            content = fh.read(ws.limits["read_max_bytes"])
    except OSError:
        raise HelperError("not_found", "export not found")
    return {"id": export_id, "content": content}


def op_storage_status(ws, args):
    usage = ws.store_usage()
    limit = ws.store_limit_bytes()
    result = {
        "domain": ws.domain,
        "webspace_used_bytes": ws.used_bytes,
        "quota_bytes": ws.quota_bytes,
        "remaining_bytes": (ws.quota_bytes - ws.used_bytes) if (ws.quota_bytes and ws.used_bytes is not None) else None,
        "store": usage,
        "store_limit_bytes": limit,
        "retention": {
            "backup_retention_days": ws.limits["backup_retention_days"],
            "trash_retention_days": ws.limits["trash_retention_days"],
            "backup_min_keep_days": ws.limits["backup_min_keep_days"],
        },
    }
    return result


def op_purge_store(ws, args):
    what = args.get("what", "trash")
    if what not in ("trash", "backups", "db_dumps", "all"):
        raise HelperError("bad_request", "what must be trash, backups, db_dumps or all")
    older = args.get("older_than_days")
    if older is not None and (not isinstance(older, int) or older < 0):
        raise HelperError("bad_request", "older_than_days must be a non-negative integer")
    confirm = bool(args.get("confirm", False))
    categories = {"trash": ("trash",), "backups": ("versions", "dns"), "db_dumps": ("db",), "all": ("trash", "versions", "dns", "db")}[what]
    now = time.time()
    selected = []
    for e in ws.store_inventory():
        if e["category"] not in categories:
            continue
        if e.get("domain") not in (ws.domain, ws.domain_dir, None):
            continue
        if older is not None and now - _parse_iso(e["created_at"]) < older * 86400:
            continue
        selected.append(e)
    summary = {"what": what, "older_than_days": older, "entries": len(selected), "bytes": sum(e["size"] for e in selected), "preview": not confirm}
    if confirm:
        for e in selected:
            ws.delete_entry(e)
    return summary


def op_retention(ws, args):
    return ws.run_retention(aggressive=bool(args.get("aggressive")), dry_run=bool(args.get("dry_run")))


def op_report_ownership(ws, args):
    """Read-only: files and directories below the docroot not owned by the system user."""
    limit = 5000
    foreign = []
    unreadable = []
    count = 0
    for root, dirs, files in os.walk(ws.docroot):
        rel_root = os.path.relpath(root, ws.docroot)
        rel_root = "" if rel_root == "." else rel_root
        if STORE_DIRNAME in dirs:
            dirs.remove(STORE_DIRNAME)
        for name in list(dirs) + files:
            count += 1
            if count > limit * 20:
                break
            rel = name if not rel_root else rel_root + "/" + name
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
            except OSError:
                unreadable.append(rel)
                continue
            if stat.S_ISLNK(st.st_mode):
                continue
            if st.st_uid != ws.uid:
                try:
                    owner = pwd.getpwuid(st.st_uid).pw_name
                except KeyError:
                    owner = str(st.st_uid)
                foreign.append({"path": rel, "type": _entry_type(st), "owner": owner, "mode": "%04o" % stat.S_IMODE(st.st_mode)})
                if len(foreign) >= limit:
                    break
            if stat.S_ISDIR(st.st_mode) and not os.access(path, os.R_OK | os.X_OK):
                unreadable.append(rel)
                if name in dirs:
                    dirs.remove(name)
        if len(foreign) >= limit:
            break
    return {"docroot": ws.docroot, "foreign": foreign, "unreadable": unreadable[:limit], "truncated": len(foreign) >= limit, "scanned": count}


# ------------------------------------------------------------------- databases
def _find_db_configs(ws):
    """Discover database credentials in site configuration files. Values stay inside the helper."""
    found = []
    candidates = []
    for source in ws.db_sources:
        candidates.append(source)
        try:
            names = os.listdir(ws.docroot)
        except OSError:
            names = []
        for name in names:
            if name.startswith("."):
                continue
            candidates.append(name + "/" + source)
    seen = set()
    for rel in candidates:
        try:
            abs_path, clean, st = ws.resolve(rel, must_exist=True)
        except HelperError:
            continue
        if not stat.S_ISREG(st.st_mode) or clean in seen:
            continue
        seen.add(clean)
        try:
            data, _ = _read_regular(abs_path, clean, st, 512 * 1024)
            text = data.decode("utf-8", "replace")
        except HelperError:
            continue
        for cred in _parse_db_config(text, os.path.basename(clean)):
            cred["source"] = clean
            found.append(cred)
    return found


def _parse_db_config(text, base):
    creds = []
    if base == "wp-config.php":
        values = {}
        for m in re.finditer(r"""define\s*\(\s*['"](DB_NAME|DB_USER|DB_PASSWORD|DB_HOST)['"]\s*,\s*['"]([^'"]*)['"]\s*\)""", text):
            values[m.group(1)] = m.group(2)
        if "DB_NAME" in values and "DB_USER" in values:
            creds.append({"database": values["DB_NAME"], "user": values["DB_USER"], "password": values.get("DB_PASSWORD", ""), "host": values.get("DB_HOST", "localhost")})
    elif base.startswith(".env"):
        values = {}
        for m in re.finditer(r"^\s*(DB_DATABASE|DB_USERNAME|DB_PASSWORD|DB_HOST|DB_NAME|DB_USER|DB_PASS|DATABASE_URL)\s*=\s*(.*)$", text, re.M):
            values[m.group(1)] = m.group(2).strip().strip("\"'")
        url = values.get("DATABASE_URL")
        if url:
            m = re.match(r"^mysql[a-z0-9+]*://([^:/@]+)(?::([^@]*))?@([^:/]+)(?::\d+)?/([^?\s]+)", url)
            if m:
                creds.append({"database": m.group(4), "user": m.group(1), "password": m.group(2) or "", "host": m.group(3)})
        name = values.get("DB_DATABASE") or values.get("DB_NAME")
        user = values.get("DB_USERNAME") or values.get("DB_USER")
        if name and user:
            creds.append({"database": name, "user": user, "password": values.get("DB_PASSWORD") or values.get("DB_PASS") or "", "host": values.get("DB_HOST", "localhost")})
    elif base == "configuration.php":
        values = {}
        for m in re.finditer(r"""public\s+\$(db|user|password|host)\s*=\s*['"]([^'"]*)['"]""", text):
            values[m.group(1)] = m.group(2)
        if "db" in values and "user" in values:
            creds.append({"database": values["db"], "user": values["user"], "password": values.get("password", ""), "host": values.get("host", "localhost")})
    elif base == "env.php":
        values = {}
        for m in re.finditer(r"""['"](dbname|username|password|host)['"]\s*=>\s*['"]([^'"]*)['"]""", text):
            values.setdefault(m.group(1), m.group(2))
        if "dbname" in values and "username" in values:
            creds.append({"database": values["dbname"], "user": values["username"], "password": values.get("password", ""), "host": values.get("host", "localhost")})
    elif base == "database.php":
        values = {}
        for m in re.finditer(r"""['"](database|username|password|hostname|host)['"]\s*=>\s*['"]([^'"]*)['"]""", text):
            values.setdefault(m.group(1), m.group(2))
        if "database" in values and "username" in values:
            creds.append({"database": values["database"], "user": values["username"], "password": values.get("password", ""), "host": values.get("hostname") or values.get("host") or "localhost"})
    return [c for c in creds if DB_NAME_RE.match(c["database"]) and IDENT_RE.match(c["user"])]


def _db_host_local(host):
    host = (host or "localhost").split(":")[0]
    return host in ("localhost", "127.0.0.1", "::1", "") or host.startswith("/")


def _db_credentials(ws, args):
    """Credentials for args['database']: stored (passed by the api) or discovered from site config."""
    database = args.get("database")
    if not isinstance(database, str) or not DB_NAME_RE.match(database):
        raise HelperError("bad_request", "invalid database name")
    stored = args.get("credentials")
    if isinstance(stored, dict) and isinstance(stored.get("user"), str) and isinstance(stored.get("password"), str):
        if not IDENT_RE.match(stored["user"]):
            raise HelperError("bad_request", "invalid database user")
        return database, stored["user"], stored["password"], "stored"
    for cred in _find_db_configs(ws):
        if cred["database"] == database:
            if not _db_host_local(cred.get("host")):
                raise HelperError("db_remote_host", "the configured database host is not local; only local databases are supported")
            return database, cred["user"], cred["password"], "config"
    raise HelperError("db_no_credentials", "no credentials known for database %s: none found in the site configuration and none stored on the account page" % database)


class MysqlSession(object):
    """Runs mysql / mysqldump with a private defaults file (0600, deleted afterwards)."""

    def __init__(self, ws, database, user, password):
        self.ws = ws
        self.database = database
        self.user = user
        self.tmpdir = ws._ensure_store("tmp")
        fd, self.defaults = tempfile.mkstemp(prefix="my-", suffix=".cnf", dir=self.tmpdir)
        with os.fdopen(fd, "w") as fh:
            fh.write("[client]\nuser=%s\npassword=%s\nhost=localhost\n" % (user, password.replace("\\", "\\\\").replace("\n", "")))
        os.chmod(self.defaults, 0o600)
        self.mysql = _which("mysql")
        self.mysqldump = _which("mysqldump")
        if not self.mysql:
            self.close()
            raise HelperError("db_cli_missing", "the mysql command line client is not installed on the server")

    def close(self):
        _unlink_quiet(self.defaults)

    def run(self, sql, time_limit, max_lines=None, database=None):
        cmd = [self.mysql, "--defaults-extra-file=" + self.defaults, "--batch", "--raw", "--default-character-set=utf8mb4", "--connect-timeout=5"]
        if database is not False:
            cmd.append(database or self.database)
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            proc.stdin.write(sql.encode("utf-8"))
            proc.stdin.close()
        except (BrokenPipeError, OSError):
            pass
        lines = []
        truncated = False
        deadline = time.time() + time_limit + 5
        for raw in proc.stdout:
            if max_lines is not None and len(lines) >= max_lines:
                truncated = True
                proc.kill()
                break
            lines.append(raw.decode("utf-8", "replace").rstrip("\n"))
            if time.time() > deadline:
                proc.kill()
                raise HelperError("db_timeout", "the query exceeded the time limit")
        try:
            proc.wait(timeout=time_limit + 5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        err = proc.stderr.read().decode("utf-8", "replace").strip()
        if proc.returncode != 0 and not truncated:
            raise HelperError("db_error", _clean_mysql_error(err))
        return lines, truncated

    def dump(self, tables, target_gz):
        if not self.mysqldump:
            raise HelperError("db_cli_missing", "mysqldump is not installed on the server")
        cmd = [self.mysqldump, "--defaults-extra-file=" + self.defaults, "--single-transaction", "--skip-comments", "--add-drop-table", "--default-character-set=utf8mb4", self.database] + list(tables)
        with gzip.open(target_gz, "wb") as out:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for chunk in iter(lambda: proc.stdout.read(65536), b""):
                out.write(chunk)
            proc.wait()
            if proc.returncode != 0:
                err = proc.stderr.read().decode("utf-8", "replace").strip()
                _unlink_quiet(target_gz)
                raise HelperError("db_error", "mysqldump failed: " + _clean_mysql_error(err))
        os.chmod(target_gz, 0o600)

    def restore(self, source_gz, time_limit):
        cmd = [self.mysql, "--defaults-extra-file=" + self.defaults, "--default-character-set=utf8mb4", self.database]
        with gzip.open(source_gz, "rb") as src:
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                shutil.copyfileobj(src, proc.stdin)
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass
            try:
                proc.wait(timeout=time_limit)
            except subprocess.TimeoutExpired:
                proc.kill()
                raise HelperError("db_timeout", "restoring the dump exceeded the time limit")
            if proc.returncode != 0:
                raise HelperError("db_error", "restore failed: " + _clean_mysql_error(proc.stderr.read().decode("utf-8", "replace").strip()))


def _which(name):
    for directory in ("/usr/bin", "/usr/local/bin", "/bin"):
        path = os.path.join(directory, name)
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def _clean_mysql_error(err):
    err = re.sub(r"\s*\[Warning\].*?\n", "", err)
    err = err.replace("mysql: ", "").strip()
    return err[:500] or "unknown database error"


def _strip_sql(sql):
    """Remove comments and string literals so keyword checks cannot be hidden."""
    out = []
    i = 0
    n = len(sql)
    while i < n:
        ch = sql[i]
        if ch in ("'", '"', "`"):
            quote = ch
            i += 1
            start = i
            while i < n:
                if sql[i] == "\\":
                    i += 2
                    continue
                if sql[i] == quote:
                    if i + 1 < n and sql[i + 1] == quote:
                        i += 2
                        continue
                    break
                i += 1
            if quote == "`":
                ident = sql[start:i]
                # plain quoted identifiers stay visible so the target table can be read; anything odd is masked
                out.append("`%s`" % ident if IDENT_RE.match(ident) else " `x` ")
            else:
                out.append(" '' ")
            i += 1
            continue
        if sql.startswith("--", i) or ch == "#":
            while i < n and sql[i] != "\n":
                i += 1
            out.append(" ")
            continue
        if sql.startswith("/*", i):
            if sql.startswith("/*!", i) or sql.startswith("/*+", i):
                # MySQL executes the content of /*! ... */ comments: never let them hide a keyword
                raise HelperError("bad_request", "executable comments (/*! ... */) are not allowed")
            end = sql.find("*/", i + 2)
            if end == -1:
                raise HelperError("bad_request", "unterminated comment")
            out.append(" ")
            i = end + 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_FORBIDDEN_ALWAYS = re.compile(r"\b(INTO\s+(?:OUTFILE|DUMPFILE)|LOAD_FILE|SLEEP|BENCHMARK|LOAD\s+DATA|HANDLER|LOCK\s+TABLES|UNLOCK\s+TABLES|GRANT|REVOKE|FLUSH|SHUTDOWN|KILL|CALL|DO|PREPARE|EXECUTE|DEALLOCATE)\b", re.I)
_WRITE_WORDS = re.compile(r"\b(INSERT|UPDATE|DELETE|REPLACE|CREATE|ALTER|DROP|TRUNCATE|RENAME|SET|START|COMMIT|ROLLBACK|SAVEPOINT|USE|OPTIMIZE|REPAIR|ANALYZE|INSTALL|UNINSTALL|RESET|PURGE|CHANGE|STOP|SIGNAL|RESIGNAL|LOAD|IMPORT|BEGIN|END)\b", re.I)
_DDL_WORDS = re.compile(r"\b(CREATE|ALTER|DROP|TRUNCATE|RENAME|GRANT|REVOKE|USE|START|COMMIT|ROLLBACK|SAVEPOINT|OPTIMIZE|REPAIR|ANALYZE|INSTALL|UNINSTALL|RESET|PURGE|CHANGE|STOP|SIGNAL|RESIGNAL|LOAD|IMPORT|BEGIN|END|SELECT\s+.*\bINTO\b)\b", re.I)


def _single_statement(sql):
    if not isinstance(sql, str) or not sql.strip():
        raise HelperError("bad_request", "sql must be a non-empty string")
    if len(sql) > 20000:
        raise HelperError("bad_request", "sql too long")
    if "\x00" in sql:
        raise HelperError("bad_request", "sql contains NUL")
    stripped = _strip_sql(sql).strip()
    body = stripped.rstrip(";").strip()
    if ";" in body:
        raise HelperError("bad_request", "only one statement is allowed")
    if "@" in body and re.search(r"@[A-Za-z0-9_@]*\s*:?=", body):
        raise HelperError("bad_request", "variable assignments are not allowed")
    if _FORBIDDEN_ALWAYS.search(body):
        raise HelperError("bad_request", "the statement uses a forbidden function or clause")
    return sql.strip().rstrip(";").strip(), body


def validate_read_sql(sql):
    original, body = _single_statement(sql)
    first = body.split(None, 1)[0].upper() if body else ""
    if first not in ("SELECT", "SHOW", "DESCRIBE", "DESC", "EXPLAIN", "WITH"):
        raise HelperError("bad_request", "only SELECT, SHOW, DESCRIBE and EXPLAIN are allowed")
    if _WRITE_WORDS.search(body):
        raise HelperError("bad_request", "the statement contains a write or control keyword")
    if re.search(r"\bFOR\s+UPDATE\b|\bLOCK\s+IN\s+SHARE\s+MODE\b|\bFOR\s+SHARE\b", body, re.I):
        raise HelperError("bad_request", "locking reads are not allowed")
    return original


def validate_write_sql(sql):
    original, body = _single_statement(sql)
    first = body.split(None, 1)[0].upper() if body else ""
    if first not in ("INSERT", "UPDATE", "DELETE"):
        raise HelperError("bad_request", "only INSERT, UPDATE and DELETE are allowed")
    if _DDL_WORDS.search(body):
        raise HelperError("bad_request", "DDL, transaction control and privilege statements are not allowed")
    if re.search(r"\bREPLACE\b", body, re.I) and first != "UPDATE":
        raise HelperError("bad_request", "REPLACE is not allowed")
    tables = _tables_of(body, first)
    if not tables:
        raise HelperError("bad_request", "could not determine the target table")
    return original, tables


def _tables_of(body, first):
    ident = r"`?([A-Za-z0-9_$]+)`?(?:\.`?([A-Za-z0-9_$]+)`?)?"
    tables = []
    if first == "INSERT":
        m = re.search(r"\bINSERT\s+(?:LOW_PRIORITY\s+|DELAYED\s+|HIGH_PRIORITY\s+)?(?:IGNORE\s+)?(?:INTO\s+)?" + ident, body, re.I)
        if m:
            tables.append(m.group(2) or m.group(1))
    elif first == "DELETE":
        m = re.search(r"\bDELETE\s+(?:LOW_PRIORITY\s+|QUICK\s+|IGNORE\s+)*FROM\s+" + ident, body, re.I)
        if m:
            tables.append(m.group(2) or m.group(1))
    elif first == "UPDATE":
        m = re.search(r"\bUPDATE\s+(?:LOW_PRIORITY\s+|IGNORE\s+)*(.+?)\s+SET\b", body, re.I | re.S)
        if m:
            for part in re.split(r",|\bJOIN\b", m.group(1), flags=re.I):
                im = re.match(r"\s*(?:LEFT\s+|RIGHT\s+|INNER\s+|OUTER\s+|CROSS\s+)*" + ident, part, re.I)
                if im:
                    tables.append(im.group(2) or im.group(1))
    return [t for t in dict.fromkeys(tables) if IDENT_RE.match(t)]


def _parse_batch(lines):
    if not lines:
        return [], []
    columns = lines[0].split("\t")
    rows = [line.split("\t") for line in lines[1:]]
    return columns, rows


def _redact_rows(ws, columns, rows):
    sensitive = [i for i, c in enumerate(columns) if any(p and p in c.lower() for p in ws.redact_columns)]
    if not sensitive:
        return rows, []
    out = []
    for row in rows:
        row = list(row)
        for i in sensitive:
            if i < len(row) and row[i] not in ("NULL", ""):
                row[i] = REDACTED
        out.append(row)
    return out, [columns[i] for i in sensitive]


def _server_prelude(session, time_limit):
    lines, _ = session.run("SELECT VERSION();", 5, database=False)
    version = lines[1] if len(lines) > 1 else ""
    if "mariadb" in version.lower():
        return "SET SESSION max_statement_time=%d;\n" % time_limit, version
    return "SET SESSION MAX_EXECUTION_TIME=%d;\n" % (time_limit * 1000), version


def _db_size(ws, database, user, password):
    """Data plus index size of the database in bytes, or None when it cannot be read."""
    try:
        session = MysqlSession(ws, database, user, password)
    except HelperError:
        return None
    try:
        lines, _ = session.run("SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = DATABASE();", 5)
        columns, rows = _parse_batch(lines)
        return int(rows[0][0]) if rows else 0
    except (HelperError, ValueError, IndexError):
        return None
    finally:
        session.close()


def op_db_list(ws, args):
    """Databases of the subscription with their credential source.

    `databases` are the names Plesk reports for the webspace (api), `stored`
    the names with credentials on the account page, `created` the names the
    service created itself. Sizes are read with the credentials where known.
    """
    configured = {}
    for cred in _find_db_configs(ws):
        configured.setdefault(cred["database"], cred)
    known = args.get("databases") or []
    stored = args.get("stored") or []
    created = set(n for n in (args.get("created") or []) if isinstance(n, str))
    stored_creds = args.get("stored_credentials") or {}
    names = []
    for name in list(known) + list(configured.keys()) + list(stored):
        if isinstance(name, str) and DB_NAME_RE.match(name) and name not in names:
            names.append(name)
    result = []
    for name in names:
        size = None
        if name in created and name in stored_creds:
            source = "service"
        elif name in configured:
            source = "config"
        elif name in stored_creds or name in stored:
            source = "stored"
        else:
            source = "missing"
        if args.get("sizes", True):
            cred = stored_creds.get(name) if isinstance(stored_creds, dict) else None
            if isinstance(cred, dict) and isinstance(cred.get("user"), str) and isinstance(cred.get("password"), str) and IDENT_RE.match(cred["user"]):
                size = _db_size(ws, name, cred["user"], cred["password"])
            elif name in configured and _db_host_local(configured[name].get("host")):
                size = _db_size(ws, name, configured[name]["user"], configured[name]["password"])
        result.append({"database": name, "credentials": source, "config_file": configured[name]["source"] if name in configured else None, "size_bytes": size, "service_created": name in created})
    return {"databases": result}


def op_db_schema(ws, args):
    database, user, password, source = _db_credentials(ws, args)
    table = args.get("table")
    session = MysqlSession(ws, database, user, password)
    try:
        prelude, _ = _server_prelude(session, ws.limits["db_query_time_limit"])
        if table:
            if not isinstance(table, str) or not IDENT_RE.match(table):
                raise HelperError("bad_request", "invalid table name")
            lines, _ = session.run(prelude + "SHOW FULL COLUMNS FROM `%s`;" % table, ws.limits["db_query_time_limit"])
            columns, rows = _parse_batch(lines)
            return {"database": database, "table": table, "columns": [dict(zip(columns, r)) for r in rows], "credentials": source}
        lines, _ = session.run(prelude + "SHOW TABLE STATUS;", ws.limits["db_query_time_limit"])
        columns, rows = _parse_batch(lines)
        tables = []
        for r in rows:
            d = dict(zip(columns, r))
            tables.append({"name": d.get("Name"), "rows": d.get("Rows"), "engine": d.get("Engine"), "data_length": d.get("Data_length"), "collation": d.get("Collation")})
        return {"database": database, "tables": tables, "credentials": source}
    finally:
        session.close()


def op_db_query(ws, args):
    database, user, password, source = _db_credentials(ws, args)
    sql = validate_read_sql(args.get("sql"))
    max_rows = ws.limits["db_max_rows"]
    session = MysqlSession(ws, database, user, password)
    try:
        prelude, _ = _server_prelude(session, ws.limits["db_query_time_limit"])
        script = prelude + "START TRANSACTION READ ONLY;\n" + sql + ";\nROLLBACK;\n"
        lines, truncated = session.run(script, ws.limits["db_query_time_limit"], max_lines=max_rows + 1)
        columns, rows = _parse_batch(lines)
        rows, redacted = _redact_rows(ws, columns, rows)
        return {"database": database, "columns": columns, "rows": rows, "returned": len(rows), "truncated": truncated, "redacted_columns": redacted, "credentials": source}
    finally:
        session.close()


def _db_dump_dir(ws, database):
    return ws._ensure_store("db", database)


def _write_dump(ws, session, tables, reason):
    dump_id = _new_id()
    ddir = _db_dump_dir(ws, session.database)
    target = os.path.join(ddir, dump_id + ".sql.gz")
    _call_write(lambda: session.dump(tables, target), "", ws)
    st = os.lstat(target)
    _write_json(
        os.path.join(ddir, dump_id + ".json"),
        {"kind": "db_dump", "domain": ws.domain, "database": session.database, "tables": list(tables), "full": not tables, "size": st.st_size, "created_at": _iso(time.time()), "reason": reason, "tool": ws.tool, "request_id": ws.request_id},
    )
    ws.account_written(st.st_size)
    return dump_id, st.st_size


def op_db_execute(ws, args):
    database, user, password, source = _db_credentials(ws, args)
    sql, tables = validate_write_sql(args.get("sql"))
    confirm = bool(args.get("confirm", False))
    max_affected = ws.limits["db_max_affected_rows"]
    time_limit = ws.limits["db_query_time_limit"]
    session = MysqlSession(ws, database, user, password)
    try:
        prelude, _ = _server_prelude(session, time_limit)
        lines, _ = session.run(prelude + "SHOW TABLES;", time_limit)
        existing = {r[0] for r in _parse_batch(lines)[1]}
        missing = [t for t in tables if t not in existing]
        if missing:
            raise HelperError("bad_request", "table does not exist: " + ", ".join(missing))
        preview = prelude + "START TRANSACTION;\n" + sql + ";\nSELECT ROW_COUNT() AS affected;\nROLLBACK;\n"
        lines, _ = session.run(preview, time_limit)
        columns, rows = _parse_batch(lines)
        affected = 0
        for r in rows:
            try:
                affected = int(r[0])
            except (ValueError, IndexError):
                pass
        if not confirm:
            return {"database": database, "tables": tables, "affected_rows": affected, "preview": True, "credentials": source}
        if affected > max_affected:
            raise HelperError("too_many_rows", "the statement would change %d rows, more than the limit of %d" % (affected, max_affected))
        dump_id, dump_size = _write_dump(ws, session, tables, "db_execute")
        script = prelude + "START TRANSACTION;\n" + sql + ";\nSELECT ROW_COUNT() AS affected;\nCOMMIT;\n"
        lines, _ = session.run(script, time_limit)
        columns, rows = _parse_batch(lines)
        real = affected
        for r in rows:
            try:
                real = int(r[0])
            except (ValueError, IndexError):
                pass
        ws.run_retention()
        return {"database": database, "tables": tables, "affected_rows": real, "preview": False, "dump_id": dump_id, "dump_bytes": dump_size, "credentials": source}
    finally:
        session.close()


def op_db_restore(ws, args):
    database = args.get("database")
    if not isinstance(database, str) or not DB_NAME_RE.match(database):
        raise HelperError("bad_request", "invalid database name")
    dump_id = args.get("dump_id")
    ddir = os.path.join(ws.store_dir, "db", database)
    if not dump_id:
        dumps = []
        if os.path.isdir(ddir):
            for name in sorted(os.listdir(ddir), reverse=True):
                if name.endswith(".json"):
                    meta = _read_json(os.path.join(ddir, name)) or {}
                    dumps.append({"id": name[:-5], "tables": meta.get("tables"), "full": bool(meta.get("full")), "created_at": meta.get("created_at"), "size": meta.get("size"), "reason": meta.get("reason")})
        return {"database": database, "dumps": dumps}
    if not isinstance(dump_id, str) or not ID_RE.match(dump_id):
        raise HelperError("bad_request", "invalid dump id")
    meta = _read_json(os.path.join(ddir, dump_id + ".json"))
    source_gz = os.path.join(ddir, dump_id + ".sql.gz")
    if not meta or not os.path.isfile(source_gz):
        raise HelperError("not_found", "dump not found")
    if meta.get("domain") != ws.domain:
        raise HelperError("refused", "dump belongs to another domain")
    if not args.get("confirm"):
        return {"database": database, "dump": {"id": dump_id, "tables": meta.get("tables"), "full": bool(meta.get("full")), "created_at": meta.get("created_at"), "size": meta.get("size")}, "preview": True}
    if meta.get("full") and not args.get("allow_full"):
        raise HelperError("forbidden", "restoring a full database dump needs the db:admin scope")
    db_name, user, password, source = _db_credentials(ws, args)
    session = MysqlSession(ws, db_name, user, password)
    try:
        before_id, _ = _write_dump(ws, session, meta.get("tables") or [], "db_restore")
        session.restore(source_gz, ws.limits["time_limit"])
        ws.run_retention()
        return {"database": database, "restored_dump": dump_id, "tables": meta.get("tables"), "backup_of_previous": before_id, "preview": False}
    finally:
        session.close()


_DDL_ALLOWED = re.compile(r"^(CREATE\s+TABLE|CREATE\s+(?:UNIQUE\s+|FULLTEXT\s+)?INDEX|ALTER\s+TABLE|DROP\s+INDEX|RENAME\s+TABLE)\b", re.I)
_DDL_FORBIDDEN = re.compile(r"\b(DATABASE|SCHEMA|USER|GRANT|REVOKE|PRIVILEGES|TABLESPACE|SERVER|EVENT|TRIGGER|PROCEDURE|FUNCTION|VIEW|DATA\s+DIRECTORY|INDEX\s+DIRECTORY|DROP\s+TABLE|TRUNCATE)\b", re.I)


def validate_ddl_sql(sql):
    """One CREATE TABLE / ALTER TABLE / CREATE INDEX / DROP INDEX / RENAME TABLE statement, nothing else."""
    original, body = _single_statement(sql)
    if not _DDL_ALLOWED.match(body):
        raise HelperError("bad_request", "only CREATE TABLE, ALTER TABLE, CREATE INDEX, DROP INDEX and RENAME TABLE are allowed")
    if _DDL_FORBIDDEN.search(body):
        raise HelperError("bad_request", "the statement touches databases, users, privileges or drops tables; that is not allowed here")
    if re.search(r"`?[A-Za-z0-9_$]+`?\s*\.\s*`?[A-Za-z0-9_$]+`?\s*(\(|$|\s)", body) and re.search(r"\b(?:TABLE|INDEX|ON)\s+`?[A-Za-z0-9_$]+`?\.`?[A-Za-z0-9_$]+`?", body, re.I):
        raise HelperError("bad_request", "qualified names (database.table) are not allowed; the statement runs inside the selected database")
    tables = []
    for m in re.finditer(r"\b(?:TABLE|ON|TO)\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([A-Za-z0-9_$]+)`?", body, re.I):
        if m.group(1) and IDENT_RE.match(m.group(1)) and m.group(1) not in tables:
            tables.append(m.group(1))
    return original, tables


def op_db_apply_schema(ws, args):
    """DDL on the customer's database: preview (parsed statement, affected tables) or, with confirm, a full dump and the change."""
    database, user, password, source = _db_credentials(ws, args)
    sql, tables = validate_ddl_sql(args.get("sql"))
    confirm = bool(args.get("confirm", False))
    time_limit = ws.limits["db_query_time_limit"]
    session = MysqlSession(ws, database, user, password)
    try:
        prelude, _ = _server_prelude(session, time_limit)
        lines, _ = session.run(prelude + "SHOW TABLES;", time_limit)
        existing = sorted(r[0] for r in _parse_batch(lines)[1])
        before = {}
        for t in tables:
            if t in existing:
                cols, _ = session.run("SHOW COLUMNS FROM `%s`;" % t, time_limit)
                before[t] = [r[0] for r in _parse_batch(cols)[1]]
        if not confirm:
            return {"database": database, "statement": sql, "tables": tables, "existing_tables": [t for t in tables if t in existing], "columns_before": before, "preview": True, "credentials": source}
        dump_id, dump_size = _write_dump(ws, session, [], "db_apply_schema")
        session.run(prelude + sql + ";", time_limit)
        after = {}
        lines, _ = session.run("SHOW TABLES;", time_limit)
        now_existing = sorted(r[0] for r in _parse_batch(lines)[1])
        for t in tables + [t for t in now_existing if t not in existing]:
            if t in now_existing and t not in after:
                cols, _ = session.run("SHOW COLUMNS FROM `%s`;" % t, time_limit)
                after[t] = [r[0] for r in _parse_batch(cols)[1]]
        ws.run_retention()
        return {"database": database, "tables": tables, "columns_before": before, "columns_after": after, "preview": False, "dump_id": dump_id, "dump_bytes": dump_size, "full_dump": True, "credentials": source}
    finally:
        session.close()


def op_db_dump(ws, args):
    """Full dump of a database into the store (used before db_drop and on request)."""
    database, user, password, source = _db_credentials(ws, args)
    reason = args.get("reason") if isinstance(args.get("reason"), str) and re.match(r"^[a-z_]{1,40}$", args.get("reason")) else "db_dump"
    session = MysqlSession(ws, database, user, password)
    try:
        dump_id, dump_size = _write_dump(ws, session, [], reason)
        ws.run_retention()
        return {"database": database, "dump_id": dump_id, "dump_bytes": dump_size, "full": True, "credentials": source}
    finally:
        session.close()


def _db_creds_dir(ws, create):
    private = os.path.join(ws.home, "private")
    if create:
        try:
            os.mkdir(private, 0o700)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
    st = os.lstat(private) if os.path.lexists(private) else None
    if st is None:
        raise HelperError("not_found", "the subscription has no private directory")
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != ws.uid:
        raise HelperError("refused", "the private directory is not a directory owned by the system user")
    target = os.path.join(private, DB_CREDS_DIRNAME)
    if create:
        _mkdir_private(target)
    return target


def op_db_credentials_file(ws, args):
    """Write <home>/private/pleskmcp-db/<database>.env (0600) for a service-created database. Values never appear in the result."""
    database = args.get("database")
    user = args.get("user")
    password = args.get("password")
    if not isinstance(database, str) or not DB_NAME_RE.match(database):
        raise HelperError("bad_request", "invalid database name")
    if not isinstance(user, str) or not IDENT_RE.match(user) or not isinstance(password, str) or not password:
        raise HelperError("bad_request", "invalid credentials")
    cdir = _db_creds_dir(ws, True)
    target = os.path.join(cdir, database + ".env")
    body = "DB_HOST=localhost\nDB_NAME=%s\nDB_USER=%s\nDB_PASSWORD=%s\n" % (database, user, password.replace("\n", ""))

    def do_write():
        fd, tmp = tempfile.mkstemp(prefix=".env-", dir=cdir)
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(body)
            os.chmod(tmp, 0o600)
            os.rename(tmp, target)
        except BaseException:
            _unlink_quiet(tmp)
            raise

    _call_write(do_write, "", ws)
    return {"database": database, "credentials_file": os.path.relpath(target, ws.home)}


def op_db_credentials_remove(ws, args):
    database = args.get("database")
    if not isinstance(database, str) or not DB_NAME_RE.match(database):
        raise HelperError("bad_request", "invalid database name")
    try:
        cdir = _db_creds_dir(ws, False)
    except HelperError:
        return {"database": database, "removed": False}
    target = os.path.join(cdir, database + ".env")
    removed = os.path.lexists(target)
    _unlink_quiet(target)
    return {"database": database, "removed": removed}


OPS = {
    "ping": lambda ws, args: {"uid": ws.uid, "home": ws.home, "docroot": ws.docroot, "version": 2},
    "list_dir": op_list_dir,
    "stat": op_stat,
    "read_file": op_read_file,
    "write_file": op_write_file,
    "replace_in_file": op_replace_in_file,
    "move_file": op_move_file,
    "delete_file": op_delete_file,
    "restore_file": op_restore_file,
    "list_versions": op_list_versions,
    "restore_version": op_restore_version,
    "list_changes": op_list_changes,
    "search_log": op_search_log,
    "store_write": op_store_write,
    "store_list": op_store_list,
    "store_read": op_store_read,
    "storage_status": op_storage_status,
    "purge_store": op_purge_store,
    "retention": op_retention,
    "report_ownership": op_report_ownership,
    "db_list": op_db_list,
    "db_schema": op_db_schema,
    "db_query": op_db_query,
    "db_execute": op_db_execute,
    "db_restore": op_db_restore,
    "db_apply_schema": op_db_apply_schema,
    "db_dump": op_db_dump,
    "db_credentials_file": op_db_credentials_file,
    "db_credentials_remove": op_db_credentials_remove,
}


def handle(request):
    if not isinstance(request, dict):
        raise HelperError("bad_request", "request must be an object")
    op = request.get("op")
    if op not in OPS:
        raise HelperError("bad_request", "unknown operation")
    ws = Workspace(request.get("domain"), request.get("docroot"), request.get("limits"), request.get("request_id"), request.get("tool") or op)
    args = request.get("args") or {}
    if not isinstance(args, dict):
        raise HelperError("bad_request", "args must be an object")
    time_limit = ws.limits["time_limit"]
    if hasattr(signal, "SIGALRM") and time_limit > 0:
        signal.signal(signal.SIGALRM, _alarm)
        signal.alarm(time_limit)
    try:
        if op in WRITE_OPS and ws.request_id:
            replay = ws.idem_lookup(op)
            if replay is not None:
                return replay
        result = OPS[op](ws, args)
        if op in WRITE_OPS and ws.request_id and not (isinstance(result, dict) and result.get("preview")):
            ws.idem_store(op, result)
        return result
    except TimeLimit:
        raise HelperError("timeout", "the operation exceeded the time limit of %d seconds" % time_limit)
    finally:
        if hasattr(signal, "SIGALRM"):
            signal.alarm(0)


def main():
    raw = sys.stdin.buffer.read(64 * 1024 * 1024)
    try:
        request = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        _emit({"ok": False, "error": "bad_request", "message": "request is not valid JSON"})
        return 2
    try:
        result = handle(request)
    except HelperError as exc:
        out = {"ok": False, "error": exc.code, "message": exc.message}
        if exc.details:
            out["details"] = exc.details
        _emit(out)
        return 1
    except OSError as exc:
        _emit({"ok": False, "error": "io_error", "message": "%s" % (exc.strerror or exc)})
        return 1
    _emit({"ok": True, "result": result})
    return 0


def _emit(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False))
    sys.stdout.write("\n")
    sys.stdout.flush()


if __name__ == "__main__":
    sys.exit(main())
