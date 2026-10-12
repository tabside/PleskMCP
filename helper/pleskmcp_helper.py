#!/usr/libexec/platform-python
# -*- coding: utf-8 -*-
"""PleskMCP helper: file operations inside one subscription, run as its system user.

Installed on the Plesk server as /usr/local/bin/pleskmcp-helper (root owned,
0755) and started by the MCP service via
    sudo -n -u <sysuser> /usr/local/bin/pleskmcp-helper
with a JSON request on stdin. It prints one JSON object to stdout.

Must stay compatible with Python 3.6 (CloudLinux 8 platform-python).

Security model:
* runs with the uid/gid of the subscription's system user, never root;
* only operates below the document root passed in the request, after
  checking that the document root is inside the user's own home
  (/var/www/vhosts/<subscription>) and owned by the user;
* paths are normalised, must stay below the document root and must not
  traverse any symbolic link;
* backups and the trash live in <home>/.pleskmcp, outside every document root.
"""

import base64
import errno
import json
import os
import pwd
import re
import shutil
import stat
import sys
import tempfile
import time

VHOSTS_BASE = "/var/www/vhosts"
STORE_DIRNAME = ".pleskmcp"
BACKUPS_KEEP = 20
TRASH_ID_RE = re.compile(r"^[0-9]{14}-[A-Za-z0-9_-]{6,16}$")
LOG_NAME_RE = re.compile(
    r"^(access_log|access_ssl_log|error_log|proxy_access_log|proxy_access_ssl_log|proxy_error_log)"
    r"(\.processed|\.[0-9]+|-[0-9]{8})?(\.gz)?$"
)

DEFAULT_LIMITS = {
    "read_max_bytes": 2 * 1024 * 1024,
    "write_max_bytes": 5 * 1024 * 1024,
    "list_max_entries": 2000,
    "log_max_lines": 500,
}


class HelperError(Exception):
    def __init__(self, code, message):
        Exception.__init__(self, message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------- paths
class Workspace(object):
    """One (domain, docroot) pair validated against the current user."""

    def __init__(self, domain, docroot, limits):
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
        if os.path.basename(real) == STORE_DIRNAME or (real.startswith(self.store_dir + "/")):
            raise HelperError("refused", "document root must not be the helper store")
        self.docroot = real

        self.limits = dict(DEFAULT_LIMITS)
        if isinstance(limits, dict):
            for key in DEFAULT_LIMITS:
                value = limits.get(key)
                if isinstance(value, int) and value > 0:
                    self.limits[key] = value

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

    def normalize(self, rel):
        """Validate a client supplied relative path. Returns the clean relative path ('' for the docroot)."""
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
                    # Missing component: nothing below it can exist, so the remaining
                    # components need no symlink check. Callers decide whether to create it.
                    current = os.path.join(current, *parts[index + 1:]) if index + 1 < len(parts) else current
                    st = None
                    break
                raise HelperError("io_error", "cannot access path: " + clean)
            if stat.S_ISLNK(st.st_mode):
                raise HelperError("refused", "symbolic links are not allowed: " + clean)
        real = os.path.realpath(current)
        if not (real == self.docroot or real.startswith(self.docroot + "/")):
            raise HelperError("refused", "path escapes the document root")
        return current, clean, st

    # ------------------------------------------------------------- backups/trash
    def backup_file(self, abs_path, clean):
        """Copy an existing regular file to the backup area. Returns the backup id."""
        bdir = self._ensure_store("backups", self.domain_dir)
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
        safe = clean.replace("/", "__") or "_"
        target = os.path.join(bdir, "%s.%s" % (safe, stamp))
        counter = 0
        while os.path.lexists(target):
            counter += 1
            target = os.path.join(bdir, "%s.%s.%d" % (safe, stamp, counter))
        fd = os.open(abs_path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
        try:
            with os.fdopen(fd, "rb") as src:
                with open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)
        except BaseException:
            try:
                os.unlink(target)
            except OSError:
                pass
            raise
        os.chmod(target, 0o600)
        self._prune_backups(bdir, safe + ".")
        return os.path.basename(target)

    def _prune_backups(self, bdir, prefix):
        entries = sorted(e for e in os.listdir(bdir) if e.startswith(prefix))
        for name in entries[:-BACKUPS_KEEP]:
            try:
                os.unlink(os.path.join(bdir, name))
            except OSError:
                pass

    def trash_dir(self):
        return self._ensure_store("trash")

    def move_to_trash(self, abs_path, clean, st):
        tdir = self.trash_dir()
        stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
        trash_id = "%s-%s" % (stamp, _random_token(8))
        entry = os.path.join(tdir, trash_id)
        _mkdir_private(entry)
        kind = "dir" if stat.S_ISDIR(st.st_mode) else ("symlink" if stat.S_ISLNK(st.st_mode) else "file")
        payload = os.path.join(entry, "payload")
        os.rename(abs_path, payload)
        meta = {
            "domain": self.domain,
            "docroot": self.docroot,
            "path": clean,
            "type": kind,
            "deleted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "size": st.st_size if kind == "file" else None,
        }
        with open(os.path.join(entry, "meta.json"), "w") as fh:
            json.dump(meta, fh)
        return trash_id, meta

    def list_trash(self):
        tdir = self.trash_dir()
        items = []
        for name in sorted(os.listdir(tdir)):
            if not TRASH_ID_RE.match(name):
                continue
            meta_path = os.path.join(tdir, name, "meta.json")
            try:
                with open(meta_path) as fh:
                    meta = json.load(fh)
            except (OSError, ValueError):
                continue
            if meta.get("domain") != self.domain:
                continue
            meta["id"] = name
            items.append(meta)
        return items

    def restore_from_trash(self, trash_id):
        if not isinstance(trash_id, str) or not TRASH_ID_RE.match(trash_id):
            raise HelperError("bad_request", "invalid trash id")
        entry = os.path.join(self.trash_dir(), trash_id)
        meta_path = os.path.join(entry, "meta.json")
        try:
            with open(meta_path) as fh:
                meta = json.load(fh)
        except (OSError, ValueError):
            raise HelperError("not_found", "trash entry not found")
        if meta.get("domain") != self.domain or meta.get("docroot") != self.docroot:
            raise HelperError("refused", "trash entry belongs to another domain")
        target, clean, st = self.resolve(meta.get("path", ""), must_exist=False)
        if st is not None or os.path.lexists(target):
            raise HelperError("exists", "target already exists: " + clean)
        parent = os.path.dirname(target)
        if not os.path.isdir(parent):
            self.ensure_parents(clean)
        os.rename(os.path.join(entry, "payload"), target)
        try:
            os.unlink(meta_path)
            os.rmdir(entry)
        except OSError:
            pass
        return {"path": clean, "type": meta.get("type")}

    def ensure_parents(self, clean):
        """Create missing parent directories of `clean` (all checked against the docroot)."""
        parts = clean.split("/")[:-1]
        current = ""
        for part in parts:
            current = part if not current else current + "/" + part
            abs_path, _, st = self.resolve(current, must_exist=False)
            if st is None:
                os.mkdir(abs_path, 0o755)
            elif not stat.S_ISDIR(st.st_mode):
                raise HelperError("not_dir", "not a directory: " + current)

    # ----------------------------------------------------------------- writing
    def write_atomic(self, abs_path, clean, data, existing_st):
        parent = os.path.dirname(abs_path)
        mode = stat.S_IMODE(existing_st.st_mode) if existing_st is not None else 0o644
        fd, tmp = tempfile.mkstemp(prefix=".pleskmcp-", dir=parent)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.chmod(tmp, mode)
            # Re-check right before the rename: the target must still not be a symlink.
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


class _open_nofollow(object):
    def __init__(self, path, flags):
        self.fd = os.open(path, flags | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))

    def __enter__(self):
        return self.fd

    def __exit__(self, *exc):
        os.close(self.fd)
        return False


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _entry_type(st):
    if stat.S_ISDIR(st.st_mode):
        return "dir"
    if stat.S_ISREG(st.st_mode):
        return "file"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    return "other"


def _read_regular(abs_path, clean, st, max_bytes, offset=0):
    if not stat.S_ISREG(st.st_mode):
        raise HelperError("not_file", "not a regular file: " + clean)
    with _open_nofollow(abs_path, os.O_RDONLY) as fd:
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


# ------------------------------------------------------------------- operations
def op_list_dir(ws, args):
    abs_path, clean, st = ws.resolve(args.get("path", ""))
    if not stat.S_ISDIR(st.st_mode):
        raise HelperError("not_dir", "not a directory: " + (clean or "."))
    limit = ws.limits["list_max_entries"]
    names = sorted(os.listdir(abs_path))
    entries = []
    for name in names[:limit]:
        try:
            est = os.lstat(os.path.join(abs_path, name))
        except OSError:
            continue
        entries.append(
            {
                "name": name,
                "type": _entry_type(est),
                "size": est.st_size if stat.S_ISREG(est.st_mode) else None,
                "mtime": _iso(est.st_mtime),
                "mode": "%04o" % stat.S_IMODE(est.st_mode),
            }
        )
    return {"path": clean, "entries": entries, "truncated": len(names) > limit, "total": len(names)}


def op_stat(ws, args):
    abs_path, clean, st = ws.resolve(args.get("path", ""))
    return {"path": clean, "type": _entry_type(st), "size": st.st_size, "mtime": _iso(st.st_mtime), "mode": "%04o" % stat.S_IMODE(st.st_mode)}


def op_read_file(ws, args):
    abs_path, clean, st = ws.resolve(args.get("path"))
    encoding = args.get("encoding", "text")
    offset = args.get("offset", 0)
    if not isinstance(offset, int) or offset < 0:
        raise HelperError("bad_request", "offset must be a non-negative integer")
    max_bytes = ws.limits["read_max_bytes"]
    requested = args.get("max_bytes")
    if isinstance(requested, int) and 0 < requested < max_bytes:
        max_bytes = requested
    data, truncated = _read_regular(abs_path, clean, st, max_bytes, offset)
    result = {"path": clean, "size": st.st_size, "offset": offset, "returned": len(data), "truncated": truncated}
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
    if st is None:
        if args.get("create_dirs"):
            ws.ensure_parents(clean)
        elif not os.path.isdir(os.path.dirname(abs_path)):
            raise HelperError("not_found", "parent directory does not exist (use create_dirs)")
    elif not stat.S_ISREG(st.st_mode):
        raise HelperError("not_file", "target exists and is not a regular file: " + clean)
    backup_id = None
    if st is not None and args.get("backup", True):
        backup_id = ws.backup_file(abs_path, clean)
    ws.write_atomic(abs_path, clean, data, st)
    return {"path": clean, "size": len(data), "created": st is None, "backup": backup_id}


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
        raise HelperError("no_match", "old_str not found in file")
    if count > 1 and not replace_all:
        raise HelperError("ambiguous", "old_str occurs %d times; set replace_all=true to replace every occurrence" % count)
    updated = text.replace(old_eff, new_eff) if replace_all else text.replace(old_eff, new_eff, 1)
    encoded = updated.encode("utf-8")
    if len(encoded) > limit:
        raise HelperError("too_large", "result exceeds the write limit")
    backup_id = ws.backup_file(abs_path, clean)
    ws.write_atomic(abs_path, clean, encoded, st)
    return {"path": clean, "replacements": count if replace_all else 1, "size": len(encoded), "backup": backup_id}


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
        backup_id = ws.backup_file(dst_abs, dst_clean)
    os.rename(src_abs, dst_abs)
    return {"src": src_clean, "dst": dst_clean, "backup": backup_id}


def op_delete_file(ws, args):
    abs_path, clean, st = ws.resolve(args.get("path"))
    if not clean:
        raise HelperError("refused", "the document root itself cannot be deleted")
    if stat.S_ISDIR(st.st_mode) and not args.get("recursive"):
        raise HelperError("is_dir", "path is a directory; set recursive=true to move it to the trash")
    trash_id, meta = ws.move_to_trash(abs_path, clean, st)
    return {"path": clean, "type": meta["type"], "trash_id": trash_id}


def op_restore_file(ws, args):
    trash_id = args.get("trash_id")
    if not trash_id:
        return {"entries": ws.list_trash()}
    return ws.restore_from_trash(trash_id)


def op_store_write(ws, args):
    """Keep a copy of data (e.g. a DNS zone export) in the helper store, outside every docroot."""
    category = args.get("category")
    if category not in ("dns",):
        raise HelperError("bad_request", "unknown store category")
    content = args.get("content")
    if not isinstance(content, str) or len(content) > ws.limits["write_max_bytes"]:
        raise HelperError("bad_request", "content missing or too large")
    sdir = ws._ensure_store(category, ws.domain_dir)
    stamp = time.strftime("%Y%m%d%H%M%S", time.gmtime())
    name = "%s.json" % stamp
    target = os.path.join(sdir, name)
    counter = 0
    while os.path.lexists(target):
        counter += 1
        target = os.path.join(sdir, "%s.%d.json" % (stamp, counter))
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(content)
    os.chmod(target, 0o600)
    ws._prune_backups(sdir, "")
    return {"backup": os.path.relpath(target, ws.home)}


def op_search_log(ws, args):
    name = args.get("log", "access_log")
    if not isinstance(name, str) or not LOG_NAME_RE.match(name):
        raise HelperError("bad_request", "unknown log name")
    kind = args.get("kind", "webspace")
    logs_dir = os.path.join(ws.home, "logs")
    if kind != "webspace":
        logs_dir = os.path.join(logs_dir, ws.domain)
    # Plesk keeps addon domain logs under /var/www/vhosts/system/<domain>/logs, reached through a symlink.
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
    max_lines = ws.limits["log_max_lines"]
    wanted = args.get("lines", 200)
    if not isinstance(wanted, int) or wanted <= 0:
        wanted = 200
    wanted = min(wanted, max_lines)
    opener = open
    if name.endswith(".gz"):
        import gzip

        opener = gzip.open
    matches = []
    scanned = 0
    with opener(path, "rb") as fh:
        for raw in fh:
            scanned += 1
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if regex is None or regex.search(line):
                matches.append(line)
                if len(matches) > wanted:
                    del matches[0]
    return {"log": name, "lines": matches, "returned": len(matches), "scanned": scanned, "size": st.st_size}


OPS = {
    "ping": lambda ws, args: {"uid": ws.uid, "home": ws.home, "docroot": ws.docroot},
    "list_dir": op_list_dir,
    "stat": op_stat,
    "read_file": op_read_file,
    "write_file": op_write_file,
    "replace_in_file": op_replace_in_file,
    "move_file": op_move_file,
    "delete_file": op_delete_file,
    "restore_file": op_restore_file,
    "search_log": op_search_log,
    "store_write": op_store_write,
}


def handle(request):
    if not isinstance(request, dict):
        raise HelperError("bad_request", "request must be an object")
    op = request.get("op")
    if op not in OPS:
        raise HelperError("bad_request", "unknown operation")
    ws = Workspace(request.get("domain"), request.get("docroot"), request.get("limits"))
    args = request.get("args") or {}
    if not isinstance(args, dict):
        raise HelperError("bad_request", "args must be an object")
    return OPS[op](ws, args)


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
        _emit({"ok": False, "error": exc.code, "message": exc.message})
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
