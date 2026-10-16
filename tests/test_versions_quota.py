"""Versions, change log, retention and quota enforcement (helper level and through the tools)."""

from __future__ import annotations

import errno
import json
import os
import time
from collections import namedtuple
from pathlib import Path

import pytest

from conftest import Env, OAuthFlow, call_tool, load_helper_module, structured, tool_text

pytestmark = pytest.mark.anyio

GB = 1024**3


@pytest.fixture
def helper(tmp_path: Path):
    if os.getuid() == 0:
        pytest.skip("helper refuses to run as root")
    module = load_helper_module()
    vhosts = tmp_path / "vhosts"
    vhosts.mkdir()
    module.VHOSTS_BASE = str(vhosts)
    Passwd = namedtuple("Passwd", "pw_dir pw_name")
    home = vhosts / "example.com"
    (home / "httpdocs").mkdir(parents=True)
    module.pwd.getpwuid = lambda uid: Passwd(str(home), "example_sys")

    def factory(limits=None, request_id=None, tool=None, domain="example.com"):
        return module.Workspace(domain, str(home / "httpdocs"), limits, request_id, tool)

    return module, home, factory


def run(module, ws, op, **args):
    return module.OPS[op](ws, args)


def age(path: Path, days: float) -> None:
    """Move an entry's created_at back in time (versions, trash, db dumps carry it in meta.json)."""
    meta_path = path / "meta.json" if path.is_dir() else path
    meta = json.loads(meta_path.read_text())
    meta["created_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - days * 86400))
    meta_path.write_text(json.dumps(meta))


def test_versions_restore_and_changes(helper):
    module, home, factory = helper
    ws = factory(tool="write_file")
    run(module, ws, "write_file", path="a.txt", content="v1")
    r2 = run(module, ws, "write_file", path="a.txt", content="v2")
    r3 = run(module, ws, "write_file", path="a.txt", content="v3")
    versions = run(module, ws, "list_versions", path="a.txt")["versions"]
    assert [v["id"] for v in versions] == [r3["backup"], r2["backup"]]
    assert versions[0]["size"] == 2 and versions[0]["tool"] == "write_file" and versions[0]["path"] == "a.txt"
    assert (home / ".pleskmcp" / "versions" / r2["backup"] / "payload").read_text() == "v1"

    restored = run(module, factory(tool="restore_version"), "restore_version", path="a.txt", version_id=r2["backup"])
    assert (home / "httpdocs" / "a.txt").read_text() == "v1" and restored["backup_of_previous"]
    with pytest.raises(module.HelperError, match="belongs to"):
        run(module, ws, "restore_version", path="b.txt", version_id=r2["backup"])
    with pytest.raises(module.HelperError, match="invalid version id"):
        run(module, ws, "restore_version", path="a.txt", version_id="../../etc")

    # a deleted file can be restored from its version
    run(module, factory(tool="delete_file"), "delete_file", path="a.txt")
    assert not (home / "httpdocs" / "a.txt").exists()
    run(module, ws, "restore_version", path="a.txt", version_id=r3["backup"])
    assert (home / "httpdocs" / "a.txt").read_text() == "v2"

    changes = run(module, ws, "list_changes", limit=10)
    kinds = [c["kind"] for c in changes["changes"]]
    assert "file_backup" in kinds and "trash" in kinds and changes["total"] >= 4
    assert changes["changes"] == sorted(changes["changes"], key=lambda c: c["time"], reverse=True)
    since = changes["changes"][0]["time"]
    assert run(module, ws, "list_changes", since=since)["total"] >= 1
    # versions belong to the document root: another domain with its own docroot does not see them
    (home / "other").mkdir()
    other = module.Workspace("second.example", str(home / "other"), None)
    assert run(module, other, "list_versions", path="a.txt")["versions"] == []
    assert run(module, other, "list_changes")["changes"] == []


def test_legacy_backups_are_migrated(helper):
    module, home, factory = helper
    legacy = home / ".pleskmcp" / "backups" / "example.com"
    legacy.mkdir(parents=True, mode=0o700)
    (home / ".pleskmcp").chmod(0o700)
    (legacy / "sub__old.txt.20250101120000").write_text("old content")
    ws = factory()
    versions = run(module, ws, "list_versions", path="sub/old.txt")["versions"]
    assert len(versions) == 1 and versions[0]["migrated"] is True
    assert (home / ".pleskmcp" / "versions" / versions[0]["id"] / "payload").read_text() == "old content"
    assert not (legacy / "sub__old.txt.20250101120000").exists()


def test_retention_rules(helper):
    module, home, factory = helper
    limits = {"backup_retention_days": 30, "trash_retention_days": 10, "backup_min_keep_days": 7, "store_max_bytes": 10 * 1024 * 1024}
    ws = factory(limits)
    run(module, ws, "write_file", path="f.txt", content="1")
    old = run(module, ws, "write_file", path="f.txt", content="2")["backup"]
    newest = run(module, ws, "write_file", path="f.txt", content="3")["backup"]
    (home / "httpdocs" / "g.txt").write_text("g")
    trash_id = run(module, ws, "delete_file", path="g.txt")["trash_id"]
    vdir = home / ".pleskmcp" / "versions"
    age(vdir / old, 40)
    age(vdir / newest, 40)  # newest version of f.txt is older than the limit but is kept BACKUP_MIN_KEEP_DAYS... only if younger than 7 days
    age(home / ".pleskmcp" / "trash" / trash_id, 11)
    summary = ws.run_retention(dry_run=True)
    assert summary["dry_run"] and (vdir / old).exists()
    summary = ws.run_retention()
    assert not (vdir / old).exists() and not (home / ".pleskmcp" / "trash" / trash_id).exists()
    # 40 days old is beyond backup_min_keep_days, so even the newest version goes
    assert not (vdir / newest).exists()
    assert summary["deleted"] == 3

    # the newest version per file survives a short age limit while it is younger than BACKUP_MIN_KEEP_DAYS
    oldest = run(module, ws, "write_file", path="f.txt", content="4")["backup"]
    older = run(module, ws, "write_file", path="f.txt", content="5")["backup"]
    keep = run(module, ws, "write_file", path="f.txt", content="6")["backup"]
    ws.limits["backup_retention_days"] = 2
    age(vdir / oldest, 5)
    age(vdir / older, 4)
    age(vdir / keep, 3)
    ws.run_retention()
    assert (vdir / keep).exists() and not (vdir / older).exists() and not (vdir / oldest).exists()
    ws.limits["backup_retention_days"] = 30

    # size budget: oldest entries go first, the newest per file last
    ws.limits["store_max_bytes"] = 1  # clamped to 1 MiB inside store_limit_bytes
    big = "x" * (600 * 1024)
    run(module, ws, "write_file", path="big.bin", content=big)
    first = run(module, ws, "write_file", path="big.bin", content=big + "1")["backup"]
    second = run(module, ws, "write_file", path="big.bin", content=big + "2")["backup"]
    assert not (vdir / first).exists() and (vdir / second).exists()
    status = run(module, ws, "storage_status")
    assert status["store"]["total"] <= status["store_limit_bytes"] == 1024 * 1024

    # purge_store: preview changes nothing, confirm deletes, scoped by what
    preview = run(module, ws, "purge_store", what="backups")
    assert preview["preview"] and preview["entries"] >= 1 and (vdir / second).exists()
    done = run(module, ws, "purge_store", what="backups", confirm=True)
    assert not done["preview"] and not (vdir / second).exists()
    with pytest.raises(module.HelperError, match="what must be"):
        run(module, ws, "purge_store", what="everything", confirm=True)


def test_quota_is_enforced_despite_plesk_overuse(helper):
    module, home, factory = helper
    quota = 5 * GB
    # 1000 bytes left although Plesk itself would allow the write (overuse)
    ws = factory({"quota_bytes": quota, "used_bytes": quota - 1000})
    with pytest.raises(module.HelperError) as info:
        run(module, ws, "write_file", path="big.txt", content="x" * 5000)
    assert info.value.code == "quota_exceeded"
    assert info.value.details["limit_bytes"] == quota and info.value.details["usage_bytes"] >= quota - 1000
    assert not (home / "httpdocs" / "big.txt").exists()
    # small writes still work and are accounted
    run(module, ws, "write_file", path="small.txt", content="x" * 100)
    assert ws.used_bytes == quota - 900
    # cleaning the store frees room: an old version of 2000 bytes is sacrificed before the verdict
    ws2 = factory({"quota_bytes": quota, "used_bytes": quota - 100, "backup_retention_days": 30})
    run(module, ws2, "write_file", path="small.txt", content="y" * 100)  # 0 net bytes + a 100 byte backup
    assert ws2.used_bytes == quota
    ws3 = factory({"quota_bytes": quota, "used_bytes": quota - 50})
    (home / "httpdocs" / "big.txt").write_text("z" * 3000)
    # replacing a 3000 byte file by a 10 byte file frees space, no quota error even though a backup is written
    run(module, ws3, "replace_in_file", path="big.txt", old_str="z" * 3000, new_str="short")
    assert (home / "httpdocs" / "big.txt").read_text() == "short"
    # unlimited quota: nothing is enforced
    ws4 = factory({"quota_bytes": None, "used_bytes": 10})
    run(module, ws4, "write_file", path="free.txt", content="x" * 5000)


def test_edquot_from_the_filesystem_is_mapped(helper, monkeypatch):
    module, home, factory = helper
    ws = factory({"quota_bytes": 5 * GB, "used_bytes": 0})
    real_rename = module.os.rename
    attempts = []

    def failing_rename(src, dst):
        attempts.append(dst)
        raise OSError(errno.EDQUOT, "Disk quota exceeded")

    monkeypatch.setattr(module.os, "rename", failing_rename)
    with pytest.raises(module.HelperError) as info:
        run(module, ws, "write_file", path="q.txt", content="data")
    assert info.value.code == "quota_exceeded" and len(attempts) == 2  # one cleanup retry
    monkeypatch.setattr(module.os, "rename", real_rename)
    assert not list((home / "httpdocs").glob(".pleskmcp-*"))  # temp files cleaned up


def test_large_files_are_not_backed_up(helper):
    module, home, factory = helper
    ws = factory({"backup_max_file_bytes": 100})
    (home / "httpdocs" / "video.bin").write_text("v" * 500)
    result = run(module, ws, "write_file", path="video.bin", content="w" * 500)
    assert result["backup"] is None and result["backup_skipped"] == "too_large"
    assert run(module, ws, "list_versions", path="video.bin")["versions"] == []


def test_idempotent_replay(helper):
    module, home, factory = helper
    request = {"op": "write_file", "domain": "example.com", "docroot": str(home / "httpdocs"), "request_id": "req-0001-abcdef", "args": {"path": "i.txt", "content": "one"}}
    first = module.handle(request)
    (home / "httpdocs" / "i.txt").write_text("changed meanwhile")
    replay = module.handle(request)
    assert replay == {**first, "replayed": True} and (home / "httpdocs" / "i.txt").read_text() == "changed meanwhile"
    # a different request id runs again
    request["request_id"] = "req-0002-abcdef"
    module.handle(request)
    assert (home / "httpdocs" / "i.txt").read_text() == "one"
    # previews are not recorded
    preview = {"op": "purge_store", "domain": "example.com", "docroot": str(home / "httpdocs"), "request_id": "req-0003-abcdef", "args": {"what": "trash"}}
    assert module.handle(preview)["preview"] is True
    assert not (home / ".pleskmcp" / "idem" / "req-0003-abcdef.json").exists()


def test_time_limit(helper, monkeypatch):
    module, home, factory = helper
    slow = {"op": "list_dir", "domain": "example.com", "docroot": str(home / "httpdocs"), "limits": {"time_limit": 1}, "args": {}}
    original = module.op_list_dir

    def sleepy(ws, args):
        time.sleep(3)
        return original(ws, args)

    monkeypatch.setitem(module.OPS, "list_dir", sleepy)
    with pytest.raises(module.HelperError) as info:
        module.handle(slow)
    assert info.value.code == "timeout"


async def test_quota_and_versions_through_the_tools(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    # example.com: 5 GB quota, 1 GB used -> fine
    structured(await call_tool(env.client, access, "write_file", {"domain": "example.com", "path": "index.php", "content": "<?php // v2\n"}))
    versions = structured(await call_tool(env.client, access, "list_versions", {"domain": "example.com", "path": "index.php"}))["versions"]
    assert len(versions) == 1 and versions[0]["tool"] == "write_file"
    restored = structured(await call_tool(env.client, access, "restore_version", {"domain": "example.com", "path": "index.php", "version_id": versions[0]["id"]}))
    assert restored["restored_version"] == versions[0]["id"]
    assert (env.vhosts / "example.com" / "httpdocs" / "index.php").read_text() == "<?php echo 'hi';\n"
    changes = structured(await call_tool(env.client, access, "list_changes", {"domain": "example.com"}))
    assert changes["total"] >= 2 and changes["changes"][0]["request_id"]

    # Plesk reports the webspace nearly full: the service refuses the write although Plesk would allow overuse
    env.plesk.users["kunde"].domains[0]["used"] = 5 * GB - 10
    await env.services.accounts.invalidate_caches("kunde")
    result = await call_tool(env.client, access, "write_file", {"domain": "example.com", "path": "big.txt", "content": "x" * 50000})
    assert result["isError"] and "quota_exceeded" in tool_text(result) and "Kontingent" in tool_text(result)
    assert not (env.vhosts / "example.com" / "httpdocs" / "big.txt").exists()
    status = structured(await call_tool(env.client, access, "storage_status", {"domain": "example.com"}))
    assert status["remaining_bytes"] == 10

    purge = structured(await call_tool(env.client, access, "purge_store", {"domain": "example.com", "what": "all"}))
    assert purge["preview"] and purge["entries"] >= 1
    audit = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert '"tool": "restore_version"' in audit and '"tool": "purge_store"' not in audit  # preview is not a write
