"""Path safety of the server-side helper: traversal, symlinks, reserved paths, ownership."""

from __future__ import annotations

import json
import os
from collections import namedtuple
from pathlib import Path

import pytest

from conftest import load_helper_module

pytestmark = pytest.mark.skipif(os.getuid() == 0, reason="helper refuses to run as root")


@pytest.fixture
def ws_factory(tmp_path: Path):
    module = load_helper_module()
    vhosts = tmp_path / "vhosts"
    vhosts.mkdir()
    module.VHOSTS_BASE = str(vhosts)
    Passwd = namedtuple("Passwd", "pw_dir")

    def factory(sub: str = "example.com", docroot: str | None = None, home_override: Path | None = None):
        home = vhosts / sub
        (home / "httpdocs").mkdir(parents=True, exist_ok=True)
        module.pwd.getpwuid = lambda uid: Passwd(str(home_override or home))
        return module, module.Workspace("example.com", docroot or str(home / "httpdocs"), None), home

    return factory


def run(module, ws, op, **args):
    return module.OPS[op](ws, args)


def test_traversal_rejected(ws_factory):
    module, ws, home = ws_factory()
    (home / "secret.txt").write_text("outside")
    for bad in ["../secret.txt", "a/../../secret.txt", "/etc/passwd", "..", "assets/../../secret.txt", "x\x00y", "../../other.example/httpdocs"]:
        with pytest.raises(module.HelperError):
            ws.resolve(bad, must_exist=False)


def test_normal_paths(ws_factory):
    module, ws, home = ws_factory()
    (home / "httpdocs" / "a").mkdir()
    (home / "httpdocs" / "a" / "b.txt").write_text("x")
    abs_path, clean, st = ws.resolve("a/./b.txt")
    assert clean == "a/b.txt" and abs_path == str(home / "httpdocs" / "a" / "b.txt")
    assert ws.resolve("", must_exist=True)[1] == ""
    assert ws.resolve(".", must_exist=True)[1] == ""


def test_symlink_escape_rejected(ws_factory):
    module, ws, home = ws_factory()
    (home / "private.txt").write_text("private")
    os.symlink(str(home / "private.txt"), str(home / "httpdocs" / "link.txt"))
    os.symlink("/etc", str(home / "httpdocs" / "etcdir"))
    os.symlink("..", str(home / "httpdocs" / "up"))
    with pytest.raises(module.HelperError, match="symbolic"):
        run(module, ws, "read_file", path="link.txt")
    with pytest.raises(module.HelperError, match="symbolic"):
        run(module, ws, "list_dir", path="etcdir")
    with pytest.raises(module.HelperError, match="symbolic"):
        run(module, ws, "read_file", path="up/private.txt")
    with pytest.raises(module.HelperError, match="symbolic"):
        run(module, ws, "write_file", path="link.txt", content="pwned")
    assert (home / "private.txt").read_text() == "private"
    # a symlink is listed but marked as such
    listing = run(module, ws, "list_dir", path="")
    assert {e["name"]: e["type"] for e in listing["entries"]}["link.txt"] == "symlink"


def test_docroot_must_be_inside_own_home(ws_factory, tmp_path: Path):
    module, ws, home = ws_factory()
    other = home.parent / "other.example"
    (other / "httpdocs").mkdir(parents=True)
    with pytest.raises(module.HelperError, match="outside"):
        module.Workspace("example.com", str(other / "httpdocs"), None)
    with pytest.raises(module.HelperError, match="subscription directory itself"):
        module.Workspace("example.com", str(home), None)
    with pytest.raises(module.HelperError, match="outside"):
        module.Workspace("example.com", "/etc", None)
    with pytest.raises(module.HelperError):
        module.Workspace("example.com", "relative/path", None)


def test_store_dir_is_reserved(ws_factory):
    module, ws, home = ws_factory()
    with pytest.raises(module.HelperError, match="reserved"):
        ws.resolve(".pleskmcp/trash", must_exist=False)


def test_write_backup_and_replace(ws_factory):
    module, ws, home = ws_factory()
    run(module, ws, "write_file", path="new/dir/file.txt", content="hello", create_dirs=True)
    assert (home / "httpdocs" / "new" / "dir" / "file.txt").read_text() == "hello"
    result = run(module, ws, "write_file", path="new/dir/file.txt", content="hello world")
    assert result["backup"]
    versions = run(module, ws, "list_versions", path="new/dir/file.txt")["versions"]
    assert len(versions) == 1 and versions[0]["id"] == result["backup"]
    assert (home / ".pleskmcp" / "versions" / result["backup"] / "payload").read_text() == "hello"
    assert oct((home / ".pleskmcp").stat().st_mode & 0o777) == "0o700"
    with pytest.raises(module.HelperError, match="use create_dirs"):
        run(module, ws, "write_file", path="missing/file.txt", content="x")

    result = run(module, ws, "replace_in_file", path="new/dir/file.txt", old_str="world", new_str="there")
    assert result["replacements"] == 1
    assert (home / "httpdocs" / "new" / "dir" / "file.txt").read_text() == "hello there"
    with pytest.raises(module.HelperError, match="not found"):
        run(module, ws, "replace_in_file", path="new/dir/file.txt", old_str="zzz", new_str="")
    (home / "httpdocs" / "dup.txt").write_text("a a a")
    with pytest.raises(module.HelperError, match="3 times"):
        run(module, ws, "replace_in_file", path="dup.txt", old_str="a", new_str="b")
    assert run(module, ws, "replace_in_file", path="dup.txt", old_str="a", new_str="b", replace_all=True)["replacements"] == 3
    assert (home / "httpdocs" / "dup.txt").read_text() == "b b b"


def test_binary_roundtrip_and_limits(ws_factory):
    import base64

    module, ws, home = ws_factory()
    payload = bytes(range(256)) * 10
    run(module, ws, "write_file", path="bin.dat", content=base64.b64encode(payload).decode(), encoding="base64")
    with pytest.raises(module.HelperError, match="binary"):
        run(module, ws, "read_file", path="bin.dat")
    got = run(module, ws, "read_file", path="bin.dat", encoding="base64")
    assert base64.b64decode(got["content"]) == payload
    ws.limits["read_max_bytes"] = 100
    got = run(module, ws, "read_file", path="bin.dat", encoding="base64")
    assert got["truncated"] and got["returned"] == 100
    got2 = run(module, ws, "read_file", path="bin.dat", encoding="base64", offset=100)
    assert base64.b64decode(got2["content"]) == payload[100:200]
    ws.limits["write_max_bytes"] = 10
    with pytest.raises(module.HelperError, match="exceeds"):
        run(module, ws, "write_file", path="big.txt", content="x" * 11)


def test_trash_and_restore(ws_factory):
    module, ws, home = ws_factory()
    (home / "httpdocs" / "old.txt").write_text("bye")
    (home / "httpdocs" / "folder").mkdir()
    (home / "httpdocs" / "folder" / "f.txt").write_text("in folder")
    with pytest.raises(module.HelperError, match="recursive"):
        run(module, ws, "delete_file", path="folder")
    r1 = run(module, ws, "delete_file", path="old.txt")
    r2 = run(module, ws, "delete_file", path="folder", recursive=True)
    assert not (home / "httpdocs" / "old.txt").exists() and not (home / "httpdocs" / "folder").exists()
    entries = run(module, ws, "restore_file")["entries"]
    assert {e["id"] for e in entries} == {r1["trash_id"], r2["trash_id"]}
    with pytest.raises(module.HelperError, match="document root itself"):
        run(module, ws, "delete_file", path="")
    assert run(module, ws, "restore_file", trash_id=r2["trash_id"])["path"] == "folder"
    assert (home / "httpdocs" / "folder" / "f.txt").read_text() == "in folder"
    (home / "httpdocs" / "old.txt").write_text("new content")
    with pytest.raises(module.HelperError, match="already exists"):
        run(module, ws, "restore_file", trash_id=r1["trash_id"])
    with pytest.raises(module.HelperError, match="invalid trash id"):
        run(module, ws, "restore_file", trash_id="../../etc")
    # trash entries of another domain in the same subscription are invisible
    ws2 = module.Workspace("second.example", str(home / "httpdocs"), None)
    assert run(module, ws2, "restore_file")["entries"] == []


def test_move(ws_factory):
    module, ws, home = ws_factory()
    (home / "httpdocs" / "a.txt").write_text("A")
    (home / "httpdocs" / "b.txt").write_text("B")
    with pytest.raises(module.HelperError, match="destination exists"):
        run(module, ws, "move_file", src="a.txt", dst="b.txt")
    result = run(module, ws, "move_file", src="a.txt", dst="b.txt", overwrite=True)
    assert result["backup"] and (home / "httpdocs" / "b.txt").read_text() == "A"
    with pytest.raises(module.HelperError):
        run(module, ws, "move_file", src="b.txt", dst="../escaped.txt")
    with pytest.raises(module.HelperError, match="use create_dirs"):
        run(module, ws, "move_file", src="b.txt", dst="sub/b.txt")
    run(module, ws, "move_file", src="b.txt", dst="sub/b.txt", create_dirs=True)
    assert (home / "httpdocs" / "sub" / "b.txt").exists()


def test_search_log(ws_factory):
    module, ws, home = ws_factory()
    (home / "logs").mkdir()
    (home / "logs" / "error_log").write_text("ok\nerror: one\nerror: two\n")
    result = run(module, ws, "search_log", log="error_log", pattern="error:", lines=1)
    assert result["lines"] == ["error: two"] and result["scanned"] == 3
    with pytest.raises(module.HelperError, match="unknown log"):
        run(module, ws, "search_log", log="../httpdocs/index.php")
    with pytest.raises(module.HelperError, match="unknown log"):
        run(module, ws, "search_log", log="access_log; touch /tmp/x")


def test_main_roundtrip(ws_factory, capsys, monkeypatch):
    import io

    module, ws, home = ws_factory()
    (home / "httpdocs" / "x.txt").write_text("content")
    request = {"op": "read_file", "domain": "example.com", "docroot": str(home / "httpdocs"), "args": {"path": "x.txt"}}
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(json.dumps(request).encode())))
    assert module.main() == 0
    out = json.loads(capsys.readouterr().out)
    assert out["ok"] and out["result"]["content"] == "content"
