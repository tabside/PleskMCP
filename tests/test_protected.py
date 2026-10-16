"""Protected files: redaction on read, no "***" written back, log redaction, key files refused, ownership hints.

Also covers nested document roots (httpdocs/public, a docroot that is a
subfolder of the subscription, an addon domain with its own path) and a
WordPress layout.
"""

from __future__ import annotations

import errno
import os
from collections import namedtuple
from pathlib import Path

import pytest

from conftest import Env, OAuthFlow, call_tool, load_helper_module, structured, tool_text

pytestmark = pytest.mark.anyio

WP_CONFIG = """<?php
define( 'DB_NAME', 'wp_db' );
define( 'DB_USER', 'wp_user' );
define( 'DB_PASSWORD', 'wp-secret-pw' );
define( 'DB_HOST', 'localhost' );
define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_SALT', 'another unique phrase' );
$table_prefix = 'wp_';
define( 'WP_DEBUG', false );
"""

DOTENV = """APP_NAME=Demo
APP_KEY=base64:verysecretkey==
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PASSWORD=app-secret-pw
MAIL_PASSWORD="quoted secret"
DATABASE_URL=mysql://user:pw123@localhost/app
REDIS_HOST=127.0.0.1
"""


@pytest.fixture
def helper(tmp_path: Path):
    if os.getuid() == 0:
        pytest.skip("helper refuses to run as root")
    module = load_helper_module()
    vhosts = tmp_path / "vhosts"
    vhosts.mkdir()
    module.VHOSTS_BASE = str(vhosts)
    Passwd = namedtuple("Passwd", "pw_dir pw_name")

    def factory(sub: str, docroot: str, domain: str = "example.com", limits=None):
        home = vhosts / sub
        Path(docroot).mkdir(parents=True, exist_ok=True)
        module.pwd.getpwuid = lambda uid: Passwd(str(home), "sysuser%d" % uid)
        return module.Workspace(domain, docroot, limits)

    return module, vhosts, factory


def run(module, ws, op, **args):
    return module.OPS[op](ws, args)


def test_redaction_regexes():
    module = load_helper_module()
    text, n = module.redact_config(WP_CONFIG, "wp-config.php")
    assert "wp-secret-pw" not in text and "put your unique phrase" not in text and "another unique phrase" not in text
    assert "define( 'DB_NAME', 'wp_db' )" in text and "define( 'DB_USER', 'wp_user' )" in text
    assert "define( 'DB_PASSWORD', '***' )" in text and n == 3
    text, n = module.redact_config(DOTENV, ".env")
    assert "verysecretkey" not in text and "app-secret-pw" not in text and "quoted secret" not in text and "pw123" not in text
    assert "APP_NAME=Demo" in text and "DB_HOST=127.0.0.1" in text and "APP_KEY=***" in text and "mysql://user:***@localhost/app" in text
    # write-back detection: a redacted secret position holding *** is refused, a literal *** elsewhere is fine
    assert module.contains_redacted_secret("define('DB_PASSWORD', '***');", "wp-config.php")
    assert module.contains_redacted_secret("DB_PASSWORD=***\n", ".env")
    assert not module.contains_redacted_secret("# *** header ***\nDB_HOST=localhost\n", ".env")
    assert not module.contains_redacted_secret("echo '***';", "index.php")
    assert module.redact_log_line("GET /login?password=hunter2&user=a") == "GET /login?password=***&user=a"
    assert module.redact_log_line("Authorization: Bearer abc.def") == "Authorization: ***"
    assert module.redact_log_line("plain line") == "plain line"


def test_protected_read_write_in_helper(helper):
    module, vhosts, factory = helper
    docroot = vhosts / "example.com" / "httpdocs"
    ws = factory("example.com", str(docroot))
    (docroot / "wp-config.php").write_text(WP_CONFIG)
    (docroot / ".env").write_text(DOTENV)
    (docroot / "config").mkdir()
    (docroot / "config" / "database.php").write_text("<?php return ['password' => 'dbpw', 'host' => 'localhost'];")
    (docroot / "server.key").write_text("-----BEGIN PRIVATE KEY-----\nabc\n")
    (docroot / ".git").mkdir()
    (docroot / ".git" / "config").write_text("[remote \"origin\"]\n\turl = https://user:tok@git.example/repo.git\n")

    got = run(module, ws, "read_file", path="wp-config.php")
    assert got["protected"] and got["redacted"] == 3 and "wp-secret-pw" not in got["content"]
    got = run(module, ws, "read_file", path=".env")
    assert got["protected"] and "app-secret-pw" not in got["content"] and "APP_NAME=Demo" in got["content"]
    got = run(module, ws, "read_file", path="config/database.php")
    assert "dbpw" not in got["content"] and "'host' => 'localhost'" in got["content"]
    got = run(module, ws, "read_file", path=".git/config")
    assert "tok@" not in got["content"]
    with pytest.raises(module.HelperError, match="key material"):
        run(module, ws, "read_file", path="server.key")
    with pytest.raises(module.HelperError, match="whole text"):
        run(module, ws, "read_file", path="wp-config.php", encoding="base64")

    listing = run(module, ws, "list_dir", path="")
    flags = {e["name"]: e.get("protected") for e in listing["entries"]}
    assert flags["wp-config.php"] is True and flags[".env"] is True and flags.get("server.key") is True

    # writing the redacted text back is refused and changes nothing
    redacted = got_wp = run(module, ws, "read_file", path="wp-config.php")["content"]
    with pytest.raises(module.HelperError, match="redacted"):
        run(module, ws, "write_file", path="wp-config.php", content=redacted)
    assert (docroot / "wp-config.php").read_text() == WP_CONFIG
    with pytest.raises(module.HelperError, match="redacted"):
        run(module, ws, "replace_in_file", path="wp-config.php", old_str="define( 'DB_PASSWORD', 'wp-secret-pw' )", new_str="define( 'DB_PASSWORD', '***' )")
    with pytest.raises(module.HelperError, match="redacted"):
        run(module, ws, "write_file", path=".env", content="DB_PASSWORD=***\n")
    # a change elsewhere in the protected file is allowed, the secret stays
    result = run(module, ws, "replace_in_file", path="wp-config.php", old_str="define( 'WP_DEBUG', false );", new_str="define( 'WP_DEBUG', true );")
    assert result["backup"]
    text = (docroot / "wp-config.php").read_text()
    assert "define( 'WP_DEBUG', true );" in text and "wp-secret-pw" in text
    del got_wp

    # search_log redacts credential patterns
    logs = vhosts / "example.com" / "logs"
    logs.mkdir()
    (logs / "error_log").write_text("ok\nPOST /wp-login.php pwd=abc&log=admin\nAuthorization: Basic xyz\ntoken=secret123 ok\n")
    result = run(module, ws, "search_log", log="error_log", pattern=".", lines=10)
    joined = "\n".join(result["lines"])
    assert "abc" not in joined and "xyz" not in joined and "secret123" not in joined and "ok" in joined


async def test_protected_files_via_tools(env: Env, flow: OAuthFlow):
    tokens = await flow.full_login()
    access = tokens["access_token"]
    read = structured(await call_tool(env.client, access, "read_file", {"domain": "example.com", "path": "wp-config.php"}))
    assert read["protected"] and "wp-secret-pw" not in read["content"] and "long-random-key" not in read["content"]
    assert "define('DB_NAME', 'wp_db')" in read["content"]
    result = await call_tool(env.client, access, "write_file", {"domain": "example.com", "path": "wp-config.php", "content": read["content"]})
    assert result["isError"] and "redacted" in tool_text(result)
    assert "wp-secret-pw" in (env.vhosts / "example.com" / "httpdocs" / "wp-config.php").read_text()
    read = structured(await call_tool(env.client, access, "read_file", {"domain": "data.example", "path": ".env"}))
    assert "app-secret-pw" not in read["content"] and "APP_NAME=Demo" in read["content"]
    log = structured(await call_tool(env.client, access, "search_log", {"domain": "example.com", "log": "error_log", "pattern": "password"}))
    assert log["lines"] == ["login password=*** failed"]
    audit = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert "wp-secret-pw" not in audit and "app-secret-pw" not in audit


def test_not_owner_hint(helper, monkeypatch):
    module, vhosts, factory = helper
    docroot = vhosts / "example.com" / "httpdocs"
    ws = factory("example.com", str(docroot))
    (docroot / "foreign").mkdir()
    (docroot / "foreign" / "file.txt").write_text("x")
    real_lstat = os.lstat
    Stat = namedtuple("Stat", "st_mode st_uid st_gid st_size st_mtime st_ino st_dev st_nlink st_atime st_ctime")

    def fake_lstat(path, *a, **kw):
        st = real_lstat(path, *a, **kw)
        if str(path).endswith("/foreign") or str(path).endswith("/foreign/file.txt"):
            return Stat(st.st_mode, st.st_uid + 1, st.st_gid, st.st_size, st.st_mtime, st.st_ino, st.st_dev, st.st_nlink, st.st_atime, st.st_ctime)
        return st

    monkeypatch.setattr(module.os, "lstat", fake_lstat)

    def denied():
        raise OSError(errno.EACCES, "Permission denied")

    with pytest.raises(module.HelperError) as info:
        module._call_write(denied, "foreign/file.txt", ws)
    assert info.value.code == "not_owner" and info.value.details["path"] == "foreign/file.txt"
    assert "report-ownership" in info.value.message
    # listing flags the entry, the read-only report finds it
    listing = run(module, ws, "list_dir", path="")
    assert any(e["name"] == "foreign" and e.get("owner_ok") is False for e in listing["entries"])
    report = run(module, ws, "report_ownership")
    assert any(f["path"].startswith("foreign") for f in report["foreign"])
    assert report["scanned"] >= 2


def test_nested_docroots_and_wordpress_layout(helper):
    module, vhosts, factory = helper
    home = vhosts / "shop.example"
    # docroot two levels below the subscription (Laravel style httpdocs/public)
    public = home / "httpdocs" / "public"
    ws = factory("shop.example", str(public), domain="shop.example")
    (home / "httpdocs" / ".env").write_text("APP_KEY=topsecret\n")
    (public / "index.php").write_text("<?php\n")
    with pytest.raises(module.HelperError):
        run(module, ws, "read_file", path="../.env")
    with pytest.raises(module.HelperError):
        run(module, ws, "read_file", path="../../.env")
    assert run(module, ws, "read_file", path="index.php")["content"] == "<?php\n"
    # the store lives in the subscription root, outside every docroot
    run(module, ws, "write_file", path="index.php", content="<?php // v2\n")
    assert (home / ".pleskmcp" / "versions").is_dir() and not (public / ".pleskmcp").exists()
    with pytest.raises(module.HelperError, match="reserved|store"):
        ws.resolve(".pleskmcp/x", must_exist=False)

    # addon domain with its own directory next to httpdocs
    addon = factory("shop.example", str(home / "addon.example"), domain="addon.example")
    (home / "addon.example" / "wp-config.php").write_text(WP_CONFIG)
    (home / "addon.example" / "wp-content" / "uploads").mkdir(parents=True)
    (home / "addon.example" / "wp-content" / "uploads" / "a.jpg").write_bytes(b"\xff\xd8\xff")
    got = run(module, addon, "read_file", path="wp-config.php")
    assert got["protected"] and "wp-secret-pw" not in got["content"]
    with pytest.raises(module.HelperError, match="binary|UTF-8"):
        run(module, addon, "read_file", path="wp-content/uploads/a.jpg")
    assert run(module, addon, "read_file", path="wp-content/uploads/a.jpg", encoding="base64")["encoding"] == "base64"
    # versions of the two docroots are kept apart
    run(module, addon, "write_file", path="wp-content/x.txt", content="1")
    run(module, addon, "write_file", path="wp-content/x.txt", content="2")
    assert len(run(module, addon, "list_versions", path="wp-content/x.txt")["versions"]) == 1
    assert run(module, ws, "list_versions", path="wp-content/x.txt")["versions"] == []
    changes = run(module, addon, "list_changes")["changes"]
    assert changes and changes[0]["kind"] == "file_backup" and changes[0]["path"] == "wp-content/x.txt"

    # the docroot must not be the subscription root and must stay inside it
    with pytest.raises(module.HelperError, match="itself"):
        factory("shop.example", str(home), domain="shop.example")
    with pytest.raises(module.HelperError, match="outside"):
        factory("shop.example", str(vhosts / "other.example" / "httpdocs"), domain="shop.example")
