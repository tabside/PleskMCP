"""Database tools against the SQLite-backed stand-in for the mysql CLI and the fake Plesk XML API.

Covers: credential sources, redaction, read-only enforcement (nested and
commented writes), previews that change nothing, dumps and restore,
schema changes, db_create (credentials outside the docroot, never returned)
and db_drop refusing foreign databases.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from conftest import Env, OAuthFlow, call_tool, load_helper_module, structured, tool_text

pytestmark = pytest.mark.anyio


def test_sql_validators():
    module = load_helper_module()
    ok = ["SELECT * FROM users", "select id from users where id = 1;", "SHOW TABLES", "DESCRIBE users", "EXPLAIN SELECT 1", "SELECT 'a;b' AS x", "WITH t AS (SELECT 1) SELECT * FROM t"]
    for sql in ok:
        module.validate_read_sql(sql)
    bad = [
        "DELETE FROM users",
        "SELECT 1; DELETE FROM users",
        "SELECT 1 /* ; */ ; DROP TABLE users",
        "SELECT * FROM users -- harmless\n; UPDATE users SET a=1",
        "SELECT * FROM users WHERE id IN (SELECT id FROM users); UPDATE users SET a=1",
        "SELECT * INTO OUTFILE '/tmp/x' FROM users",
        "SELECT LOAD_FILE('/etc/passwd')",
        "SELECT SLEEP(10)",
        "SELECT BENCHMARK(1000000, MD5('x'))",
        "SET @a := 1",
        "SELECT @a := 1",
        "SELECT * FROM users FOR UPDATE",
        "SELECT * FROM users LOCK IN SHARE MODE",
        "INSERT INTO users VALUES (1)",
        "SELECT /*! DELETE */ 1 FROM users",
        "SELECT 1 UNION SELECT 1; CREATE TABLE x (a int)",
    ]
    for sql in bad:
        with pytest.raises(module.HelperError):
            module.validate_read_sql(sql)
    assert module.validate_write_sql("UPDATE users SET email='x' WHERE id=1")[1] == ["users"]
    assert module.validate_write_sql("DELETE FROM `posts` WHERE id=2")[1] == ["posts"]
    assert module.validate_write_sql("INSERT INTO posts (id, title) VALUES (3, 'x')")[1] == ["posts"]
    for sql in ["DROP TABLE users", "UPDATE users SET a=1; DROP TABLE users", "GRANT ALL ON *.* TO x", "CREATE TABLE t (a int)", "REPLACE INTO users VALUES (1)", "TRUNCATE users", "SELECT 1", "UPDATE users SET a=(SELECT 1 INTO OUTFILE '/x')"]:
        with pytest.raises(module.HelperError):
            module.validate_write_sql(sql)
    assert module.validate_ddl_sql("CREATE TABLE notes (id INT PRIMARY KEY, body TEXT)")[1] == ["notes"]
    assert module.validate_ddl_sql("ALTER TABLE users ADD COLUMN nick VARCHAR(50)")[1] == ["users"]
    assert module.validate_ddl_sql("CREATE INDEX idx_email ON users (email)")[1] == ["users"]
    for sql in ["DROP TABLE users", "DROP DATABASE app_db", "CREATE DATABASE x", "CREATE USER 'x'@'%'", "GRANT SELECT ON app_db.* TO x", "ALTER TABLE users ADD COLUMN a INT; DROP TABLE users", "TRUNCATE TABLE users", "CREATE TABLE other.t (a int)", "CREATE TRIGGER t BEFORE INSERT ON users FOR EACH ROW SET NEW.a=1"]:
        with pytest.raises(module.HelperError):
            module.validate_ddl_sql(sql)


async def login(flow: OAuthFlow) -> str:
    return (await flow.full_login())["access_token"]


async def test_db_list_sources_and_sizes(env: Env, flow: OAuthFlow):
    access = await login(flow)
    result = structured(await call_tool(env.client, access, "db_list", {"domain": "data.example"}))
    by_name = {d["database"]: d for d in result["databases"]}
    assert by_name["app_db"]["credentials"] == "config" and by_name["app_db"]["config_file"] == ".env"
    assert by_name["app_db"]["size_bytes"] > 0
    assert by_name["legacy_db"]["credentials"] == "missing" and by_name["legacy_db"]["size_bytes"] is None
    assert result["account_page"].endswith("/account") and result["management_enabled"] is True
    text = json.dumps(result)
    assert "app-secret-pw" not in text and "legacy-pw" not in text
    # the plan of example.com has no db scope at all
    result = await call_tool(env.client, access, "db_list", {"domain": "example.com"})
    assert result["isError"] and "erlaubt db:read nicht" in tool_text(result)


async def test_query_schema_redaction_and_readonly(env: Env, flow: OAuthFlow):
    access = await login(flow)
    schema = structured(await call_tool(env.client, access, "db_schema", {"domain": "data.example", "database": "app_db"}))
    assert {t["name"] for t in schema["tables"]} == {"users", "posts"}
    cols = structured(await call_tool(env.client, access, "db_schema", {"domain": "data.example", "database": "app_db", "table": "users"}))
    assert [c["Field"] for c in cols["columns"]] == ["id", "email", "password", "api_token"]

    rows = structured(await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "app_db", "sql": "SELECT * FROM users ORDER BY id"}))
    assert rows["columns"] == ["id", "email", "password", "api_token"] and rows["returned"] == 3
    assert rows["rows"][0] == ["1", "a@example.com", "***", "***"] and rows["rows"][2][3] == "NULL"
    assert set(rows["redacted_columns"]) == {"password", "api_token"}
    assert "hash-a" not in json.dumps(rows) and "tok-a" not in json.dumps(rows)

    for sql in ["DELETE FROM users", "SELECT 1; DELETE FROM users", "SELECT * FROM users /* x */; UPDATE users SET email='x'", "SELECT * INTO OUTFILE '/tmp/x' FROM users"]:
        result = await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "app_db", "sql": sql})
        assert result["isError"], sql
    conn = sqlite3.connect(str(env.mysql.path("app_db")))
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 3
    conn.close()

    # unknown credentials -> clear hint to the account page
    result = await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "legacy_db", "sql": "SELECT 1"})
    assert result["isError"] and "db_no_credentials" in tool_text(result)
    # a database of another subscription of the same customer is refused by the service before any job runs
    result = await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "wp_db", "sql": "SELECT 1"})
    assert result["isError"] and "gehört nicht zum Abo data.example" in tool_text(result)
    many = structured(await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "app_db", "sql": "SELECT id FROM users"}))
    assert many["truncated"] is False


async def test_foreign_database_refused_server_side(env: Env, flow: OAuthFlow):
    """The database -> subscription check does not rely on MySQL grants or on the account page.

    Even with stored credentials for a database of another customer (the UI
    check bypassed) every database tool refuses it; own databases work, a
    database created in the panel a moment ago is picked up despite the cache.
    """
    access = await login(flow)
    env.plesk.add_database(env.plesk.webspace_id("other.example"), "other_db")
    env.mysql.add("other_db", "other_user", "other-pw")
    conn = env.mysql.connect("other_db")
    conn.executescript("CREATE TABLE secrets (id INTEGER PRIMARY KEY, v TEXT); INSERT INTO secrets VALUES (1, 'other customer data');")
    conn.close()
    await env.services.store.save_db_credential("kunde", "other_db", "other_user", env.services.accounts.encrypt("other-pw"), source="stored")
    jobs_before = len(env.pool.calls)
    for tool, extra in [
        ("db_schema", {}),
        ("db_query", {"sql": "SELECT * FROM secrets"}),
        ("db_execute", {"sql": "DELETE FROM secrets WHERE id=1", "confirm": True}),
        ("db_apply_schema", {"sql": "ALTER TABLE secrets ADD COLUMN x INT", "confirm": True}),
        ("db_restore", {}),
    ]:
        result = await call_tool(env.client, access, tool, {"domain": "data.example", "database": "other_db", **extra})
        text = tool_text(result)
        assert result["isError"] and "gehört nicht zum Abo data.example" in text, tool
        assert "other customer data" not in text
    assert len(env.pool.calls) == jobs_before  # nothing reached the helper
    conn = env.mysql.connect("other_db")
    assert conn.execute("SELECT COUNT(*) FROM secrets").fetchone()[0] == 1
    conn.close()
    audit = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert '"event": "db_foreign_refused"' in audit and '"database": "other_db"' in audit
    # own databases of the subscription keep working
    rows = structured(await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "app_db", "sql": "SELECT COUNT(*) AS n FROM posts"}))
    assert rows["rows"][0] == ["2"]
    # a database added in the panel after the list was cached is accepted (cache is re-read once before refusing)
    env.plesk.add_database(env.plesk.webspace_id("data.example"), "fresh_db")
    env.mysql.add("fresh_db", "fresh_user", "fresh-pw")
    await env.services.store.save_db_credential("kunde", "fresh_db", "fresh_user", env.services.accounts.encrypt("fresh-pw"), source="stored")
    schema = structured(await call_tool(env.client, access, "db_schema", {"domain": "data.example", "database": "fresh_db"}))
    assert schema["tables"] == []
    # a name Plesk does not know at all
    result = await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "nothere", "sql": "SELECT 1"})
    assert result["isError"] and "gehört nicht zum Abo" in tool_text(result)


async def test_db_tools_unavailable_in_login_only_mode(env: Env, flow: OAuthFlow):
    """Without Plesk API access the ownership check cannot run: the database tools are off, not open."""
    access = await login(flow)
    # give the plan itself (not only the add-on, which login_only cannot see) the db scopes, so the profile check passes
    profiles = {**env.settings.profiles, "guid-plan-standard": env.settings.profiles["ki-zugang"]}
    settings = env.settings.__class__(**{**env.settings.__dict__, "account_check_mode": "login_only", "profiles": profiles})
    env.services.accounts._settings = settings
    env.services.runner._settings = settings
    await env.services.accounts.invalidate_caches("kunde")
    result = await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "app_db", "sql": "SELECT 1"})
    assert result["isError"] and "login_only" in tool_text(result)


async def test_db_tools_fail_closed_when_plesk_listing_fails(env: Env, flow: OAuthFlow, monkeypatch):
    from pleskmcp.plesk_api import PleskError

    access = await login(flow)
    await env.services.accounts.forget_databases("kunde", "data.example")

    async def broken(auth, webspace_name):
        raise PleskError("agent.php unreachable")

    monkeypatch.setattr(env.services.plesk, "get_databases", broken)
    result = await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "app_db", "sql": "SELECT 1"})
    assert result["isError"] and "nicht abgefragt" in tool_text(result)
    # the failure is not cached: once Plesk answers again, the query runs
    monkeypatch.undo()
    rows = structured(await call_tool(env.client, access, "db_query", {"domain": "data.example", "database": "app_db", "sql": "SELECT COUNT(*) AS n FROM posts"}))
    assert rows["rows"][0] == ["2"]


async def test_execute_preview_confirm_and_restore(env: Env, flow: OAuthFlow):
    access = await login(flow)
    args = {"domain": "data.example", "database": "app_db", "sql": "UPDATE users SET email = 'changed@example.com' WHERE id <= 2"}
    preview = structured(await call_tool(env.client, access, "db_execute", args))
    assert preview["preview"] is True and preview["affected_rows"] == 2 and preview["tables"] == ["users"]
    conn = sqlite3.connect(str(env.mysql.path("app_db")))
    assert conn.execute("SELECT COUNT(*) FROM users WHERE email='changed@example.com'").fetchone()[0] == 0

    done = structured(await call_tool(env.client, access, "db_execute", {**args, "confirm": True}))
    assert done["preview"] is False and done["affected_rows"] == 2 and done["dump_id"]
    assert conn.execute("SELECT COUNT(*) FROM users WHERE email='changed@example.com'").fetchone()[0] == 2
    dump_file = env.vhosts / "data.example" / ".pleskmcp" / "db" / "app_db" / (done["dump_id"] + ".sql.gz")
    assert dump_file.exists() and oct(dump_file.stat().st_mode & 0o777) == "0o600"

    dumps = structured(await call_tool(env.client, access, "db_restore", {"domain": "data.example", "database": "app_db"}))
    assert [d["id"] for d in dumps["dumps"]] == [done["dump_id"]] and dumps["dumps"][0]["tables"] == ["users"]
    preview = structured(await call_tool(env.client, access, "db_restore", {"domain": "data.example", "database": "app_db", "dump_id": done["dump_id"]}))
    assert preview["preview"] is True
    assert conn.execute("SELECT COUNT(*) FROM users WHERE email='changed@example.com'").fetchone()[0] == 2
    restored = structured(await call_tool(env.client, access, "db_restore", {"domain": "data.example", "database": "app_db", "dump_id": done["dump_id"], "confirm": True}))
    assert restored["restored_dump"] == done["dump_id"] and restored["backup_of_previous"]
    assert conn.execute("SELECT email FROM users ORDER BY id").fetchall() == [("a@example.com",), ("b@example.com",), ("c@example.com",)]
    conn.close()

    result = await call_tool(env.client, access, "db_execute", {"domain": "data.example", "database": "app_db", "sql": "DELETE FROM users"})
    assert structured(result)["affected_rows"] == 3
    result = await call_tool(env.client, access, "db_execute", {"domain": "data.example", "database": "app_db", "sql": "DELETE FROM nothere", "confirm": True})
    assert result["isError"] and "does not exist" in tool_text(result)

    audit = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert "changed@example.com" not in audit and '"tool": "db_execute"' in audit
    changes = structured(await call_tool(env.client, access, "list_changes", {"domain": "data.example"}))
    assert any(c["kind"] == "db_dump" for c in changes["changes"])


async def test_apply_schema(env: Env, flow: OAuthFlow):
    access = await login(flow)
    args = {"domain": "data.example", "database": "app_db", "sql": "ALTER TABLE users ADD COLUMN nick VARCHAR(50)"}
    preview = structured(await call_tool(env.client, access, "db_apply_schema", args))
    assert preview["preview"] and preview["columns_before"]["users"] == ["id", "email", "password", "api_token"]
    conn = sqlite3.connect(str(env.mysql.path("app_db")))
    assert [r[1] for r in conn.execute("PRAGMA table_info(users)")] == ["id", "email", "password", "api_token"]
    done = structured(await call_tool(env.client, access, "db_apply_schema", {**args, "confirm": True}))
    assert done["full_dump"] and done["dump_id"] and done["columns_after"]["users"][-1] == "nick"
    assert [r[1] for r in conn.execute("PRAGMA table_info(users)")][-1] == "nick"
    conn.close()
    for sql in ["DROP TABLE users", "CREATE DATABASE x", "GRANT ALL ON *.* TO 'x'"]:
        result = await call_tool(env.client, access, "db_apply_schema", {"domain": "data.example", "database": "app_db", "sql": sql, "confirm": True})
        assert result["isError"]
    # full dumps need db:admin to restore; a token without it is refused
    narrow = (await flow.full_login(scope="files:read db:read db:write"))["access_token"]
    result = await call_tool(env.client, narrow, "db_restore", {"domain": "data.example", "database": "app_db", "dump_id": done["dump_id"], "confirm": True})
    assert result["isError"] and "db:admin" in tool_text(result)
    result = await call_tool(env.client, narrow, "db_apply_schema", {**args, "confirm": True})
    assert result["isError"] and "db:admin" in tool_text(result)


async def test_create_and_drop(env: Env, flow: OAuthFlow):
    access = await login(flow)
    preview = structured(await call_tool(env.client, access, "db_create", {"domain": "data.example", "name_suffix": "Shop-Data"}))
    assert preview["preview"] and preview["database"] == "data_shop_data" and preview["max_databases_created"] == 2
    assert not any(db["name"] == "data_shop_data" for db in env.plesk.databases.values())

    created = structured(await call_tool(env.client, access, "db_create", {"domain": "data.example", "name_suffix": "shop_data", "confirm": True, "write_config_path": "config/db.env"}))
    assert created["database"] == "data_shop_data" and created["credentials_file"] == "private/pleskmcp-db/data_shop_data.env"
    assert created["config_written"] == "config/db.env"
    text = json.dumps(created)
    assert "DB_PASSWORD" not in text and "_u" not in text.replace("data_shop_data", "")
    # Plesk has the database and a dedicated user with a long random password
    plesk_db = next(db for db in env.plesk.databases.values() if db["name"] == "data_shop_data")
    user = next(u for u in env.plesk.db_users.values() if u["db_id"] == next(i for i, d in env.plesk.databases.items() if d is plesk_db))
    assert len(user["password"]) >= 32 and user["login"].startswith("data_shop_data_u")
    # credentials file outside every docroot, 0600 in a 0700 directory
    home = env.vhosts / "data.example"
    creds_file = home / "private" / "pleskmcp-db" / "data_shop_data.env"
    assert creds_file.exists() and oct(creds_file.stat().st_mode & 0o777) == "0o600"
    assert oct((home / "private" / "pleskmcp-db").stat().st_mode & 0o777) == "0o700"
    assert f"DB_PASSWORD={user['password']}" in creds_file.read_text()
    assert not list((home / "httpdocs").rglob("*.env.*")) and not (home / "httpdocs" / "private").exists()
    # the optional config file in the docroot carries the values and is protected from now on
    cfg = home / "httpdocs" / "config" / "db.env"
    assert user["password"] in cfg.read_text()
    # stored encrypted, decryptable by the service only
    row = await env.services.store.get_db_credential_row("kunde", "data_shop_data")
    assert row["source"] == "service" and row["webspace"] == "data.example" and user["password"] not in row["password_enc"]
    assert env.services.accounts.decrypt(row["password_enc"]) == user["password"]
    # audit log never carries the password
    audit = open(env.settings.audit_log_file, encoding="utf-8").read()
    assert user["password"] not in audit and '"event": "db_create"' in audit

    listed = structured(await call_tool(env.client, access, "db_list", {"domain": "data.example"}))
    assert {d["database"]: d["credentials"] for d in listed["databases"]}["data_shop_data"] == "service"

    # second database allowed, third exceeds the profile limit
    structured(await call_tool(env.client, access, "db_create", {"domain": "data.example", "name_suffix": "two", "confirm": True}))
    result = await call_tool(env.client, access, "db_create", {"domain": "data.example", "name_suffix": "three", "confirm": True})
    assert result["isError"] and "Limit 2" in tool_text(result)
    result = await call_tool(env.client, access, "db_create", {"domain": "data.example", "name_suffix": "!!!", "confirm": True})
    assert result["isError"] and "Bereinigung" in tool_text(result)
    # a plan without db:admin cannot create
    result = await call_tool(env.client, access, "db_create", {"domain": "example.com", "name_suffix": "x", "confirm": True})
    assert result["isError"] and "db:admin" in tool_text(result)

    # db_drop: foreign database refused, own one dumped and removed
    env.mysql.add("data_shop_data", user["login"], user["password"])
    conn = env.mysql.connect("data_shop_data")
    conn.execute("CREATE TABLE t (a INT)")
    conn.execute("INSERT INTO t VALUES (1)")
    conn.commit()
    conn.close()
    result = await call_tool(env.client, access, "db_drop", {"domain": "data.example", "database": "legacy_db", "confirm": True})
    assert result["isError"] and "nicht vom Dienst" in tool_text(result)
    assert any(db["name"] == "legacy_db" for db in env.plesk.databases.values())
    preview = structured(await call_tool(env.client, access, "db_drop", {"domain": "data.example", "database": "data_shop_data"}))
    assert preview["preview"] and any(db["name"] == "data_shop_data" for db in env.plesk.databases.values())
    dropped = structured(await call_tool(env.client, access, "db_drop", {"domain": "data.example", "database": "data_shop_data", "confirm": True}))
    assert dropped["dropped"] and dropped["dump_id"]
    assert not any(db["name"] == "data_shop_data" for db in env.plesk.databases.values())
    assert not any(u["login"] == user["login"] for u in env.plesk.db_users.values())
    assert await env.services.store.get_db_credential_row("kunde", "data_shop_data") is None
    assert not creds_file.exists()
    assert (home / ".pleskmcp" / "db" / "data_shop_data" / (dropped["dump_id"] + ".sql.gz")).exists()


async def test_create_refused_when_plesk_denies(env: Env, flow: OAuthFlow):
    access = await login(flow)
    env.plesk.users["kunde"].can_manage_db = False
    result = await call_tool(env.client, access, "db_create", {"domain": "data.example", "name_suffix": "x", "confirm": True})
    assert result["isError"] and "1006" in tool_text(result)
    assert not env.plesk.db_users
    env.plesk.users["kunde"].can_manage_db = True
    env.plesk.users["kunde"].domains[2]["max_db"] = 2  # app_db and legacy_db already exist
    result = await call_tool(env.client, access, "db_create", {"domain": "data.example", "name_suffix": "x", "confirm": True})
    assert result["isError"] and "Limit" in tool_text(result)


async def test_management_switch(env: Env, flow: OAuthFlow, monkeypatch):
    access = await login(flow)
    env.services.runner._settings = env.settings.__class__(**{**env.settings.__dict__, "db_management_enabled": False})
    result = await call_tool(env.client, access, "db_create", {"domain": "data.example", "name_suffix": "x", "confirm": True})
    assert result["isError"] and "DB_MANAGEMENT_ENABLED" in tool_text(result)
    listed = structured(await call_tool(env.client, access, "db_list", {"domain": "data.example"}))
    assert listed["management_enabled"] is False
