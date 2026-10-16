"""initial schema

Revision ID: 0001_initial
Revises:
Create Date: 2026-10-16
"""
from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("client_id", sa.String(512), primary_key=True),
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("info_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("fetched_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "auth_requests",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("client_id", sa.String(512), nullable=False),
        sa.Column("params_json", sa.Text(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "auth_codes",
        sa.Column("code_hash", sa.String(64), primary_key=True),
        sa.Column("client_id", sa.String(512), nullable=False),
        sa.Column("plesk_login", sa.String(255), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False),
        sa.Column("code_challenge", sa.String(255), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("redirect_uri_explicit", sa.Boolean(), nullable=False),
        sa.Column("resource", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("revoke_others", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.create_table(
        "tokens",
        sa.Column("token_hash", sa.String(64), primary_key=True),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("client_id", sa.String(512), nullable=False),
        sa.Column("plesk_login", sa.String(255), nullable=False),
        sa.Column("scopes", sa.Text(), nullable=False),
        sa.Column("resource", sa.Text(), nullable=True),
        sa.Column("family_id", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("rotated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_used_at", sa.Integer(), nullable=True),
    )
    op.create_index("tokens_login", "tokens", ["plesk_login"])
    op.create_index("tokens_family", "tokens", ["family_id"])
    op.create_table(
        "accounts",
        sa.Column("plesk_login", sa.String(255), primary_key=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("secret_key_enc", sa.Text(), nullable=True),
        sa.Column("domains_json", sa.Text(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("checked_at", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "login_attempts",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ts", sa.Integer(), nullable=False),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("login", sa.String(255), nullable=False),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("plesk_checked", sa.Boolean(), nullable=False),
    )
    op.create_index("login_attempts_ts", "login_attempts", ["ts"])
    op.create_table(
        "db_credentials",
        sa.Column("plesk_login", sa.String(255), primary_key=True),
        sa.Column("database", sa.String(255), primary_key=True),
        sa.Column("db_user", sa.String(255), nullable=False),
        sa.Column("password_enc", sa.Text(), nullable=False),
        sa.Column("source", sa.String(16), nullable=False, server_default="stored"),
        sa.Column("webspace", sa.String(255), nullable=True),
        sa.Column("plesk_db_id", sa.Integer(), nullable=True),
        sa.Column("plesk_user_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
    )


def downgrade() -> None:
    for name in ("db_credentials", "login_attempts", "accounts", "tokens", "auth_codes", "auth_requests", "clients"):
        op.drop_table(name)
