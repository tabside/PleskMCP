"""signup orders and events

Revision ID: 0002_signup
Revises: 0001_initial
Create Date: 2026-10-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0002_signup"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "signup_orders",
        sa.Column("id", sa.String(32), primary_key=True),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("previous_status", sa.String(24), nullable=True),
        sa.Column("attention_reason", sa.String(64), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(128), nullable=True),
        sa.Column("company", sa.String(100), nullable=True),
        sa.Column("first_name", sa.String(60), nullable=False),
        sa.Column("last_name", sa.String(60), nullable=False),
        sa.Column("street", sa.String(120), nullable=False),
        sa.Column("zip", sa.String(16), nullable=False),
        sa.Column("city", sa.String(60), nullable=False),
        sa.Column("country", sa.String(2), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("phone", sa.String(32), nullable=True),
        sa.Column("domain_mode", sa.String(8), nullable=False),
        sa.Column("domain", sa.String(253), nullable=False),
        sa.Column("tld", sa.String(32), nullable=True),
        sa.Column("domain_price", sa.Float(), nullable=True),
        sa.Column("hosting_price", sa.Float(), nullable=False),
        sa.Column("terms_version", sa.String(32), nullable=False),
        sa.Column("terms_accepted_at", sa.Integer(), nullable=False),
        sa.Column("ip_hash", sa.String(64), nullable=False),
        sa.Column("bexio_contact_id", sa.Integer(), nullable=True),
        sa.Column("rebill_external_ref", sa.String(100), nullable=True),
        sa.Column("rebill_recurring_id", sa.Integer(), nullable=True),
        sa.Column("bexio_invoice_id", sa.Integer(), nullable=True),
        sa.Column("invoice_due_date", sa.String(10), nullable=True),
        sa.Column("paid_at", sa.Integer(), nullable=True),
        sa.Column("subscription_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("period_end", sa.String(10), nullable=True),
        sa.Column("last_invoice_id", sa.Integer(), nullable=True),
        sa.Column("last_invoice_due", sa.String(10), nullable=True),
        sa.Column("last_invoice_status", sa.String(16), nullable=True),
        sa.Column("last_invoice_checked_at", sa.Integer(), nullable=True),
        sa.Column("zammad_ticket_id", sa.Integer(), nullable=True),
        sa.Column("netim_owner_contact_id", sa.String(32), nullable=True),
        sa.Column("netim_operation_id", sa.Integer(), nullable=True),
        sa.Column("netim_operation_started", sa.Integer(), nullable=True),
        sa.Column("domain_status", sa.String(16), nullable=False, server_default="none"),
        sa.Column("domain_expires", sa.String(10), nullable=True),
        sa.Column("domain_renewed_until", sa.String(10), nullable=True),
        sa.Column("domain_renew_notice_for", sa.String(10), nullable=True),
        sa.Column("plesk_login", sa.String(64), nullable=True),
        sa.Column("plesk_customer_id", sa.Integer(), nullable=True),
        sa.Column("plesk_webspace_id", sa.Integer(), nullable=True),
        sa.Column("sysuser", sa.String(64), nullable=True),
        sa.Column("activated_at", sa.Integer(), nullable=True),
        sa.Column("suspended_at", sa.Integer(), nullable=True),
        sa.Column("suspend_reason", sa.String(32), nullable=True),
        sa.Column("cancelled_at", sa.Integer(), nullable=True),
        sa.Column("delete_after", sa.Integer(), nullable=True),
        sa.Column("backup_started_at", sa.Integer(), nullable=True),
        sa.Column("backup_done_at", sa.Integer(), nullable=True),
        sa.Column("backup_result", sa.String(128), nullable=True),
        sa.Column("deleted_at", sa.Integer(), nullable=True),
        sa.Column("welcome_token_hash", sa.String(64), nullable=True),
        sa.Column("welcome_token_expires", sa.Integer(), nullable=True),
        sa.Column("welcome_sent_at", sa.Integer(), nullable=True),
    )
    op.create_index("signup_orders_status", "signup_orders", ["status"])
    op.create_index("signup_orders_email", "signup_orders", ["email"])
    op.create_index("signup_orders_domain", "signup_orders", ["domain"])
    op.create_table(
        "signup_events",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("order_id", sa.String(32), nullable=False),
        sa.Column("ts", sa.Integer(), nullable=False),
        sa.Column("event", sa.String(48), nullable=False),
        sa.Column("data_json", sa.Text(), nullable=False, server_default="{}"),
    )
    op.create_index("signup_events_order", "signup_events", ["order_id"])


def downgrade() -> None:
    op.drop_table("signup_events")
    op.drop_table("signup_orders")
