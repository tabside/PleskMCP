"""signup: e-mail confirmation before the invoice

Revision ID: 0003_signup_confirmation
Revises: 0002_signup
Create Date: 2026-10-17
"""
from alembic import op
import sqlalchemy as sa

revision = "0003_signup_confirmation"
down_revision = "0002_signup"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("signup_orders", sa.Column("confirm_token_hash", sa.String(64), nullable=True))
    op.add_column("signup_orders", sa.Column("confirm_expires", sa.Integer(), nullable=True))
    op.add_column("signup_orders", sa.Column("confirmed_at", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("signup_orders", "confirmed_at")
    op.drop_column("signup_orders", "confirm_expires")
    op.drop_column("signup_orders", "confirm_token_hash")
