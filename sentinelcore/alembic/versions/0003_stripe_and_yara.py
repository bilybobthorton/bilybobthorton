"""add stripe fields to users and yara_rules table

Revision ID: 0003
Revises: 0002
Create Date: 2026-04-29
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Stripe fields on users
    op.add_column("users", sa.Column("stripe_customer_id", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("stripe_subscription_id", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("subscription_status", sa.String(32), nullable=True))
    op.add_column("users", sa.Column("subscription_period_end", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_users_stripe_customer_id", "users", ["stripe_customer_id"])

    # YARA rules
    op.create_table(
        "yara_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("name", sa.String(255), nullable=False, unique=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("rule_text", sa.Text, nullable=False),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true"), nullable=False),
        sa.Column("is_builtin", sa.Boolean, server_default=sa.text("false"), nullable=False),
        sa.Column("hit_count", sa.String(20), server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_yara_rules_name", "yara_rules", ["name"])
    op.create_index("ix_yara_rules_user_id", "yara_rules", ["user_id"])


def downgrade() -> None:
    op.drop_table("yara_rules")
    op.drop_index("ix_users_stripe_customer_id", "users")
    op.drop_column("users", "subscription_period_end")
    op.drop_column("users", "subscription_status")
    op.drop_column("users", "stripe_subscription_id")
    op.drop_column("users", "stripe_customer_id")
