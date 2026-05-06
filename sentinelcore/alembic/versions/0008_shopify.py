"""replace stripe billing with shopify

Revision ID: 0008
Revises: 0007
Create Date: 2026-05-05
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("users", sa.Column("shopify_customer_id", sa.String(64), nullable=True))
    op.create_index("ix_users_shopify_customer_id", "users", ["shopify_customer_id"])

    # Drop Stripe columns — no longer used
    op.drop_index("ix_users_stripe_customer_id", table_name="users")
    op.drop_column("users", "stripe_customer_id")
    op.drop_column("users", "stripe_subscription_id")
    op.drop_column("users", "subscription_status")
    op.drop_column("users", "subscription_period_end")


def downgrade() -> None:
    op.drop_index("ix_users_shopify_customer_id", table_name="users")
    op.drop_column("users", "shopify_customer_id")

    op.add_column("users", sa.Column("stripe_customer_id", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("stripe_subscription_id", sa.String(64), nullable=True))
    op.add_column("users", sa.Column("subscription_status", sa.String(32), nullable=True))
    op.add_column("users", sa.Column("subscription_period_end", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_users_stripe_customer_id", "users", ["stripe_customer_id"])
