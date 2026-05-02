"""Create vpn_keys table

Revision ID: 0007
Revises: 0006
Create Date: 2026-05-02
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vpn_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("private_key", sa.Text(), nullable=False),
        sa.Column("preshared_key", sa.Text(), nullable=False),
        sa.Column("client_ip", sa.String(length=20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vpn_keys_user_id", "vpn_keys", ["user_id"])


def downgrade() -> None:
    op.drop_index("ix_vpn_keys_user_id", table_name="vpn_keys")
    op.drop_table("vpn_keys")
