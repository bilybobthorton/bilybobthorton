"""Add email verification fields to users

Revision ID: 0005
Revises: 0004
Create Date: 2026-05-02
"""
from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("is_verified", sa.Boolean(), nullable=False, server_default="false"))
    op.add_column("users", sa.Column("verification_token", sa.String(length=64), nullable=True))
    op.create_index("ix_users_verification_token", "users", ["verification_token"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_verification_token", table_name="users")
    op.drop_column("users", "verification_token")
    op.drop_column("users", "is_verified")
