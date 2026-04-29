"""initial schema

Revision ID: 0001
Revises:
Create Date: 2026-04-29
"""
from typing import Sequence, Union
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from alembic import op

revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("tier", sa.String(20), server_default="free"),
        sa.Column("api_key", sa.String(64), unique=True),
        sa.Column("scans_today", sa.Integer, server_default="0"),
        sa.Column("scans_reset_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("ix_users_email", "users", ["email"])
    op.create_index("ix_users_api_key", "users", ["api_key"])

    op.create_table(
        "scan_jobs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("filename", sa.String(512)),
        sa.Column("file_size", sa.Integer),
        sa.Column("sha256", sa.String(64)),
        sa.Column("status", sa.String(20), server_default="queued"),
        sa.Column("threat_level", sa.String(20)),
        sa.Column("confidence", sa.Float),
        sa.Column("result_json", postgresql.JSONB),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
    )
    op.create_index("ix_scan_jobs_sha256", "scan_jobs", ["sha256"])


def downgrade() -> None:
    op.drop_table("scan_jobs")
    op.drop_table("users")
