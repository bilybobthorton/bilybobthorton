"""add agent_alerts table

Revision ID: 0002
Revises: 0001
Create Date: 2026-04-29
"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "agent_alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("remote_id", sa.String(64), nullable=True),
        sa.Column("agent_id", sa.String(64), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("kind", sa.String(64), nullable=True),
        sa.Column("severity", sa.String(20), nullable=True),
        sa.Column("title", sa.String(512), nullable=True),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("path", sa.Text, nullable=True),
        sa.Column("mitre_technique", sa.String(32), nullable=True),
        sa.Column("process_json", postgresql.JSONB, nullable=True),
        sa.Column("hashes_json", postgresql.JSONB, nullable=True),
        sa.Column("raw_json", postgresql.JSONB, nullable=True),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
        ),
        sa.Column("agent_timestamp", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_agent_alerts_remote_id", "agent_alerts", ["remote_id"])
    op.create_index("ix_agent_alerts_agent_id", "agent_alerts", ["agent_id"])
    op.create_index("ix_agent_alerts_hostname", "agent_alerts", ["hostname"])
    op.create_index("ix_agent_alerts_kind", "agent_alerts", ["kind"])
    op.create_index("ix_agent_alerts_severity", "agent_alerts", ["severity"])


def downgrade() -> None:
    op.drop_table("agent_alerts")
