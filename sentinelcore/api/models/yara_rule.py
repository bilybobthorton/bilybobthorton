import uuid

from sqlalchemy import Boolean, Column, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID

from api.models.scan import Base


class YaraRule(Base):
    __tablename__ = "yara_rules"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=True, index=True)  # None = built-in
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text)
    rule_text = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    is_builtin = Column(Boolean, default=False, nullable=False)
    hit_count = Column(String(20), default="0")   # stored as string to avoid BIGINT migration
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
