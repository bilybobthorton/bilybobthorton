import uuid

from sqlalchemy import Column, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID

from api.models.scan import Base


class AgentAlert(Base):
    __tablename__ = "agent_alerts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Sent by the agent
    remote_id = Column(String(64), index=True)       # Alert UUID from the agent
    agent_id = Column(String(64), index=True)
    hostname = Column(String(255), index=True)
    kind = Column(String(64), index=True)
    severity = Column(String(20), index=True)
    title = Column(String(512))
    description = Column(Text)
    path = Column(Text)
    mitre_technique = Column(String(32))
    process_json = Column(JSONB)                     # ProcessContext
    hashes_json = Column(JSONB)                      # FileHashes
    raw_json = Column(JSONB)                         # Full alert payload for forward-compat
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    agent_timestamp = Column(DateTime(timezone=True))
