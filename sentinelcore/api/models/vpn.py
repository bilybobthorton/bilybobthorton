from __future__ import annotations

import uuid

from sqlalchemy import Column, DateTime, String, Text, func
from sqlalchemy.dialects.postgresql import UUID

from api.models.scan import Base


class VpnKey(Base):
    __tablename__ = "vpn_keys"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=False, index=True)
    name = Column(String(100), nullable=False, default="My Device")
    # WireGuard keys (base64-encoded)
    public_key = Column(Text, nullable=False)
    private_key = Column(Text, nullable=False)
    preshared_key = Column(Text, nullable=False)
    # Assigned client IP (e.g. 10.8.0.5/32)
    client_ip = Column(String(20), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
