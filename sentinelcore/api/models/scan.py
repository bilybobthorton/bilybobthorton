import uuid
from enum import Enum

from sqlalchemy import Column, DateTime, Float, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class TierEnum(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    tier = Column(String(20), default=TierEnum.FREE)
    api_key = Column(String(64), unique=True, index=True)
    scans_today = Column(Integer, default=0)
    scans_reset_at = Column(DateTime(timezone=True))
    trial_ends_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), nullable=True)
    filename = Column(String(512))
    file_size = Column(Integer)
    sha256 = Column(String(64), index=True)
    status = Column(String(20), default=ScanStatus.QUEUED)
    threat_level = Column(String(20))
    confidence = Column(Float)
    result_json = Column(JSONB)
    error = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
