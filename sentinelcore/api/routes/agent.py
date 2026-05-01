"""
Agent alert ingestion — receives real-time detections from the Rust endpoint agent.
Authenticated via X-API-Key header (same as the scan API).
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import text

from api.auth.dependencies import get_current_user
from api.database import get_session
from api.models.alert import AgentAlert
from api.models.scan import User

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])


# ── Pydantic schemas (mirror the Rust Alert struct) ─────────────────────────

class ProcessContext(BaseModel):
    pid: int
    name: str
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    cmdline: Optional[str] = None
    exe_path: Optional[str] = None


class FileHashes(BaseModel):
    md5: str
    sha256: str


class AlertPayload(BaseModel):
    id: str
    kind: str
    severity: str
    title: str
    description: str
    path: Optional[str] = None
    process: Optional[ProcessContext] = None
    hashes: Optional[FileHashes] = None
    timestamp: datetime
    hostname: str
    mitre_technique: Optional[str] = None


class AgentAlertRequest(BaseModel):
    agent_id: str
    hostname: str
    alert: AlertPayload


class AlertResponse(BaseModel):
    id: str
    remote_id: str
    agent_id: str
    hostname: str
    kind: str
    severity: str
    title: str
    description: str
    path: Optional[str]
    mitre_technique: Optional[str]
    process: Optional[Dict[str, Any]]
    hashes: Optional[Dict[str, Any]]
    received_at: datetime
    agent_timestamp: datetime

    class Config:
        from_attributes = True


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/alert", status_code=201)
async def ingest_alert(
    body: AgentAlertRequest,
    current_user: User = Depends(get_current_user),
):
    """Receive an alert from an endpoint agent."""
    alert = body.alert

    row = AgentAlert(
        remote_id=alert.id,
        agent_id=body.agent_id,
        hostname=alert.hostname,
        kind=alert.kind,
        severity=alert.severity,
        title=alert.title,
        description=alert.description,
        path=alert.path,
        mitre_technique=alert.mitre_technique,
        process_json=alert.process.model_dump() if alert.process else None,
        hashes_json=alert.hashes.model_dump() if alert.hashes else None,
        raw_json=alert.model_dump(),
        agent_timestamp=alert.timestamp,
    )

    async with get_session() as session:
        session.add(row)
        await session.commit()
        await session.refresh(row)

    return {"status": "accepted", "id": str(row.id)}


@router.get("/alerts", response_model=List[AlertResponse])
async def list_alerts(
    hostname: Optional[str] = Query(None),
    kind: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    limit: int = Query(100, le=500),
    offset: int = Query(0),
    current_user: User = Depends(get_current_user),
):
    """List ingested agent alerts. Supports filtering by hostname, kind, severity."""
    async with get_session() as session:
        q = "SELECT * FROM agent_alerts WHERE 1=1"
        params: Dict[str, Any] = {}

        if hostname:
            q += " AND hostname = :hostname"
            params["hostname"] = hostname
        if kind:
            q += " AND kind = :kind"
            params["kind"] = kind
        if severity:
            q += " AND severity = :severity"
            params["severity"] = severity

        q += " ORDER BY received_at DESC LIMIT :limit OFFSET :offset"
        params["limit"] = limit
        params["offset"] = offset

        result = await session.execute(text(q), params)
        rows = result.mappings().all()

    return [
        AlertResponse(
            id=str(r["id"]),
            remote_id=r["remote_id"],
            agent_id=r["agent_id"],
            hostname=r["hostname"],
            kind=r["kind"],
            severity=r["severity"],
            title=r["title"],
            description=r["description"],
            path=r["path"],
            mitre_technique=r["mitre_technique"],
            process=r["process_json"],
            hashes=r["hashes_json"],
            received_at=r["received_at"],
            agent_timestamp=r["agent_timestamp"],
        )
        for r in rows
    ]


@router.get("/stats")
async def agent_stats(current_user: User = Depends(get_current_user)):
    """Summary stats across all agent alerts."""
    async with get_session() as session:
        result = await session.execute(
            text("""
                SELECT
                    COUNT(*)                                          AS total,
                    COUNT(*) FILTER (WHERE severity = 'critical')    AS critical,
                    COUNT(*) FILTER (WHERE severity = 'high')        AS high,
                    COUNT(*) FILTER (WHERE severity = 'medium')      AS medium,
                    COUNT(*) FILTER (WHERE severity = 'low')         AS low,
                    COUNT(DISTINCT hostname)                          AS hosts,
                    COUNT(DISTINCT kind)                              AS unique_alert_types,
                    MAX(received_at)                                  AS last_seen
                FROM agent_alerts
            """)
        )
        row = result.mappings().one()

    return dict(row)
