from __future__ import annotations
import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user, get_current_user_optional
from api.config import Settings, get_settings
from api.database import get_db
from api.middleware.rate_limit import check_and_increment, get_remaining
from api.models.scan import ScanJob, User
from api.tasks.scan_tasks import run_scan
from engine.intel.virustotal import vt_lookup_hash

router = APIRouter(prefix="/scan", tags=["scan"])


class HashLookupRequest(BaseModel):
    hash: str


class ScanSubmitted(BaseModel):
    scan_id: str
    filename: str
    status: str
    scans_remaining: int | None = None


class ScanResult(BaseModel):
    scan_id: str
    filename: str
    sha256: str | None
    status: str
    threat_level: str | None
    confidence: float | None
    indicators: list[str]
    ml: dict | None = None
    virustotal: dict | None = None
    otx: dict | None = None
    heuristics: dict | None = None
    error: str | None


class ScanHistoryItem(BaseModel):
    scan_id: str
    filename: str
    sha256: str | None
    status: str
    threat_level: str | None
    confidence: float | None
    created_at: str
    completed_at: str | None


@router.post("/file", response_model=ScanSubmitted, status_code=status.HTTP_202_ACCEPTED)
async def scan_file(
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    if file.size and file.size > settings.max_file_size_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_file_size_mb}MB limit")

    # Enforce tier quota
    await check_and_increment(current_user)

    scan_id = str(uuid.uuid4())
    upload_dir = Path(settings.upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / scan_id

    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    job = ScanJob(
        id=uuid.UUID(scan_id),
        user_id=current_user.id if current_user else None,
        filename=file.filename or "unknown",
        file_size=dest.stat().st_size,
        status="queued",
    )
    db.add(job)
    await db.commit()

    run_scan.delay(
        scan_id, str(dest), file.filename or "unknown",
        str(current_user.id) if current_user else None,
    )

    scans_remaining = None
    if current_user:
        quota = await get_remaining(current_user)
        scans_remaining = quota.get("remaining")

    return ScanSubmitted(
        scan_id=scan_id,
        filename=file.filename or "unknown",
        status="queued",
        scans_remaining=scans_remaining,
    )


@router.get("/history", response_model=list[ScanHistoryItem])
async def scan_history(
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Return the authenticated user's scan history, newest first."""
    result = await db.execute(
        select(ScanJob)
        .where(ScanJob.user_id == current_user.id)
        .order_by(desc(ScanJob.created_at))
        .limit(limit)
        .offset(offset)
    )
    jobs = result.scalars().all()
    return [
        ScanHistoryItem(
            scan_id=str(j.id),
            filename=j.filename,
            sha256=j.result_json.get("hashes", {}).get("sha256") if j.result_json else None,
            status=j.status,
            threat_level=j.threat_level,
            confidence=j.confidence,
            created_at=j.created_at.isoformat() if j.created_at else "",
            completed_at=j.completed_at.isoformat() if j.completed_at else None,
        )
        for j in jobs
    ]


@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    indicators = []
    sha256 = None
    ml_data = None
    vt_data = None
    otx_data = None
    heuristics_data = None

    if job.result_json:
        indicators = job.result_json.get("indicators", [])
        hashes = job.result_json.get("hashes", {})
        sha256 = hashes.get("sha256")
        ml_data = job.result_json.get("ml")
        vt_data = job.result_json.get("virustotal")
        otx_data = job.result_json.get("otx")
        heuristics_data = job.result_json.get("heuristics")

    return ScanResult(
        scan_id=str(job.id),
        filename=job.filename,
        sha256=sha256,
        status=job.status,
        threat_level=job.threat_level,
        confidence=job.confidence,
        indicators=indicators,
        ml=ml_data,
        virustotal=vt_data,
        otx=otx_data,
        heuristics=heuristics_data,
        error=job.error,
    )


@router.post("/hash")
async def lookup_hash(body: HashLookupRequest):
    vt = await vt_lookup_hash(body.hash)
    local_hit = body.hash.lower() in _local_bad_hashes()
    return {
        "hash": body.hash,
        "local_db": {"found": local_hit, "malicious": local_hit},
        "virustotal": vt,
    }


@router.get("/quota/me")
async def my_quota(current_user: User = Depends(get_current_user)):
    """Return the authenticated user's scan quota status."""
    return await get_remaining(current_user)


def _local_bad_hashes() -> set:
    try:
        from engine.intel.hash_db import _KNOWN_BAD
        return _KNOWN_BAD
    except Exception:
        return set()
