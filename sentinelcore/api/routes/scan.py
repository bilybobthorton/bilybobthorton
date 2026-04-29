import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user_optional
from api.config import Settings, get_settings
from api.database import get_db
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


class ScanResult(BaseModel):
    scan_id: str
    filename: str
    sha256: str | None
    status: str
    threat_level: str | None
    confidence: float | None
    indicators: list[str]
    error: str | None


@router.post("/file", response_model=ScanSubmitted, status_code=status.HTTP_202_ACCEPTED)
async def scan_file(
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings),
    db: AsyncSession = Depends(get_db),
    current_user: User | None = Depends(get_current_user_optional),
):
    if file.size and file.size > settings.max_file_size_mb * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File exceeds {settings.max_file_size_mb}MB limit")

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

    run_scan.delay(scan_id, str(dest), file.filename or "unknown",
                   str(current_user.id) if current_user else None)

    return ScanSubmitted(scan_id=scan_id, filename=file.filename or "unknown", status="queued")


@router.get("/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    indicators = []
    sha256 = None
    if job.result_json:
        indicators = job.result_json.get("indicators", [])
        hashes = job.result_json.get("hashes", {})
        sha256 = hashes.get("sha256")

    return ScanResult(
        scan_id=str(job.id),
        filename=job.filename,
        sha256=sha256,
        status=job.status,
        threat_level=job.threat_level,
        confidence=job.confidence,
        indicators=indicators,
        error=job.error,
    )


@router.post("/hash")
async def lookup_hash(body: HashLookupRequest):
    vt = await vt_lookup_hash(body.hash)
    return {
        "hash": body.hash,
        "virustotal": vt,
        "source": "virustotal" if vt else "local_db",
    }
