import shutil
import uuid
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel

from api.config import Settings, get_settings
from engine.static.analyzer import analyze_file
from engine.static.models import ThreatLevel

router = APIRouter(prefix="/scan", tags=["scan"])


class HashLookupRequest(BaseModel):
    hash: str


class ScanSummary(BaseModel):
    scan_id: str
    filename: str
    sha256: str
    threat_level: str
    confidence: float
    indicators: list[str]
    status: str


class ScanDetail(ScanSummary):
    file_size: int
    file_type: str
    mime_type: str
    yara_matches: list[str]
    suspicious_imports: list[str]
    embedded_urls: list[str]
    embedded_ips: list[str]
    errors: list[str]


@router.post("/file", response_model=ScanSummary, status_code=status.HTTP_202_ACCEPTED)
async def scan_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    settings: Settings = Depends(get_settings),
):
    if file.size and file.size > settings.max_file_size_mb * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File exceeds {settings.max_file_size_mb}MB limit",
        )

    scan_id = str(uuid.uuid4())
    upload_dir = Path(settings.upload_dir)
    upload_dir.mkdir(parents=True, exist_ok=True)
    dest = upload_dir / scan_id

    with dest.open("wb") as f:
        shutil.copyfileobj(file.file, f)

    # Run static analysis synchronously for now; move to Celery in next iteration
    try:
        result = analyze_file(dest)
    except Exception as e:
        dest.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=str(e))

    yara_names = [m.rule_name for m in result.yara_matches]
    suspicious_imports: list[str] = []
    embedded_urls: list[str] = []
    embedded_ips: list[str] = []

    if result.pe_info and result.pe_info.is_pe:
        from engine.static.pe_analyzer import get_suspicious_imports
        suspicious_imports = get_suspicious_imports(result.pe_info)

    if result.strings:
        embedded_urls = result.strings.urls
        embedded_ips = result.strings.ips

    background_tasks.add_task(dest.unlink, missing_ok=True)

    return ScanSummary(
        scan_id=scan_id,
        filename=file.filename or "unknown",
        sha256=result.hashes.sha256,
        threat_level=result.threat_level.value,
        confidence=result.confidence,
        indicators=result.indicators,
        status="complete",
    )


@router.post("/hash", status_code=status.HTTP_200_OK)
async def lookup_hash(body: HashLookupRequest):
    # TODO: query internal hash reputation DB + VirusTotal
    return {
        "hash": body.hash,
        "known_malicious": False,
        "source": "local_db",
        "message": "Hash reputation lookup not yet implemented — coming soon",
    }
