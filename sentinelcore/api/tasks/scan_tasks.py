import asyncio
import dataclasses
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session

from api.config import get_settings
from api.models.scan import ScanJob
from api.tasks.celery_app import celery_app
from engine.intel import hash_db
from engine.intel.virustotal import VirusTotalClient
from engine.static.analyzer import analyze_file
from engine.static.models import ThreatLevel

settings = get_settings()

_sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
_engine = create_engine(_sync_url, pool_pre_ping=True)


def _get_session() -> Session:
    return Session(_engine)


def _serialize(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    return str(obj)


def _run_async(coro):
    """Run an async coroutine from a sync Celery task."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


@celery_app.task(bind=True, name="scan_tasks.run_scan", max_retries=2)
def run_scan(self, scan_id: str, file_path: str, filename: str, user_id: str | None = None):
    path = Path(file_path)

    with _get_session() as db:
        db.execute(
            update(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)).values(status="running")
        )
        db.commit()

    try:
        result = analyze_file(path)
        indicators = list(result.indicators)

        # ── Layer 1: local hash reputation ───────────────────────────────────
        sha256 = result.hashes.sha256
        local_hit = _run_async(hash_db.lookup(sha256))

        if local_hit:
            result = dataclasses.replace(result, threat_level=ThreatLevel.MALICIOUS, confidence=1.0)
            indicators.insert(0, f"Known malicious hash (local DB): {sha256[:16]}...")

        # ── Layer 2: VirusTotal enrichment ────────────────────────────────────
        vt_data = None
        if settings.virustotal_api_key:
            vt_client = VirusTotalClient(settings.virustotal_api_key)
            vt_data = _run_async(vt_client.lookup_hash(sha256))

            if vt_data and vt_data.get("found"):
                malicious = vt_data.get("malicious", 0)
                total = vt_data.get("total_engines", 1)
                if malicious > 0:
                    vt_score = malicious / total
                    # Boost confidence based on VT detections
                    new_confidence = max(result.confidence, min(0.5 + vt_score * 0.5, 1.0))
                    result = dataclasses.replace(
                        result,
                        threat_level=ThreatLevel.MALICIOUS if malicious >= 3 else ThreatLevel.SUSPICIOUS,
                        confidence=new_confidence,
                    )
                    indicators.insert(0, f"VirusTotal: {malicious}/{total} engines detected ({vt_data.get('popular_threat_name', '')})")
                    # Add to local cache so we don't re-query VT for the same hash
                    hash_db.add_hash(sha256)

        # Build final result dict
        result_dict = json.loads(json.dumps(dataclasses.asdict(result), default=_serialize))
        result_dict["indicators"] = indicators
        if vt_data:
            result_dict["virustotal"] = vt_data

        with _get_session() as db:
            db.execute(
                update(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)).values(
                    status="complete",
                    threat_level=result.threat_level.value,
                    confidence=result.confidence,
                    result_json=result_dict,
                    completed_at=datetime.now(timezone.utc),
                )
            )
            db.commit()

    except Exception as exc:
        with _get_session() as db:
            db.execute(
                update(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)).values(
                    status="failed",
                    error=str(exc),
                    completed_at=datetime.now(timezone.utc),
                )
            )
            db.commit()
        raise self.retry(exc=exc, countdown=5)
    finally:
        path.unlink(missing_ok=True)
