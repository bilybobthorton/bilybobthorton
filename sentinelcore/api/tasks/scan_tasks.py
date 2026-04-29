import asyncio
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, update
from sqlalchemy.orm import Session

from api.config import get_settings
from api.models.scan import ScanJob
from api.tasks.celery_app import celery_app
from engine.static.analyzer import analyze_file

settings = get_settings()

# Sync engine for Celery workers (Celery is sync by default)
_sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
_engine = create_engine(_sync_url, pool_pre_ping=True)


def _get_session() -> Session:
    return Session(_engine)


@celery_app.task(bind=True, name="scan_tasks.run_scan", max_retries=2)
def run_scan(self, scan_id: str, file_path: str, filename: str, user_id: str | None = None):
    path = Path(file_path)

    with _get_session() as db:
        db.execute(
            update(ScanJob).where(ScanJob.id == uuid.UUID(scan_id))
            .values(status="running")
        )
        db.commit()

    try:
        result = analyze_file(path)

        import dataclasses, json

        def _serialize(obj):
            if dataclasses.is_dataclass(obj):
                return dataclasses.asdict(obj)
            if isinstance(obj, bytes):
                return obj.hex()
            return str(obj)

        result_dict = json.loads(json.dumps(dataclasses.asdict(result), default=_serialize))

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
                    status="failed", error=str(exc),
                    completed_at=datetime.now(timezone.utc),
                )
            )
            db.commit()
        raise self.retry(exc=exc, countdown=5)
    finally:
        path.unlink(missing_ok=True)
