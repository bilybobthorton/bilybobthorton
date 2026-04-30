"""
Enterprise-tier endpoints.

All routes here require tier == "enterprise".
Currently includes MISP event export and push.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user
from api.config import get_settings, Settings
from api.database import get_db
from api.models.scan import ScanJob, User
from api.routes.report import _build_report_dict, _get_job   # reuse helpers
from api.services.misp import build_misp_event, push_to_misp

router = APIRouter(prefix="/api/v1/enterprise", tags=["enterprise"])


def _require_enterprise(user: User = Depends(get_current_user)) -> User:
    if user.tier != "enterprise":
        raise HTTPException(
            status_code=403,
            detail="This feature requires an Enterprise plan.",
        )
    return user


# ── MISP endpoints ────────────────────────────────────────────────────────────

class MISPExportResponse(BaseModel):
    scan_id: str
    misp_event: dict
    pushed: bool
    misp_event_uuid: str | None = None
    misp_event_url: str | None = None


@router.get("/misp/export/{scan_id}", response_model=MISPExportResponse)
async def misp_export(
    scan_id: str,
    push: bool = False,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(_require_enterprise),
    settings: Settings = Depends(get_settings),
):
    """
    Build a MISP event from a completed scan.

    - Returns the full MISP event JSON.
    - If `?push=true` and MISP_URL + MISP_KEY are configured, also pushes
      the event to your MISP instance.

    **Enterprise only.**
    """
    job = await _get_job(scan_id, db)
    report = _build_report_dict(job, current_user)
    event = build_misp_event(report, org_name="SentinelCore")

    pushed = False
    event_uuid: str | None = None
    event_url: str | None = None

    if push:
        if not settings.misp_url or not settings.misp_key:
            raise HTTPException(
                status_code=422,
                detail="MISP_URL and MISP_KEY must be configured to push events. "
                       "Set them in your .env file.",
            )
        try:
            response = await push_to_misp(
                event,
                misp_url=settings.misp_url,
                misp_key=settings.misp_key,
                verify_ssl=settings.misp_verify_ssl,
            )
            pushed = True
            event_uuid = response.get("Event", {}).get("uuid")
            if event_uuid and settings.misp_url:
                event_url = f"{settings.misp_url.rstrip('/')}/events/view/{event_uuid}"
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Failed to push event to MISP: {exc}",
            )

    return MISPExportResponse(
        scan_id=scan_id,
        misp_event=event,
        pushed=pushed,
        misp_event_uuid=event_uuid,
        misp_event_url=event_url,
    )


@router.post("/misp/push/{scan_id}", response_model=MISPExportResponse)
async def misp_push(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(_require_enterprise),
    settings: Settings = Depends(get_settings),
):
    """
    Build and immediately push a MISP event to your configured MISP instance.
    Requires MISP_URL and MISP_KEY in server config.

    **Enterprise only.**
    """
    if not settings.misp_url or not settings.misp_key:
        raise HTTPException(
            status_code=422,
            detail="MISP_URL and MISP_KEY must be set in server configuration.",
        )

    job = await _get_job(scan_id, db)
    report = _build_report_dict(job, current_user)
    event = build_misp_event(report, org_name="SentinelCore")

    try:
        response = await push_to_misp(
            event,
            misp_url=settings.misp_url,
            misp_key=settings.misp_key,
            verify_ssl=settings.misp_verify_ssl,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"MISP push failed: {exc}")

    event_uuid = response.get("Event", {}).get("uuid")
    event_url = (
        f"{settings.misp_url.rstrip('/')}/events/view/{event_uuid}"
        if event_uuid else None
    )

    return MISPExportResponse(
        scan_id=scan_id,
        misp_event=event,
        pushed=True,
        misp_event_uuid=event_uuid,
        misp_event_url=event_url,
    )
