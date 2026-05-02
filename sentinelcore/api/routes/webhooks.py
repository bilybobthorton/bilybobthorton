from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import uuid
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, HttpUrl
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user
from api.database import get_db
from api.models.scan import User
from api.models.webhook import WebhookEndpoint

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

VALID_EVENTS = {"scan.complete", "scan.malicious", "scan.suspicious"}

MAX_WEBHOOKS = {"free": 0, "pro": 3, "enterprise": 20}


class WebhookCreate(BaseModel):
    url: HttpUrl
    events: list[str] = ["scan.malicious", "scan.suspicious"]
    name: str = "My Webhook"


class WebhookOut(BaseModel):
    id: str
    url: str
    events: list[str]
    is_active: bool
    secret: str
    created_at: str


@router.get("", response_model=list[WebhookOut])
async def list_webhooks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(WebhookEndpoint).where(WebhookEndpoint.user_id == current_user.id)
    )
    rows = result.scalars().all()
    return [_out(r) for r in rows]


@router.post("", response_model=WebhookOut, status_code=status.HTTP_201_CREATED)
async def create_webhook(
    body: WebhookCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    tier = current_user.tier or "free"
    limit = MAX_WEBHOOKS.get(tier, 0)
    if limit == 0:
        raise HTTPException(status_code=403, detail="Webhooks require Pro or Enterprise tier")

    result = await db.execute(
        select(WebhookEndpoint).where(WebhookEndpoint.user_id == current_user.id)
    )
    existing = result.scalars().all()
    if len(existing) >= limit:
        raise HTTPException(status_code=403, detail=f"Webhook limit reached ({limit} for {tier} tier)")

    invalid = [e for e in body.events if e not in VALID_EVENTS]
    if invalid:
        raise HTTPException(status_code=422, detail=f"Invalid events: {invalid}")

    endpoint = WebhookEndpoint(
        id=uuid.uuid4(),
        user_id=current_user.id,
        url=str(body.url),
        events=",".join(body.events),
        secret=secrets.token_hex(32),
    )
    db.add(endpoint)
    await db.commit()
    await db.refresh(endpoint)
    return _out(endpoint)


@router.delete("/{webhook_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_webhook(
    webhook_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == uuid.UUID(webhook_id),
            WebhookEndpoint.user_id == current_user.id,
        )
    )
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Webhook not found")
    await db.execute(delete(WebhookEndpoint).where(WebhookEndpoint.id == endpoint.id))
    await db.commit()


@router.post("/{webhook_id}/test", status_code=status.HTTP_200_OK)
async def test_webhook(
    webhook_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(WebhookEndpoint).where(
            WebhookEndpoint.id == uuid.UUID(webhook_id),
            WebhookEndpoint.user_id == current_user.id,
        )
    )
    endpoint = result.scalar_one_or_none()
    if not endpoint:
        raise HTTPException(status_code=404, detail="Webhook not found")

    payload = {
        "event": "webhook.test",
        "scan_id": "test-00000000",
        "filename": "test_file.exe",
        "sha256": "a" * 64,
        "threat_level": "clean",
        "confidence": 0.0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    success, status_code = await _fire(endpoint, payload)
    return {"success": success, "status_code": status_code}


def _out(r: WebhookEndpoint) -> WebhookOut:
    return WebhookOut(
        id=str(r.id),
        url=r.url,
        events=(r.events or "").split(","),
        is_active=r.is_active,
        secret=r.secret,
        created_at=r.created_at.isoformat() if r.created_at else "",
    )


def webhook_signature(secret: str, body: str) -> str:
    mac = hmac.new(secret.encode(), body.encode(), hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


async def _fire(endpoint: WebhookEndpoint, payload: dict) -> tuple[bool, int]:
    body = json.dumps(payload)
    sig = webhook_signature(endpoint.secret, body)
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            resp = await client.post(
                endpoint.url,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-Sentinel-Signature": sig,
                    "X-Sentinel-Event": payload.get("event", ""),
                    "User-Agent": "SentinelCore-Webhook/1.0",
                },
            )
            return resp.status_code < 400, resp.status_code
    except Exception:
        return False, 0
