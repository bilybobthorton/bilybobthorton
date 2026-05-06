"""
Shopify integration.

Endpoints:
  POST /api/v1/shopify/webhook      — Shopify webhook (HMAC verified, no auth)
  GET  /api/v1/shopify/subscription — current user subscription status
  GET  /api/v1/shopify/config       — public store URLs for frontend upgrade links
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy import update

from api.auth.dependencies import get_current_user
from api.config import get_settings
from api.database import get_session
from api.models.scan import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/shopify", tags=["shopify"])
settings = get_settings()

# Product title keywords → tier (checked in order; first match wins)
_TIER_KEYWORDS: list[tuple[str, str]] = [
    ("enterprise", "enterprise"),
    ("bundle", "pro"),      # Security Bundle = SentinelCore Pro + VPN
    ("pro", "pro"),
    ("vpn", "pro"),         # standalone VPN Pro treated as pro
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _detect_tier(line_items: list[dict]) -> str:
    for item in line_items:
        title = (item.get("title") or "").lower()
        for keyword, tier in _TIER_KEYWORDS:
            if keyword in title:
                return tier
    return "pro"


def _verify_hmac(body: bytes, hmac_header: str, secret: str) -> bool:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).digest()
    computed = base64.b64encode(digest).decode()
    return hmac.compare_digest(computed, hmac_header)


# ── Webhook ───────────────────────────────────────────────────────────────────

@router.post("/webhook", include_in_schema=False)
async def shopify_webhook(
    request: Request,
    x_shopify_hmac_sha256: str = Header(None, alias="X-Shopify-Hmac-Sha256"),
    x_shopify_topic: str = Header(None, alias="X-Shopify-Topic"),
):
    body = await request.body()

    if settings.shopify_webhook_secret:
        if not x_shopify_hmac_sha256:
            raise HTTPException(status_code=400, detail="Missing HMAC header")
        if not _verify_hmac(body, x_shopify_hmac_sha256, settings.shopify_webhook_secret):
            raise HTTPException(status_code=400, detail="Invalid webhook signature")

    data: dict = json.loads(body) if body else {}
    topic = x_shopify_topic or ""

    if topic == "orders/paid":
        await _handle_order_paid(data)
    elif topic in ("app/subscriptions/activate", "app/subscriptions/update"):
        await _handle_subscription_activate(data)
    elif topic in ("app/subscriptions/cancel", "orders/cancelled", "orders/refunded"):
        await _handle_order_cancelled(data)
    elif topic in ("customers/data_request", "customers/redact", "shop/redact"):
        # Shopify mandatory GDPR webhooks — acknowledge, no action needed for MVP
        logger.info("GDPR webhook received: %s", topic)

    return {"received": True}


async def _handle_order_paid(order: dict) -> None:
    email = (order.get("email") or "").lower().strip()
    shopify_customer_id = str(order.get("customer", {}).get("id", ""))
    line_items = order.get("line_items", [])

    if not email:
        return

    tier = _detect_tier(line_items)
    async with get_session() as db:
        await db.execute(
            update(User)
            .where(User.email == email)
            .values(tier=tier, shopify_customer_id=shopify_customer_id or None)
        )
        await db.commit()

    logger.info("Shopify order paid: email=%s tier=%s", email, tier)


async def _handle_subscription_activate(sub: dict) -> None:
    email = (
        sub.get("customer", {}).get("email")
        or sub.get("billing_address", {}).get("email")
        or ""
    ).lower().strip()
    shopify_customer_id = str(sub.get("customer", {}).get("id", ""))
    name = (sub.get("name") or "").lower()

    tier = "enterprise" if "enterprise" in name else "pro"

    if not email:
        return

    async with get_session() as db:
        await db.execute(
            update(User)
            .where(User.email == email)
            .values(tier=tier, shopify_customer_id=shopify_customer_id or None)
        )
        await db.commit()

    logger.info("Shopify subscription activated: email=%s tier=%s", email, tier)


async def _handle_order_cancelled(order: dict) -> None:
    email = (order.get("email") or "").lower().strip()
    if not email:
        return

    async with get_session() as db:
        await db.execute(
            update(User)
            .where(User.email == email)
            .values(tier="free")
        )
        await db.commit()

    logger.info("Shopify order cancelled/refunded: email=%s → free", email)


# ── REST endpoints ────────────────────────────────────────────────────────────

@router.get("/subscription")
async def get_subscription(current_user: User = Depends(get_current_user)):
    """Current user's subscription tier and Shopify link."""
    return {
        "tier": current_user.tier,
        "trial_ends_at": current_user.trial_ends_at,
        "shopify_customer_id": current_user.shopify_customer_id,
        "manage_url": f"{settings.shopify_store_url}/account" if settings.shopify_store_url else None,
    }


@router.get("/config")
async def get_shopify_config():
    """Public Shopify product URLs for the billing page upgrade buttons."""
    store = settings.shopify_store_url.rstrip("/") if settings.shopify_store_url else ""
    return {
        "store_url": store,
        "pro_url": settings.shopify_pro_url or (f"{store}/products/sentinelcore-pro" if store else None),
        "enterprise_url": settings.shopify_enterprise_url or (f"{store}/products/sentinelcore-enterprise" if store else None),
        "bundle_url": settings.shopify_bundle_url or (f"{store}/products/security-bundle" if store else None),
        "manage_url": f"{store}/account" if store else None,
    }
