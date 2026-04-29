"""
Stripe billing integration.

Endpoints:
  POST /api/v1/billing/checkout      — create Stripe Checkout session (Pro or Enterprise)
  POST /api/v1/billing/portal        — customer self-service portal URL
  POST /api/v1/billing/webhook       — Stripe webhook handler (no auth, sig verified)
  GET  /api/v1/billing/subscription  — current subscription status
"""
import logging
from typing import Literal

import stripe
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy import update

from api.auth.dependencies import get_current_user
from api.config import get_settings
from api.database import get_session
from api.models.scan import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/billing", tags=["billing"])
settings = get_settings()

PRICE_IDS = {
    "pro": settings.stripe_price_pro,
    "enterprise": settings.stripe_price_enterprise,
}

TIER_MAP = {
    "active": True,
    "trialing": True,
    "past_due": True,   # Grace period — keep access, prompt payment
    "canceled": False,
    "unpaid": False,
}


def _stripe_client() -> stripe.StripeClient:
    if not settings.stripe_secret_key:
        raise HTTPException(status_code=503, detail="Billing not configured")
    return stripe.StripeClient(settings.stripe_secret_key)


# ── Schemas ──────────────────────────────────────────────────────────────────

class CheckoutRequest(BaseModel):
    plan: Literal["pro", "enterprise"]
    success_url: str
    cancel_url: str


class CheckoutResponse(BaseModel):
    checkout_url: str
    session_id: str


class PortalRequest(BaseModel):
    return_url: str


# ── Endpoints ─────────────────────────────────────────────────────────────────

@router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(
    body: CheckoutRequest,
    current_user: User = Depends(get_current_user),
):
    """Create a Stripe Checkout session for plan upgrade."""
    client = _stripe_client()
    price_id = PRICE_IDS.get(body.plan)
    if not price_id:
        raise HTTPException(status_code=400, detail=f"Unknown plan: {body.plan}")

    # Create or reuse Stripe customer
    customer_id = current_user.stripe_customer_id
    if not customer_id:
        customer = client.customers.create(params={
            "email": current_user.email,
            "metadata": {"user_id": str(current_user.id)},
        })
        customer_id = customer.id
        async with get_session() as session:
            await session.execute(
                update(User)
                .where(User.id == current_user.id)
                .values(stripe_customer_id=customer_id)
            )
            await session.commit()

    session = client.checkout.sessions.create(params={
        "customer": customer_id,
        "mode": "subscription",
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": body.success_url,
        "cancel_url": body.cancel_url,
        "allow_promotion_codes": True,
        "subscription_data": {
            "metadata": {"user_id": str(current_user.id), "plan": body.plan}
        },
    })

    return CheckoutResponse(checkout_url=session.url, session_id=session.id)


@router.post("/portal")
async def customer_portal(
    body: PortalRequest,
    current_user: User = Depends(get_current_user),
):
    """Generate a Stripe Customer Portal URL for managing/canceling subscription."""
    client = _stripe_client()
    if not current_user.stripe_customer_id:
        raise HTTPException(status_code=400, detail="No active subscription found")

    portal = client.billing_portal.sessions.create(params={
        "customer": current_user.stripe_customer_id,
        "return_url": body.return_url,
    })
    return {"portal_url": portal.url}


@router.get("/subscription")
async def get_subscription(current_user: User = Depends(get_current_user)):
    """Return the current user's subscription state."""
    return {
        "tier": current_user.tier,
        "subscription_status": getattr(current_user, "subscription_status", None),
        "subscription_period_end": getattr(current_user, "subscription_period_end", None),
        "stripe_customer_id": current_user.stripe_customer_id,
    }


@router.post("/webhook", include_in_schema=False)
async def stripe_webhook(
    request: Request,
    stripe_signature: str = Header(None, alias="stripe-signature"),
):
    """
    Stripe sends signed events here.
    Handles: checkout.session.completed, customer.subscription.updated,
             customer.subscription.deleted, invoice.payment_failed
    """
    if not settings.stripe_webhook_secret:
        raise HTTPException(status_code=503, detail="Webhook secret not configured")

    body = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            body, stripe_signature, settings.stripe_webhook_secret
        )
    except stripe.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid webhook signature")

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        await _handle_checkout_complete(data)

    elif event_type in ("customer.subscription.updated", "customer.subscription.created"):
        await _handle_subscription_update(data)

    elif event_type == "customer.subscription.deleted":
        await _handle_subscription_deleted(data)

    elif event_type == "invoice.payment_failed":
        customer_id = data.get("customer")
        logger.warning("Payment failed for customer %s", customer_id)
        # Could send an email here via background task

    return {"received": True}


# ── Webhook helpers ───────────────────────────────────────────────────────────

async def _handle_checkout_complete(session_obj: dict) -> None:
    customer_id = session_obj.get("customer")
    subscription_id = session_obj.get("subscription")
    plan = session_obj.get("metadata", {}).get("plan", "pro")

    if not customer_id:
        return

    async with get_session() as db:
        await db.execute(
            update(User)
            .where(User.stripe_customer_id == customer_id)
            .values(
                tier=plan,
                stripe_subscription_id=subscription_id,
                subscription_status="active",
            )
        )
        await db.commit()

    logger.info("Checkout complete: customer=%s plan=%s", customer_id, plan)


async def _handle_subscription_update(sub: dict) -> None:
    from datetime import datetime, timezone

    customer_id = sub.get("customer")
    status = sub.get("status")
    period_end_ts = sub.get("current_period_end")
    plan = sub.get("metadata", {}).get("plan", "pro")
    period_end = datetime.fromtimestamp(period_end_ts, tz=timezone.utc) if period_end_ts else None

    # If subscription is canceled/unpaid, downgrade tier
    new_tier = plan if TIER_MAP.get(status, False) else "free"

    async with get_session() as db:
        await db.execute(
            update(User)
            .where(User.stripe_customer_id == customer_id)
            .values(
                tier=new_tier,
                subscription_status=status,
                subscription_period_end=period_end,
            )
        )
        await db.commit()

    logger.info("Subscription updated: customer=%s status=%s tier=%s", customer_id, status, new_tier)


async def _handle_subscription_deleted(sub: dict) -> None:
    customer_id = sub.get("customer")
    async with get_session() as db:
        await db.execute(
            update(User)
            .where(User.stripe_customer_id == customer_id)
            .values(tier="free", subscription_status="canceled", stripe_subscription_id=None)
        )
        await db.commit()
    logger.info("Subscription deleted: customer=%s → downgraded to free", customer_id)
