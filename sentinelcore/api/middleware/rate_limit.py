"""
Scan rate limiting for free tier users.
Uses Redis for atomic daily counters — resets at midnight UTC.
Trial users get Pro-tier limits for the duration of their trial.
"""
from __future__ import annotations

from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import HTTPException

from api.config import get_settings
from api.models.scan import User

settings = get_settings()
_redis: aioredis.Redis | None = None


def _get_redis() -> aioredis.Redis:
    global _redis
    if _redis is None:
        _redis = aioredis.from_url(settings.redis_url, decode_responses=True)
    return _redis


def _today_key(user_id: str) -> str:
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    return f"scan_count:{user_id}:{day}"


async def check_and_increment(user: User | None) -> int:
    """
    Enforce per-tier daily scan limits.
    Returns the new count after incrementing.
    Raises HTTP 429 if limit exceeded.
    """
    if user is None:
        return 0

    tier = user.tier or "free"
    # Active trial → treat as Pro for limit purposes
    if tier == "free" and user.trial_ends_at and user.trial_ends_at > datetime.now(timezone.utc):
        tier = "pro"

    limits = {
        "free": settings.free_tier_scans_per_day,
        "pro": settings.pro_tier_scans_per_day,
        "enterprise": 0,  # 0 = unlimited
    }
    limit = limits.get(tier, settings.free_tier_scans_per_day)

    if limit == 0:
        return 0  # unlimited

    r = _get_redis()
    key = _today_key(str(user.id))

    # Atomic increment + set 25-hour expiry on first write
    count = await r.incr(key)
    if count == 1:
        await r.expire(key, 90000)  # 25 hours — covers timezone skew

    if count > limit:
        await r.decr(key)  # don't count the rejected request
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Daily scan limit reached",
                "limit": limit,
                "tier": tier,
                "resets": "midnight UTC",
                "upgrade_url": "/billing",
            },
        )

    return count


async def get_remaining(user: User) -> dict:
    """Return scan quota info for the current user."""
    tier = user.tier or "free"
    if tier == "free" and user.trial_ends_at and user.trial_ends_at > datetime.now(timezone.utc):
        tier = "pro"
    limits = {
        "free": settings.free_tier_scans_per_day,
        "pro": settings.pro_tier_scans_per_day,
        "enterprise": 0,
    }
    limit = limits.get(tier, settings.free_tier_scans_per_day)

    if limit == 0:
        return {"tier": tier, "used": 0, "limit": None, "remaining": None}

    r = _get_redis()
    key = _today_key(str(user.id))
    used = int(await r.get(key) or 0)

    return {
        "tier": tier,
        "used": used,
        "limit": limit,
        "remaining": max(0, limit - used),
    }
