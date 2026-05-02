from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user
from api.database import get_db
from api.config import get_settings
from api.models.scan import ScanJob, User

_settings = get_settings()

router = APIRouter(prefix="/api/v1/stats", tags=["stats"])


class DailyCount(BaseModel):
    date: str
    count: int


class StatsResponse(BaseModel):
    scans_today: int
    scans_this_week: int
    scans_this_month: int
    quota_today: int
    quota_limit: int
    threat_breakdown: dict[str, int]
    daily_counts: list[DailyCount]


@router.get("/me", response_model=StatsResponse)
async def my_stats(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=now.weekday())
    month_start = today_start.replace(day=1)
    window_start = today_start - timedelta(days=13)

    base = select(ScanJob).where(ScanJob.user_id == current_user.id)

    # Today
    res = await db.execute(
        base.where(ScanJob.created_at >= today_start).with_only_columns(func.count())
    )
    scans_today = res.scalar_one() or 0

    # This week
    res = await db.execute(
        base.where(ScanJob.created_at >= week_start).with_only_columns(func.count())
    )
    scans_week = res.scalar_one() or 0

    # This month
    res = await db.execute(
        base.where(ScanJob.created_at >= month_start).with_only_columns(func.count())
    )
    scans_month = res.scalar_one() or 0

    # Threat breakdown (completed scans only)
    res = await db.execute(
        select(ScanJob.threat_level, func.count().label("cnt"))
        .where(ScanJob.user_id == current_user.id, ScanJob.status == "complete")
        .group_by(ScanJob.threat_level)
    )
    breakdown: dict[str, int] = {"malicious": 0, "suspicious": 0, "clean": 0}
    for row in res.all():
        if row.threat_level:
            breakdown[row.threat_level] = row.cnt

    # Last 14 days daily counts
    res = await db.execute(
        select(
            func.date_trunc("day", ScanJob.created_at).label("day"),
            func.count().label("cnt"),
        )
        .where(ScanJob.user_id == current_user.id, ScanJob.created_at >= window_start)
        .group_by("day")
        .order_by("day")
    )
    rows = {r.day.date().isoformat(): r.cnt for r in res.all()}

    daily: list[DailyCount] = []
    for i in range(14):
        d = (window_start + timedelta(days=i)).date().isoformat()
        daily.append(DailyCount(date=d, count=rows.get(d, 0)))

    tier = current_user.tier or "free"
    _limits = {
        "free": _settings.free_tier_scans_per_day,
        "pro": _settings.pro_tier_scans_per_day,
        "enterprise": 999999,
    }
    quota_limit = _limits.get(tier, _settings.free_tier_scans_per_day)

    return StatsResponse(
        scans_today=scans_today,
        scans_this_week=scans_week,
        scans_this_month=scans_month,
        quota_today=scans_today,
        quota_limit=quota_limit,
        threat_breakdown=breakdown,
        daily_counts=daily,
    )
