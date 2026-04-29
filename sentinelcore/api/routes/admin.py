"""Platform-wide stats for internal admin dashboard."""
from fastapi import APIRouter, Depends
from sqlalchemy import text

from api.auth.dependencies import get_current_user
from api.database import get_session
from api.models.scan import User

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


def _require_admin(user: User = Depends(get_current_user)) -> User:
    if user.tier != "enterprise":
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Admin access requires Enterprise tier")
    return user


@router.get("/stats")
async def platform_stats(current_user: User = Depends(_require_admin)):
    async with get_session() as session:
        scans = await session.execute(
            text("""
                SELECT
                    COUNT(*)                                               AS total_scans,
                    COUNT(*) FILTER (WHERE status = 'complete')           AS completed,
                    COUNT(*) FILTER (WHERE status = 'failed')             AS failed,
                    COUNT(*) FILTER (WHERE threat_level = 'malicious')    AS malicious,
                    COUNT(*) FILTER (WHERE threat_level = 'suspicious')   AS suspicious,
                    COUNT(*) FILTER (WHERE threat_level = 'clean')        AS clean,
                    COUNT(DISTINCT sha256)                                 AS unique_hashes
                FROM scan_jobs
            """)
        )
        scan_row = dict(scans.mappings().one())

        users = await session.execute(
            text("""
                SELECT
                    COUNT(*)                                       AS total_users,
                    COUNT(*) FILTER (WHERE tier = 'free')          AS free_users,
                    COUNT(*) FILTER (WHERE tier = 'pro')           AS pro_users,
                    COUNT(*) FILTER (WHERE tier = 'enterprise')    AS enterprise_users
                FROM users
            """)
        )
        user_row = dict(users.mappings().one())

        alerts = await session.execute(
            text("""
                SELECT
                    COUNT(*)                                          AS total_alerts,
                    COUNT(*) FILTER (WHERE severity = 'critical')    AS critical,
                    COUNT(*) FILTER (WHERE severity = 'high')        AS high,
                    COUNT(DISTINCT hostname)                          AS monitored_hosts
                FROM agent_alerts
            """)
        )
        alert_row = dict(alerts.mappings().one())

    return {
        "scans": scan_row,
        "users": user_row,
        "agent_alerts": alert_row,
    }
