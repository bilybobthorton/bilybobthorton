from __future__ import annotations

import time
from typing import Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user
from api.database import get_db
from api.models.scan import User

router = APIRouter(prefix="/api/v1/vuln", tags=["vulnerabilities"])

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Free tier: 5 req / 30s. With API key: 50 req / 30s.
# We batch calls and respect the limit.
NVD_DELAY = 6.5  # seconds between requests (safe for unauthenticated)


class SoftwareItem(BaseModel):
    name: str
    version: Optional[str] = None
    publisher: Optional[str] = None


class CveItem(BaseModel):
    cve_id: str
    description: str
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / NONE
    cvss_score: float
    published: str
    references: list[str]


class VulnResult(BaseModel):
    name: str
    version: Optional[str]
    publisher: Optional[str]
    cves: list[CveItem]
    highest_severity: str
    cve_count: int


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"


def _highest(severities: list[str]) -> str:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
    for s in order:
        if s in severities:
            return s
    return "NONE"


async def _query_nvd(keyword: str, version: str | None) -> list[CveItem]:
    """Query NVD CVE API for a software keyword and optional version."""
    params: dict = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
        "startIndex": 0,
    }

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(NVD_API, params=params)
            if r.status_code != 200:
                return []
            data = r.json()
    except Exception:
        return []

    cves: list[CveItem] = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description (English preferred)
        descs = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descs if d.get("lang") == "en"),
            descs[0]["value"] if descs else "",
        )

        # CVSS score — try v3.1, v3.0, v2 in that order
        metrics = cve.get("metrics", {})
        score = 0.0
        severity = "NONE"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                score = float(cvss_data.get("baseScore", 0.0))
                severity = cvss_data.get("baseSeverity") or _severity_from_score(score)
                break

        # References
        refs = [r["url"] for r in cve.get("references", [])[:3] if r.get("url")]

        published = cve.get("published", "")[:10]

        # Version filter — skip CVE if version range clearly doesn't match
        # (basic check — NVD CPE matching is complex, this is best-effort)
        if version and _version_clearly_patched(cve, version):
            continue

        cves.append(CveItem(
            cve_id=cve_id,
            description=desc[:400],
            severity=severity.upper() if severity else _severity_from_score(score),
            cvss_score=score,
            published=published,
            references=refs,
        ))

    # Sort by score descending
    return sorted(cves, key=lambda c: c.cvss_score, reverse=True)


def _version_clearly_patched(cve: dict, installed_version: str) -> bool:
    """
    Returns True if CPE configuration data clearly shows the installed
    version is NOT in the vulnerable range. Conservative — returns False
    (keep the CVE) when uncertain.
    """
    try:
        from packaging.version import Version, InvalidVersion
        iv = Version(installed_version)
    except Exception:
        return False

    configs = cve.get("configurations", [])
    for cfg in configs:
        for node in cfg.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable", True):
                    continue
                vend = match.get("versionEndExcluding")
                veni = match.get("versionEndIncluding")
                try:
                    if vend and iv >= Version(vend):
                        return True
                    if veni and iv > Version(veni):
                        return True
                except Exception:
                    pass
    return False


@router.post("/scan", response_model=list[VulnResult])
async def scan_vulnerabilities(
    software: list[SoftwareItem],
    current_user: User = Depends(get_current_user),
    _db: AsyncSession = Depends(get_db),
):
    """
    Check a list of installed software against the NVD CVE database.
    Accepts up to 30 software items per request.
    """
    if len(software) > 30:
        raise HTTPException(status_code=400, detail="Maximum 30 software items per request")

    results: list[VulnResult] = []

    for i, item in enumerate(software):
        if i > 0:
            # Rate-limit NVD requests
            await _async_sleep(NVD_DELAY)

        cves = await _query_nvd(item.name, item.version)

        # Only include software that actually has CVEs
        if cves:
            severities = [c.severity for c in cves]
            results.append(VulnResult(
                name=item.name,
                version=item.version,
                publisher=item.publisher,
                cves=cves[:10],  # top 10 by score
                highest_severity=_highest(severities),
                cve_count=len(cves),
            ))

    # Sort by highest severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}
    results.sort(key=lambda r: severity_order.get(r.highest_severity, 4))
    return results


async def _async_sleep(seconds: float):
    import asyncio
    await asyncio.sleep(seconds)
