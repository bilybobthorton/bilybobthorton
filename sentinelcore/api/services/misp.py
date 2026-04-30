"""
MISP (Malware Information Sharing Platform) integration — Enterprise tier.

Converts SentinelCore scan reports to MISP event format and optionally
pushes to a MISP instance via the REST API.

No extra dependencies — uses httpx (already in requirements).
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# MISP threat level IDs
_THREAT_LEVEL = {
    "malicious":  "1",  # High
    "suspicious": "2",  # Medium
    "clean":      "4",  # Undefined
    "unknown":    "4",
}

_ANALYSIS_COMPLETED = "2"
_DISTRIBUTION_ORG_ONLY = "0"  # default; enterprise users can override


def build_misp_event(report: dict, org_name: str = "SentinelCore") -> dict:
    """
    Convert a scan report dict (from _build_report_dict) into a MISP event
    structure ready to POST to /events/add.
    """
    verdict   = report["verdict"]
    file_info = report["file"]
    hashes    = report["hashes"]
    intel     = report["intelligence"]
    strings   = report.get("strings") or {}
    tl        = verdict.get("threat_level") or "unknown"

    attributes: list[dict] = []

    # ── Hashes ────────────────────────────────────────────────────────────────
    for attr_type, key in [("md5", "md5"), ("sha1", "sha1"), ("sha256", "sha256")]:
        if hashes.get(key):
            attributes.append(_attr(attr_type, "Payload delivery", hashes[key], to_ids=True))
    if hashes.get("ssdeep"):
        attributes.append(_attr("ssdeep", "Payload delivery", hashes["ssdeep"], to_ids=False))

    # ── Filename ──────────────────────────────────────────────────────────────
    attributes.append(_attr("filename", "Payload delivery", file_info["name"], to_ids=False))

    # ── Network IOCs (IPs, URLs, domains) ─────────────────────────────────────
    for ip in strings.get("ips", [])[:20]:
        attributes.append(_attr("ip-dst", "Network activity", ip, to_ids=True))

    seen_domains: set[str] = set()
    for url in strings.get("urls", [])[:20]:
        attributes.append(_attr("url", "Network activity", url, to_ids=True))
        try:
            host = urlparse(url).hostname or ""
            if host and host not in seen_domains and not host.replace(".", "").isdigit():
                seen_domains.add(host)
                attributes.append(_attr("domain", "Network activity", host, to_ids=True))
        except Exception:
            pass

    # ── Registry keys ─────────────────────────────────────────────────────────
    for reg in strings.get("registry_keys", [])[:10]:
        attributes.append(_attr("regkey", "Artifacts dropped", reg, to_ids=False))

    # ── YARA matches ──────────────────────────────────────────────────────────
    for match in report.get("yara_matches", []):
        rule_name = match.get("rule_name", "")
        if rule_name:
            attributes.append(
                _attr("yara", "Payload delivery", rule_name, to_ids=False,
                      comment=match.get("meta", {}).get("description", ""))
            )

    # ── Threat intel annotations ──────────────────────────────────────────────
    ml = intel.get("ml") or {}
    if ml:
        label = "MALICIOUS" if ml.get("malicious") else "CLEAN"
        attributes.append(_attr(
            "text", "External analysis",
            f"SentinelCore ML: {ml.get('score', 0)*100:.1f}% malice probability ({label})",
            to_ids=False,
        ))

    vt = intel.get("virustotal") or {}
    if vt.get("found") and vt.get("malicious", 0) > 0:
        attributes.append(_attr(
            "text", "External analysis",
            f"VirusTotal: {vt.get('malicious', 0)}/{vt.get('total_engines', 0)} engines — "
            f"{vt.get('popular_threat_name', '')}",
            to_ids=False,
        ))
        if vt.get("vt_link"):
            attributes.append(_attr("link", "External analysis", vt["vt_link"], to_ids=False))

    otx = intel.get("otx") or {}
    if otx.get("found") and otx.get("pulse_count", 0) > 0:
        families = ", ".join(otx.get("malware_families", [])) or "unknown"
        attributes.append(_attr(
            "text", "External analysis",
            f"AlienVault OTX: {otx.get('pulse_count', 0)} threat pulse(s) — {families}",
            to_ids=False,
        ))
        if otx.get("otx_link"):
            attributes.append(_attr("link", "External analysis", otx["otx_link"], to_ids=False))

    # ── Indicators of compromise (free-text) ──────────────────────────────────
    for indicator in verdict.get("indicators", [])[:20]:
        attributes.append(_attr("comment", "Other", indicator, to_ids=False))

    # ── TLP tags ──────────────────────────────────────────────────────────────
    tags = _tags_for_threat_level(tl)

    event = {
        "Event": {
            "uuid": str(uuid.uuid4()),
            "info": f"SentinelCore: {file_info['name']} — {tl.upper()}",
            "threat_level_id": _THREAT_LEVEL.get(tl, "4"),
            "analysis": _ANALYSIS_COMPLETED,
            "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "distribution": _DISTRIBUTION_ORG_ONLY,
            "Org": {"name": org_name},
            "Attribute": attributes,
            "Tag": tags,
        }
    }

    return event


async def push_to_misp(
    event: dict,
    misp_url: str,
    misp_key: str,
    verify_ssl: bool = True,
) -> dict:
    """
    Push a MISP event to a MISP instance.
    Returns the server response dict on success; raises on HTTP error.
    """
    base = misp_url.rstrip("/")
    headers = {
        "Authorization": misp_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    async with httpx.AsyncClient(timeout=30, verify=verify_ssl) as client:
        r = await client.post(f"{base}/events/add", json=event, headers=headers)
        r.raise_for_status()
        data = r.json()
        logger.info(
            "MISP event created: %s",
            data.get("Event", {}).get("uuid", "unknown"),
        )
        return data


# ── Helpers ───────────────────────────────────────────────────────────────────

def _attr(
    type_: str,
    category: str,
    value: str,
    *,
    to_ids: bool = False,
    comment: str = "",
) -> dict:
    a: dict = {
        "type": type_,
        "category": category,
        "value": value,
        "to_ids": to_ids,
        "distribution": "5",  # Inherit from event
    }
    if comment:
        a["comment"] = comment
    return a


def _tags_for_threat_level(tl: str) -> list[dict]:
    mapping = {
        "malicious":  [{"name": "tlp:red"}, {"name": "malware"}, {"name": "sentinel:verdict=malicious"}],
        "suspicious": [{"name": "tlp:amber"}, {"name": "sentinel:verdict=suspicious"}],
        "clean":      [{"name": "tlp:green"}, {"name": "sentinel:verdict=clean"}],
    }
    return mapping.get(tl, [{"name": "tlp:white"}])
