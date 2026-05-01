from __future__ import annotations
import asyncio
import dataclasses
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, update, select
from sqlalchemy.orm import Session

from api.config import get_settings
from api.models.scan import ScanJob, User
from api.services.email import send_scan_alert
from api.tasks.celery_app import celery_app
from urllib.parse import urlparse

from engine.intel import hash_db
from engine.intel.virustotal import VirusTotalClient
from engine.intel.otx import otx_lookup_hash, otx_lookup_ip, otx_lookup_domain
from engine.ml.features import extract_features
from engine.ml.model import get_model
from engine.static.analyzer import analyze_file
from engine.static.models import ThreatLevel

logger = logging.getLogger(__name__)
settings = get_settings()

_sync_url = settings.database_url.replace("+asyncpg", "+psycopg2")
_engine = create_engine(_sync_url, pool_pre_ping=True)


def _get_session() -> Session:
    return Session(_engine)


def _serialize(obj):
    if dataclasses.is_dataclass(obj):
        return dataclasses.asdict(obj)
    if isinstance(obj, bytes):
        return obj.hex()
    return str(obj)


def _run_async(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _get_user_email(user_id: str) -> str | None:
    try:
        with _get_session() as db:
            row = db.execute(select(User).where(User.id == uuid.UUID(user_id))).scalar_one_or_none()
            return row.email if row else None
    except Exception:
        return None


@celery_app.task(bind=True, name="scan_tasks.run_scan", max_retries=2)
def run_scan(self, scan_id: str, file_path: str, filename: str, user_id: str | None = None):
    path = Path(file_path)

    with _get_session() as db:
        db.execute(
            update(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)).values(status="running")
        )
        db.commit()

    try:
        result = analyze_file(path)
        indicators = list(result.indicators)
        sha256 = result.hashes.sha256

        # ── Layer 1: Local hash reputation DB ────────────────────────────────
        local_hit = _run_async(hash_db.lookup(sha256))
        if local_hit:
            result = dataclasses.replace(result, threat_level=ThreatLevel.MALICIOUS, confidence=1.0)
            indicators.insert(0, f"Known malicious hash (local DB): {sha256[:16]}...")

        # ── Layer 2: ML scoring ───────────────────────────────────────────────
        ml_result: dict = {}
        try:
            model = get_model()
            if model.trained:
                features = extract_features(result)
                ml_prob = model.predict(features)
                ml_result = {
                    "score": round(ml_prob, 4),
                    "malicious": ml_prob >= model.threshold,
                    "threshold": model.threshold,
                }
                if ml_prob >= model.threshold and result.threat_level == ThreatLevel.CLEAN:
                    result = dataclasses.replace(
                        result,
                        threat_level=ThreatLevel.SUSPICIOUS,
                        confidence=max(result.confidence, ml_prob * 0.8),
                    )
                    indicators.append(f"ML model: {ml_prob:.1%} malice probability")
                elif ml_prob >= model.threshold:
                    new_conf = min(1.0, (result.confidence + ml_prob) / 2 + 0.1)
                    result = dataclasses.replace(result, confidence=new_conf)
                    indicators.append(f"ML model confirms: {ml_prob:.1%} malice probability")
        except Exception as e:
            logger.warning("ML scoring failed: %s", e)

        # ── Layer 3: VirusTotal enrichment ────────────────────────────────────
        vt_data: dict = {}
        if settings.virustotal_api_key:
            try:
                vt_client = VirusTotalClient(settings.virustotal_api_key)
                vt_raw = _run_async(vt_client.lookup_hash(sha256))
                if vt_raw and vt_raw.get("found"):
                    vt_data = vt_raw
                    malicious = vt_data.get("malicious", 0)
                    total = vt_data.get("total_engines", 1)
                    if malicious > 0:
                        vt_score = malicious / total
                        new_confidence = max(result.confidence, min(0.5 + vt_score * 0.5, 1.0))
                        result = dataclasses.replace(
                            result,
                            threat_level=ThreatLevel.MALICIOUS if malicious >= 3 else ThreatLevel.SUSPICIOUS,
                            confidence=new_confidence,
                        )
                        label = vt_data.get("popular_threat_name", "")
                        indicators.insert(0, f"VirusTotal: {malicious}/{total} engines ({label})" if label else f"VirusTotal: {malicious}/{total} engines")
                        hash_db.add_hash(sha256)
            except Exception as e:
                logger.warning("VirusTotal lookup failed: %s", e)

        # ── Layer 4: OTX hash enrichment ──────────────────────────────────────
        otx_data: dict = {}
        if settings.otx_api_key:
            try:
                otx_raw = _run_async(otx_lookup_hash(sha256))
                if otx_raw and otx_raw.get("found"):
                    otx_data = otx_raw
                    pulse_count = otx_data.get("pulse_count", 0)
                    families = otx_data.get("malware_families", [])
                    family_str = f" ({', '.join(families)})" if families else ""
                    indicators.append(f"OTX: seen in {pulse_count} threat pulse(s){family_str}")
                    if pulse_count >= 3 and result.threat_level == ThreatLevel.CLEAN:
                        result = dataclasses.replace(
                            result,
                            threat_level=ThreatLevel.SUSPICIOUS,
                            confidence=max(result.confidence, 0.4),
                        )
            except Exception as e:
                logger.warning("OTX hash lookup failed: %s", e)

        # ── Layer 4b: OTX IP enrichment ───────────────────────────────────────
        # Check IPs extracted from the file against OTX threat intel.
        # Limit to 5 IPs to respect rate limits; skip RFC-1918 addresses.
        otx_ip_hits: list[dict] = []
        if settings.otx_api_key and result.strings:
            _private_prefixes = ("10.", "192.168.", "127.", "172.")
            candidate_ips = [
                ip for ip in result.strings.ips
                if not any(ip.startswith(p) for p in _private_prefixes)
            ][:5]
            for ip in candidate_ips:
                try:
                    ip_result = _run_async(otx_lookup_ip(ip))
                    if ip_result and ip_result.get("found"):
                        pulse_count = ip_result.get("pulse_count", 0)
                        country = ip_result.get("country", "")
                        country_str = f" ({country})" if country else ""
                        indicators.append(
                            f"OTX: IP {ip}{country_str} seen in {pulse_count} threat pulse(s)"
                        )
                        otx_ip_hits.append(ip_result)
                        # Escalate threat level if a contacted IP is known-bad
                        if pulse_count >= 2 and result.threat_level == ThreatLevel.CLEAN:
                            result = dataclasses.replace(
                                result,
                                threat_level=ThreatLevel.SUSPICIOUS,
                                confidence=max(result.confidence, 0.35),
                            )
                except Exception as e:
                    logger.warning("OTX IP lookup failed for %s: %s", ip, e)

        # ── Layer 4c: URL / domain reputation ────────────────────────────────
        # Check domains extracted from file strings against OTX.
        # Check URLs against VirusTotal URL scanner.
        # Limit to 5 of each to respect rate limits.
        network_ioc_hits: list[dict] = []
        if result.strings:
            # Deduplicate domains from extracted URLs
            seen_domains: set[str] = set()
            candidate_domains: list[str] = []
            for url in result.strings.urls[:10]:
                try:
                    host = urlparse(url).hostname or ""
                    if host and host not in seen_domains and not host.replace(".", "").isdigit():
                        seen_domains.add(host)
                        candidate_domains.append(host)
                except Exception:
                    pass
            candidate_domains = candidate_domains[:5]

            if settings.otx_api_key:
                for domain in candidate_domains:
                    try:
                        dom_result = _run_async(otx_lookup_domain(domain))
                        if dom_result and dom_result.get("found"):
                            pulse_count = dom_result.get("pulse_count", 0)
                            indicators.append(
                                f"OTX: domain {domain} seen in {pulse_count} threat pulse(s)"
                            )
                            network_ioc_hits.append(dom_result)
                            if pulse_count >= 2 and result.threat_level == ThreatLevel.CLEAN:
                                result = dataclasses.replace(
                                    result,
                                    threat_level=ThreatLevel.SUSPICIOUS,
                                    confidence=max(result.confidence, 0.45),
                                )
                    except Exception as e:
                        logger.warning("OTX domain lookup failed for %s: %s", domain, e)

            if settings.virustotal_api_key:
                vt_client_url = VirusTotalClient(settings.virustotal_api_key)
                for url in result.strings.urls[:5]:
                    try:
                        url_result = _run_async(vt_client_url.lookup_url(url))
                        if url_result and url_result.get("found"):
                            mal = url_result.get("malicious", 0)
                            sus = url_result.get("suspicious", 0)
                            if mal > 0 or sus > 0:
                                total = url_result.get("total_engines", 1)
                                indicators.insert(
                                    0, f"VirusTotal URL: {url} flagged by {mal + sus}/{total} engines"
                                )
                                network_ioc_hits.append({**url_result, "type": "url"})
                                if mal >= 2:
                                    result = dataclasses.replace(
                                        result,
                                        threat_level=ThreatLevel.MALICIOUS,
                                        confidence=max(result.confidence, 0.75),
                                    )
                                elif sus >= 2 and result.threat_level == ThreatLevel.CLEAN:
                                    result = dataclasses.replace(
                                        result,
                                        threat_level=ThreatLevel.SUSPICIOUS,
                                        confidence=max(result.confidence, 0.4),
                                    )
                    except Exception as e:
                        logger.warning("VT URL lookup failed for %s: %s", url, e)

        # ── Build final result ────────────────────────────────────────────────
        result_dict = json.loads(json.dumps(dataclasses.asdict(result), default=_serialize))
        result_dict["indicators"] = indicators
        if ml_result:
            result_dict["ml"] = ml_result
        if vt_data:
            result_dict["virustotal"] = vt_data
        if otx_data or otx_ip_hits or network_ioc_hits:
            result_dict["otx"] = {
                **(otx_data or {}),
                "ip_hits": otx_ip_hits,
                "network_iocs": network_ioc_hits,
            }
        # Surface heuristic hits as a top-level key for easy UI consumption
        if result.heuristics and result.heuristics.hits:
            result_dict["heuristics"] = {
                "score": result.heuristics.score,
                "verdict": result.heuristics.verdict,
                "hits": [
                    {
                        "name": h.name,
                        "severity": h.severity,
                        "confidence": h.confidence,
                        "evidence": h.evidence,
                        "mitre_technique": h.mitre_technique,
                        "mitre_tactic": h.mitre_tactic,
                        "description": h.description,
                    }
                    for h in result.heuristics.hits
                ],
            }

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

        # ── Email notification ────────────────────────────────────────────────
        # Send alert to the scanning user if the file is malicious or suspicious.
        if user_id and settings.resend_api_key and result.threat_level in (
            ThreatLevel.MALICIOUS, ThreatLevel.SUSPICIOUS
        ):
            user_email = _get_user_email(user_id)
            if user_email:
                _run_async(send_scan_alert(
                    to_email=user_email,
                    filename=filename,
                    scan_id=scan_id,
                    threat_level=result.threat_level.value,
                    confidence=result.confidence,
                    indicators=indicators,
                    base_url=settings.app_base_url,
                    api_key=settings.resend_api_key,
                    from_email=settings.email_from,
                ))

    except Exception as exc:
        with _get_session() as db:
            db.execute(
                update(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)).values(
                    status="failed",
                    error=str(exc),
                    completed_at=datetime.now(timezone.utc),
                )
            )
            db.commit()
        raise self.retry(exc=exc, countdown=5)
    finally:
        path.unlink(missing_ok=True)
