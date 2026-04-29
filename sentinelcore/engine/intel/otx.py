"""
AlienVault OTX (Open Threat Exchange) integration.
Lookups: file hash, IP, domain, URL.
Free API key at: https://otx.alienvault.com/
"""
from __future__ import annotations

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

OTX_BASE = "https://otx.alienvault.com/api/v1"


class OTXClient:
    def __init__(self, api_key: str):
        self._api_key = api_key
        self._headers = {"X-OTX-API-KEY": api_key}

    async def lookup_hash(self, sha256: str) -> Optional[dict]:
        """Check a file hash against OTX pulses."""
        if not self._api_key:
            return None
        url = f"{OTX_BASE}/indicators/file/{sha256}/general"
        async with httpx.AsyncClient(timeout=10, headers=self._headers) as client:
            try:
                r = await client.get(url)
                if r.status_code == 404:
                    return {"found": False, "sha256": sha256, "source": "otx"}
                r.raise_for_status()
                data = r.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                pulses = data.get("pulse_info", {}).get("pulses", [])
                tags = list({tag for p in pulses for tag in p.get("tags", [])})[:10]
                malware_families = list({
                    p.get("malware_families", [{}])[0].get("display_name", "")
                    for p in pulses
                    if p.get("malware_families")
                })[:5]
                return {
                    "found": pulse_count > 0,
                    "source": "otx",
                    "sha256": sha256,
                    "pulse_count": pulse_count,
                    "tags": tags,
                    "malware_families": [f for f in malware_families if f],
                    "otx_link": f"https://otx.alienvault.com/indicator/file/{sha256}",
                }
            except Exception as e:
                logger.debug("OTX hash lookup failed: %s", e)
                return None

    async def lookup_ip(self, ip: str) -> Optional[dict]:
        url = f"{OTX_BASE}/indicators/IPv4/{ip}/general"
        async with httpx.AsyncClient(timeout=10, headers=self._headers) as client:
            try:
                r = await client.get(url)
                if r.status_code == 404:
                    return {"found": False, "ip": ip, "source": "otx"}
                r.raise_for_status()
                data = r.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                return {
                    "found": pulse_count > 0,
                    "source": "otx",
                    "ip": ip,
                    "pulse_count": pulse_count,
                    "country": data.get("country_name"),
                    "reputation": data.get("reputation", 0),
                    "otx_link": f"https://otx.alienvault.com/indicator/ip/{ip}",
                }
            except Exception as e:
                logger.debug("OTX IP lookup failed: %s", e)
                return None

    async def lookup_domain(self, domain: str) -> Optional[dict]:
        url = f"{OTX_BASE}/indicators/domain/{domain}/general"
        async with httpx.AsyncClient(timeout=10, headers=self._headers) as client:
            try:
                r = await client.get(url)
                if r.status_code == 404:
                    return {"found": False, "domain": domain, "source": "otx"}
                r.raise_for_status()
                data = r.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                return {
                    "found": pulse_count > 0,
                    "source": "otx",
                    "domain": domain,
                    "pulse_count": pulse_count,
                    "otx_link": f"https://otx.alienvault.com/indicator/domain/{domain}",
                }
            except Exception as e:
                logger.debug("OTX domain lookup failed: %s", e)
                return None


_client: Optional[OTXClient] = None


def _get_client() -> Optional[OTXClient]:
    global _client
    if _client is None:
        try:
            from api.config import get_settings
            key = get_settings().otx_api_key
            if key:
                _client = OTXClient(key)
        except Exception:
            pass
    return _client


async def otx_lookup_hash(sha256: str) -> Optional[dict]:
    client = _get_client()
    if not client:
        return None
    return await client.lookup_hash(sha256)


async def otx_lookup_ip(ip: str) -> Optional[dict]:
    client = _get_client()
    if not client:
        return None
    return await client.lookup_ip(ip)
