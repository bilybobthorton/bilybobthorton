from typing import Optional
import httpx
from api.config import get_settings

VT_BASE = "https://www.virustotal.com/api/v3"


class VirusTotalClient:
    def __init__(self, api_key: Optional[str] = None):
        self._api_key = api_key or get_settings().virustotal_api_key

    @property
    def _headers(self) -> dict:
        return {"x-apikey": self._api_key}

    async def lookup_hash(self, sha256: str) -> Optional[dict]:
        if not self._api_key:
            return None
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                r = await client.get(f"{VT_BASE}/files/{sha256}", headers=self._headers)
                if r.status_code == 404:
                    return {"found": False, "sha256": sha256}
                r.raise_for_status()
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "found": True,
                    "sha256": sha256,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": sum(stats.values()),
                    "popular_threat_name": data.get("popular_threat_classification", {})
                                               .get("suggested_threat_label", ""),
                    "vt_link": f"https://www.virustotal.com/gui/file/{sha256}",
                }
            except Exception:
                return None

    async def lookup_url(self, url: str) -> Optional[dict]:
        if not self._api_key:
            return None
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=10) as client:
            try:
                r = await client.get(f"{VT_BASE}/urls/{url_id}", headers=self._headers)
                if r.status_code == 404:
                    return {"found": False, "url": url}
                r.raise_for_status()
                data = r.json().get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "found": True,
                    "url": url,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "total_engines": sum(stats.values()),
                }
            except Exception:
                return None


_client = VirusTotalClient()


async def vt_lookup_hash(sha256: str) -> Optional[dict]:
    return await _client.lookup_hash(sha256)
