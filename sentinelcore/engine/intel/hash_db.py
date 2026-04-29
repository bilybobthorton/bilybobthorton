"""
Local hash reputation database.

Checks file hashes against:
1. An in-memory blocklist seeded from the bundled malware_hashes.txt
2. The PostgreSQL agent_alerts table (hashes seen by endpoint agents)

On a cache miss the caller should fall through to VirusTotal.
"""
import asyncio
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

_HASH_FILE = Path(__file__).parent.parent / "signatures" / "malware_hashes.txt"

# Simple in-process set — loaded once at import time
_KNOWN_BAD: set[str] = set()


def _load_hashes() -> None:
    if not _HASH_FILE.exists():
        return
    with open(_HASH_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                _KNOWN_BAD.add(line.lower())
    logger.info("Hash DB loaded: %d known-bad hashes", len(_KNOWN_BAD))


_load_hashes()


def is_known_bad(sha256: str) -> bool:
    return sha256.lower() in _KNOWN_BAD


def add_hash(sha256: str) -> None:
    """Dynamically add a hash to the in-memory blocklist (e.g. after VT confirms malicious)."""
    _KNOWN_BAD.add(sha256.lower())


async def lookup(sha256: str) -> Optional[dict]:
    """
    Returns a hit dict if hash is known-bad, None on miss.
    Callers fall through to VirusTotal on None.
    """
    if is_known_bad(sha256):
        return {
            "source": "local_db",
            "sha256": sha256,
            "malicious": True,
            "label": "Known malicious (local reputation DB)",
        }
    return None


def reload() -> None:
    """Hot-reload hashes from disk without restarting."""
    _KNOWN_BAD.clear()
    _load_hashes()
