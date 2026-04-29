import tempfile
from pathlib import Path

import pytest

from engine.static.hasher import compute_hashes
from engine.static.strings_extractor import extract_strings
from engine.static.models import ThreatLevel


def _write_temp(content: bytes) -> Path:
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(content)
    f.close()
    return Path(f.name)


def test_hashes_are_consistent():
    data = b"SentinelCore test payload"
    path = _write_temp(data)
    result = compute_hashes(path)
    result2 = compute_hashes(path)
    assert result.sha256 == result2.sha256
    assert len(result.sha256) == 64
    assert len(result.md5) == 32
    path.unlink()


def test_strings_extracts_urls():
    data = b"GET http://evil.example.com/malware.exe HTTP/1.1\x00"
    path = _write_temp(data)
    result = extract_strings(path)
    assert any("evil.example.com" in url for url in result.urls)
    path.unlink()


def test_strings_extracts_ips():
    data = b"Connecting to 192.168.1.1 for C2\x00"
    path = _write_temp(data)
    result = extract_strings(path)
    assert "192.168.1.1" in result.ips
    path.unlink()


def test_strings_flags_suspicious_api():
    data = b"VirtualAlloc WriteProcessMemory CreateRemoteThread\x00"
    path = _write_temp(data)
    result = extract_strings(path)
    suspicious_lower = [s.lower() for s in result.suspicious_apis]
    assert "virtualalloc" in suspicious_lower
    path.unlink()
