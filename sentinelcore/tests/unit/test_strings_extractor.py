"""Unit tests for string extraction."""
from pathlib import Path
import pytest
from engine.static.strings_extractor import extract_strings


def test_extracts_urls(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"connecting to http://evil.example.com/payload.exe\x00")
    result = extract_strings(f)
    assert any("evil.example.com" in u for u in result.urls)


def test_extracts_ips(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"C2 server at 192.168.1.100 port 4444\x00")
    result = extract_strings(f)
    assert "192.168.1.100" in result.ips


def test_extracts_registry_keys(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\x00")
    result = extract_strings(f)
    assert len(result.registry_keys) > 0


def test_extracts_suspicious_apis(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"VirtualAlloc\x00WriteProcessMemory\x00CreateRemoteThread\x00")
    result = extract_strings(f)
    assert len(result.suspicious_apis) > 0


def test_clean_file_no_suspicious(tmp_path):
    f = tmp_path / "clean.bin"
    f.write_bytes(b"Hello world, this is a clean file with no malicious content.\x00")
    result = extract_strings(f)
    assert len(result.ips) == 0
    assert len(result.suspicious_apis) == 0


def test_empty_file(tmp_path):
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    result = extract_strings(f)
    assert result is not None
    assert result.urls == []
    assert result.ips == []
