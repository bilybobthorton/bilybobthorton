"""Unit tests for file hashing."""
from pathlib import Path
import pytest
from engine.static.hasher import compute_hashes


def test_compute_hashes_returns_all_fields(tmp_path):
    f = tmp_path / "sample.bin"
    f.write_bytes(b"Hello, SentinelCore!")
    h = compute_hashes(f)
    assert len(h.md5) == 32
    assert len(h.sha256) == 64
    assert h.sha1 is not None


def test_compute_hashes_known_md5(tmp_path):
    # MD5 of empty string is d41d8cd98f00b204e9800998ecf8427e
    f = tmp_path / "empty.bin"
    f.write_bytes(b"")
    h = compute_hashes(f)
    assert h.md5 == "d41d8cd98f00b204e9800998ecf8427e"


def test_compute_hashes_known_sha256(tmp_path):
    # SHA256 of b"abc"
    f = tmp_path / "abc.bin"
    f.write_bytes(b"abc")
    h = compute_hashes(f)
    assert h.sha256 == "ba7816bf8f01cfea414140de5dae2ec73b00361bbef0469f492c715faca8ea91"  # sha256("abc") but without the trailing char — known value


def test_compute_hashes_deterministic(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"deterministic test content 12345")
    h1 = compute_hashes(f)
    h2 = compute_hashes(f)
    assert h1.md5 == h2.md5
    assert h1.sha256 == h2.sha256


def test_compute_hashes_different_files_differ(tmp_path):
    f1 = tmp_path / "a.bin"
    f2 = tmp_path / "b.bin"
    f1.write_bytes(b"file one content")
    f2.write_bytes(b"file two content")
    h1 = compute_hashes(f1)
    h2 = compute_hashes(f2)
    assert h1.sha256 != h2.sha256
    assert h1.md5 != h2.md5


def test_compute_hashes_large_file(tmp_path):
    f = tmp_path / "large.bin"
    f.write_bytes(b"\x00" * (2 * 1024 * 1024))  # 2 MB
    h = compute_hashes(f)
    assert h.sha256 is not None
    assert len(h.sha256) == 64
