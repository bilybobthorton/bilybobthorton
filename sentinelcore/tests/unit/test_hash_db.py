"""Unit tests for local hash reputation DB."""
import pytest
import pytest_asyncio
from engine.intel import hash_db


KNOWN_BAD = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"  # WannaCry
CLEAN_HASH = "a" * 64


def test_is_known_bad_hit():
    assert hash_db.is_known_bad(KNOWN_BAD) is True


def test_is_known_bad_miss():
    assert hash_db.is_known_bad(CLEAN_HASH) is False


def test_is_known_bad_case_insensitive():
    assert hash_db.is_known_bad(KNOWN_BAD.upper()) is True


@pytest.mark.asyncio
async def test_lookup_returns_hit():
    result = await hash_db.lookup(KNOWN_BAD)
    assert result is not None
    assert result["malicious"] is True
    assert result["source"] == "local_db"


@pytest.mark.asyncio
async def test_lookup_returns_none_on_miss():
    result = await hash_db.lookup(CLEAN_HASH)
    assert result is None


def test_add_hash_persists():
    new_hash = "b" * 64
    assert hash_db.is_known_bad(new_hash) is False
    hash_db.add_hash(new_hash)
    assert hash_db.is_known_bad(new_hash) is True
    # Cleanup
    hash_db._KNOWN_BAD.discard(new_hash)
