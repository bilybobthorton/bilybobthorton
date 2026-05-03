"""
Shared pytest fixtures for SentinelCore test suite.
"""
import asyncio
import os
import uuid
from pathlib import Path
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Use SQLite for tests — no postgres required
TEST_DB_URL = "sqlite+aiosqlite:///./test_sentinel.db"

os.environ.setdefault("DATABASE_URL", TEST_DB_URL)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/15")
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/15")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/15")
os.environ.setdefault("SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("JWT_SECRET_KEY", "test-jwt-secret")
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("STRIPE_SECRET_KEY", "")
os.environ.setdefault("VIRUSTOTAL_API_KEY", "")
os.environ.setdefault("OTX_API_KEY", "")

from api.models.scan import Base, User  # noqa: E402
from api.auth.jwt import hash_password, create_access_token, generate_api_key  # noqa: E402


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def test_engine():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    factory = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def free_user(db_session: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"free_{uuid.uuid4().hex[:6]}@test.com",
        hashed_password=hash_password("testpass123"),
        tier="free",
        api_key=generate_api_key(),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest_asyncio.fixture
async def pro_user(db_session: AsyncSession) -> User:
    user = User(
        id=uuid.uuid4(),
        email=f"pro_{uuid.uuid4().hex[:6]}@test.com",
        hashed_password=hash_password("testpass123"),
        tier="pro",
        api_key=generate_api_key(),
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


@pytest.fixture
def free_user_token(free_user: User) -> str:
    return create_access_token(str(free_user.id))


@pytest.fixture
def pro_user_token(pro_user: User) -> str:
    return create_access_token(str(pro_user.id))


@pytest_asyncio.fixture
async def api_client(test_engine) -> AsyncGenerator[AsyncClient, None]:
    """Full ASGI test client with DB override."""
    from api.main import app
    from api.database import get_db
    from sqlalchemy.ext.asyncio import AsyncSession

    factory = async_sessionmaker(test_engine, expire_on_commit=False, class_=AsyncSession)

    async def override_get_db():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client

    app.dependency_overrides.clear()


@pytest.fixture
def sample_pe_bytes() -> bytes:
    """Minimal valid MZ/PE header for testing."""
    # MZ header + minimal PE stub — not executable, just parseable
    mz = b"MZ" + b"\x90\x00" + b"\x03\x00" + b"\x00" * 52 + b"\x40\x00\x00\x00"
    pe_sig = b"PE\x00\x00"
    coff = (
        b"\x4c\x01"   # Machine: i386
        b"\x01\x00"   # NumberOfSections: 1
        + b"\x00" * 12  # TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
        + b"\xe0\x00"   # SizeOfOptionalHeader
        + b"\x02\x01"   # Characteristics
    )
    return mz + pe_sig + coff + b"\x00" * 512


@pytest.fixture
def tmp_pe_file(tmp_path: Path, sample_pe_bytes: bytes) -> Path:
    p = tmp_path / "test_sample.exe"
    p.write_bytes(sample_pe_bytes)
    return p


@pytest.fixture
def tmp_text_file(tmp_path: Path) -> Path:
    p = tmp_path / "test_script.ps1"
    p.write_text("Write-Host 'hello world'\n")
    return p
