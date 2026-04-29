"""Integration tests for auth routes."""
import pytest
import pytest_asyncio


@pytest.mark.asyncio
async def test_register_success(api_client):
    res = await api_client.post("/api/v1/auth/register", json={
        "email": "newuser@test.com",
        "password": "securepassword123",
    })
    assert res.status_code == 201
    data = res.json()
    assert "access_token" in data
    assert "api_key" in data
    assert data["tier"] == "free"


@pytest.mark.asyncio
async def test_register_duplicate_email(api_client):
    payload = {"email": "dup@test.com", "password": "pass123"}
    await api_client.post("/api/v1/auth/register", json=payload)
    res = await api_client.post("/api/v1/auth/register", json=payload)
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_login_success(api_client):
    email = "logintest@test.com"
    password = "mypassword123"
    await api_client.post("/api/v1/auth/register", json={"email": email, "password": password})
    res = await api_client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert res.status_code == 200
    assert "access_token" in res.json()


@pytest.mark.asyncio
async def test_login_wrong_password(api_client):
    email = "wrongpass@test.com"
    await api_client.post("/api/v1/auth/register", json={"email": email, "password": "correct"})
    res = await api_client.post("/api/v1/auth/login", json={"email": email, "password": "wrong"})
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(api_client):
    res = await api_client.post("/api/v1/auth/login", json={
        "email": "nobody@test.com", "password": "anything",
    })
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_protected_route_requires_auth(api_client):
    res = await api_client.get("/api/v1/agent/stats")
    assert res.status_code == 401


@pytest.mark.asyncio
async def test_api_key_auth(api_client):
    reg = await api_client.post("/api/v1/auth/register", json={
        "email": "apikey@test.com", "password": "testpass",
    })
    api_key = reg.json()["api_key"]
    res = await api_client.get(
        "/api/v1/agent/stats",
        headers={"X-API-Key": api_key},
    )
    assert res.status_code == 200
