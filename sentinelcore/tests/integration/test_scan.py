"""Integration tests for scan routes."""
import pytest
from unittest.mock import patch, AsyncMock


@pytest.mark.asyncio
async def test_scan_file_queued(api_client, free_user_token, tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("hello world")

    with patch("api.routes.scan.run_scan") as mock_task, \
         patch("api.middleware.rate_limit.check_and_increment", new_callable=AsyncMock) as mock_rate:
        mock_task.delay = lambda *a, **kw: None
        mock_rate.return_value = 1

        res = await api_client.post(
            "/api/v1/scan/file",
            files={"file": ("test.txt", f.read_bytes(), "text/plain")},
            headers={"Authorization": f"Bearer {free_user_token}"},
        )

    assert res.status_code == 202
    data = res.json()
    assert "scan_id" in data
    assert data["status"] == "queued"
    assert data["filename"] == "test.txt"


@pytest.mark.asyncio
async def test_get_scan_not_found(api_client):
    import uuid
    fake_id = str(uuid.uuid4())
    res = await api_client.get(f"/api/v1/scan/{fake_id}")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_hash_lookup_no_vt_key(api_client):
    res = await api_client.post(
        "/api/v1/scan/hash",
        json={"hash": "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "hash" in data
    # Local DB hit for WannaCry hash
    assert data["local_db"]["found"] is True


@pytest.mark.asyncio
async def test_quota_endpoint(api_client, free_user_token):
    with patch("api.middleware.rate_limit._get_redis") as mock_redis:
        mock_r = AsyncMock()
        mock_r.get = AsyncMock(return_value="2")
        mock_redis.return_value = mock_r

        res = await api_client.get(
            "/api/v1/scan/quota/me",
            headers={"Authorization": f"Bearer {free_user_token}"},
        )
    assert res.status_code == 200
    data = res.json()
    assert data["tier"] == "free"
    assert "limit" in data
    assert "remaining" in data


@pytest.mark.asyncio
async def test_scan_unauthenticated_allowed(api_client, tmp_path):
    """Anonymous users can scan (rate limiting handles quotas separately)."""
    f = tmp_path / "anon.txt"
    f.write_text("anonymous scan test")

    with patch("api.routes.scan.run_scan") as mock_task, \
         patch("api.middleware.rate_limit.check_and_increment", new_callable=AsyncMock) as mock_rate:
        mock_task.delay = lambda *a, **kw: None
        mock_rate.return_value = 0

        res = await api_client.post(
            "/api/v1/scan/file",
            files={"file": ("anon.txt", f.read_bytes(), "text/plain")},
        )

    assert res.status_code == 202
