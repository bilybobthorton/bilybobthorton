"""Integration tests for YARA rule management."""
import pytest


VALID_RULE = """
rule Test_Detection {
    meta:
        description = "Test rule"
        severity = "high"
    strings:
        $s1 = "malicious_string" nocase
    condition:
        $s1
}
"""

INVALID_RULE = "rule Broken { this is not valid yara syntax }"


@pytest.mark.asyncio
async def test_validate_valid_rule(api_client, free_user_token):
    res = await api_client.post(
        "/api/v1/yara/validate",
        json={"rule_text": VALID_RULE},
        headers={"Authorization": f"Bearer {free_user_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is True
    assert data["rule_count"] == 1


@pytest.mark.asyncio
async def test_validate_invalid_rule(api_client, free_user_token):
    res = await api_client.post(
        "/api/v1/yara/validate",
        json={"rule_text": INVALID_RULE},
        headers={"Authorization": f"Bearer {free_user_token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["valid"] is False
    assert "error" in data


@pytest.mark.asyncio
async def test_create_rule_requires_pro(api_client, free_user_token):
    res = await api_client.post(
        "/api/v1/yara/rules",
        json={"name": "My_Rule", "rule_text": VALID_RULE},
        headers={"Authorization": f"Bearer {free_user_token}"},
    )
    assert res.status_code == 403


@pytest.mark.asyncio
async def test_create_rule_pro_user(api_client, pro_user_token):
    res = await api_client.post(
        "/api/v1/yara/rules",
        json={"name": "Pro_Test_Rule", "rule_text": VALID_RULE, "description": "Test"},
        headers={"Authorization": f"Bearer {pro_user_token}"},
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Pro_Test_Rule"
    assert data["is_builtin"] is False
    assert data["enabled"] is True


@pytest.mark.asyncio
async def test_create_rule_invalid_yara_rejected(api_client, pro_user_token):
    res = await api_client.post(
        "/api/v1/yara/rules",
        json={"name": "Bad_Rule", "rule_text": INVALID_RULE},
        headers={"Authorization": f"Bearer {pro_user_token}"},
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_list_rules(api_client, free_user_token):
    res = await api_client.get(
        "/api/v1/yara/rules",
        headers={"Authorization": f"Bearer {free_user_token}"},
    )
    assert res.status_code == 200
    assert isinstance(res.json(), list)


@pytest.mark.asyncio
async def test_delete_rule(api_client, pro_user_token):
    # Create then delete
    create = await api_client.post(
        "/api/v1/yara/rules",
        json={"name": "Delete_Me_Rule", "rule_text": VALID_RULE},
        headers={"Authorization": f"Bearer {pro_user_token}"},
    )
    assert create.status_code == 201
    rule_id = create.json()["id"]

    delete = await api_client.delete(
        f"/api/v1/yara/rules/{rule_id}",
        headers={"Authorization": f"Bearer {pro_user_token}"},
    )
    assert delete.status_code == 204
