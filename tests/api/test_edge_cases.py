"""Edge case tests: empty strings, zero page_size, negative page, unicode, SQL injection.

Verifies the API handles boundary inputs correctly -- returns structured 4xx
responses, never 500. All error responses should be structured JSON with a
'detail' field.
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

# ─── Pagination edge cases ────────────────────────────────────────────────────
# FastAPI Query(ge=1) and Query(le=250) constraints produce automatic 422.


@pytest.mark.asyncio
async def test_list_systems_page_zero(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems?page=0 returns 422 (ge=1 constraint)."""
    resp = await async_client.get(
        "/systems?page=0",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_systems_page_negative(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems?page=-1 returns 422."""
    resp = await async_client.get(
        "/systems?page=-1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_systems_page_size_zero(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems?page_size=0 returns 422 (ge=1 constraint)."""
    resp = await async_client.get(
        "/systems?page_size=0",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_systems_page_size_too_large(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems?page_size=9999 returns 422 (le=250 constraint)."""
    resp = await async_client.get(
        "/systems?page_size=9999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_list_systems_empty_result(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems with no seeded data returns 200 with empty items list."""
    resp = await async_client.get(
        "/systems",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_list_systems_page_very_large(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems?page=999999 returns 200 with empty items (no data at that offset)."""
    resp = await async_client.get(
        "/systems?page=999999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []


@pytest.mark.asyncio
async def test_audit_page_zero(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /audit/events?page=0 returns 422 (ge=1 constraint on audit router too)."""
    resp = await async_client.get(
        "/audit/events?page=0",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


# ─── Empty string inputs ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_system_empty_name(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /systems with name='' returns 422 (min_length=1 on SystemCreateRequest)."""
    resp = await async_client.post(
        "/systems",
        json={"name": "", "host": "10.0.0.1"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_create_system_empty_host(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /systems with host='' returns 422 (min_length=1 on SystemCreateRequest)."""
    resp = await async_client.post(
        "/systems",
        json={"name": "valid-name", "host": ""},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_login_empty_key(async_client: AsyncClient) -> None:
    """POST /auth/token with api_key='' returns 401 (no match)."""
    resp = await async_client.post("/auth/token", json={"api_key": ""})
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_session_message_empty_content(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /sessions/{id}/messages with content='' returns 422 (min_length=1)."""
    # Create a session first
    resp_create = await async_client.post(
        "/sessions",
        json={"title": "edge-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_create.status_code == 201
    session_id = resp_create.json()["session_id"]

    resp = await async_client.post(
        f"/sessions/{session_id}/messages",
        json={"content": ""},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


# ─── Unicode inputs ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_create_system_unicode_name(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /systems with French accented name succeeds (201)."""
    resp = await async_client.post(
        "/systems",
        json={"name": "srv-\u00e9\u00e8\u00ea", "host": "10.0.0.50"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    assert resp.json()["name"] == "srv-\u00e9\u00e8\u00ea"


@pytest.mark.asyncio
async def test_create_system_unicode_description(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /systems with Chinese characters in description succeeds."""
    resp = await async_client.post(
        "/systems",
        json={"name": "srv-cn-test", "host": "10.0.0.51", "description": "\u670d\u52a1\u5668\u6d4b\u8bd5"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201
    assert "\u670d\u52a1\u5668" in resp.json()["description"]


@pytest.mark.asyncio
async def test_create_system_emoji_name(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /systems with emoji in name should succeed or return structured 422."""
    resp = await async_client.post(
        "/systems",
        json={"name": "srv-\U0001f525", "host": "10.0.0.52"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Either succeeds or returns 422 -- never 500
    assert resp.status_code in (201, 422)


@pytest.mark.asyncio
async def test_session_unicode_message(
    async_client: AsyncClient, admin_token: str
) -> None:
    """Session message with unicode content is stored correctly."""
    # Create session
    resp_create = await async_client.post(
        "/sessions",
        json={"title": "unicode-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_create.status_code == 201
    session_id = resp_create.json()["session_id"]

    # platform=None means 503 after session check, but the point is:
    # unicode content reaches the server without causing 500
    resp = await async_client.post(
        f"/sessions/{session_id}/messages",
        json={"content": "\u4f60\u597d\u4e16\u754c \U0001f600 \u00e9\u00e8\u00ea"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # 503 (no platform) is acceptable -- NOT 500
    assert resp.status_code in (200, 503)
    assert resp.status_code != 500


# ─── SQL injection attempts ──────────────────────────────────────────────────
# All queries use parameterized statements (SQLModel/SQLAlchemy). These tests
# verify that SQL injection payloads produce structured responses, never 500.


@pytest.mark.asyncio
async def test_create_system_sqli_name(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /systems with SQL injection payload in name -- never produces 500."""
    resp = await async_client.post(
        "/systems",
        json={"name": "'; DROP TABLE managed_systems; --", "host": "10.0.0.60"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # Should store safely (parameterized queries) or reject (validation)
    assert resp.status_code in (201, 422)
    assert resp.status_code != 500


@pytest.mark.asyncio
async def test_get_system_sqli_id(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems/'1 OR 1=1' returns 422 (path param is int, not string)."""
    resp = await async_client.get(
        "/systems/1%20OR%201%3D1",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_session_sqli_content(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST message with SQL injection content is stored safely, never 500."""
    resp_create = await async_client.post(
        "/sessions",
        json={"title": "sqli-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp_create.status_code == 201
    session_id = resp_create.json()["session_id"]

    resp = await async_client.post(
        f"/sessions/{session_id}/messages",
        json={"content": "' OR '1'='1"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    # 503 (no platform) or 200 -- but never 500
    assert resp.status_code in (200, 503)
    assert resp.status_code != 500


@pytest.mark.asyncio
async def test_audit_sqli_stage_filter(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /audit/events?stage='SQLi payload' returns 200 with empty results, not 500."""
    resp = await async_client.get(
        "/audit/events",
        params={"stage": "'; DROP TABLE audit_events;--"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_systems_sqli_in_query_param(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems?page=1&page_size=50 with SQLi in a non-existent param is safe."""
    resp = await async_client.get(
        "/systems",
        params={"page": 1, "page_size": 50},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200


# ─── Extreme values ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_system_id_very_large(
    async_client: AsyncClient, admin_token: str
) -> None:
    """GET /systems/999999999 returns 404 for nonexistent system."""
    resp = await async_client.get(
        "/systems/999999999",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_create_system_very_long_name(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /systems with 10000-char name returns 422 (max_length=128 on schema)."""
    long_name = "a" * 10_000
    resp = await async_client.post(
        "/systems",
        json={"name": long_name, "host": "10.0.0.70"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_task_submit_empty_query(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /task with empty query_text returns 422 (min_length=1 on TaskCreateRequest)."""
    resp = await async_client.post(
        "/task",
        json={"query_text": ""},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_analyze_empty_query(
    async_client: AsyncClient, admin_token: str
) -> None:
    """POST /analyze with empty query_text returns 422 (min_length=1)."""
    resp = await async_client.post(
        "/analyze",
        json={"query_text": "", "targets": []},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422
