"""Input fuzzing tests -- Phase 107.

Proves every POST/PUT/PATCH endpoint handles empty bodies and unicode/emoji
strings gracefully -- returning 422 (not 500) for invalid input.

Requirements covered:
  STRESS-09: Empty input fuzzing -- every POST with {} returns 422 not 500
  STRESS-10: Unicode/emoji in all string fields -- no crashes
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

__all__ = [
    "test_empty_body_auth_token_422",
    "test_empty_body_auth_refresh_422",
    "test_empty_body_auth_keys_succeeds",
    "test_empty_body_config_put_422",
    "test_empty_body_session_create_succeeds",
    "test_empty_body_session_message_422",
    "test_empty_body_system_create_422",
    "test_empty_body_system_update_succeeds",
    "test_empty_body_analyze_422",
    "test_empty_body_task_create_422",
    "test_empty_body_findings_bulk_422",
    "test_unicode_session_title",
    "test_unicode_system_fields",
    "test_unicode_task_query",
    "test_unicode_session_message",
    "test_unicode_auth_key_label",
    "test_null_byte_rejected_or_handled",
]

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Unicode payloads
# ---------------------------------------------------------------------------

UNICODE_PAYLOADS: list[tuple[str, str]] = [
    ("cjk", "\u4e16\u754c\u4f60\u597d"),
    ("emoji", "\U0001f680\U0001f525\U0001f30d"),
    ("rtl", "\u0645\u0631\u062d\u0628\u0627"),
    ("mixed", "hello \U0001f30d \u4e16\u754c \u0645\u0631\u062d\u0628\u0627"),
    ("zalgo", "t\u0361\u0316\u0356e\u0344\u031b\u0353s\u0352\u032c\u0348t\u0361\u0315\u0324"),
    ("fullwidth", "\uff34\uff25\uff33\uff34"),
]


# ---------------------------------------------------------------------------
# Task 1: Empty body fuzzing
# ---------------------------------------------------------------------------


async def test_empty_body_auth_token_422(async_client: AsyncClient) -> None:
    """POST /auth/token with {} must return 422 -- api_key is required."""
    resp = await async_client.post("/auth/token", json={})
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_empty_body_auth_refresh_422(async_client: AsyncClient) -> None:
    """POST /auth/refresh with {} must return 422 -- refresh_token is required."""
    resp = await async_client.post("/auth/refresh", json={})
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_empty_body_auth_keys_succeeds(
    async_client: AsyncClient, admin_token: str,
) -> None:
    """POST /auth/keys with {} has defaults (role=reader, label='') -- should succeed."""
    resp = await async_client.post(
        "/auth/keys",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"


async def test_empty_body_config_put_422(
    async_client_with_registries: AsyncClient, admin_token: str,
    seeded_config_entry,
) -> None:
    """PUT /config/{ns}/{key} with {} must return 422 -- value is required."""
    resp = await async_client_with_registries.put(
        "/config/vulnerability/max_cves",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_empty_body_session_create_succeeds(
    async_client: AsyncClient, admin_token: str,
) -> None:
    """POST /sessions with {} has default title='Untitled' -- should succeed."""
    resp = await async_client.post(
        "/sessions",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 201, f"Expected 201, got {resp.status_code}: {resp.text}"


async def test_empty_body_session_message_422(
    async_client: AsyncClient, admin_token: str,
) -> None:
    """POST /sessions/{id}/messages with {} must return 422 -- content is required."""
    # Create a session first
    create_resp = await async_client.post(
        "/sessions",
        json={"title": "fuzz-test"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_resp.status_code == 201
    session_id = create_resp.json()["session_id"]

    resp = await async_client.post(
        f"/sessions/{session_id}/messages",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_empty_body_system_create_422(
    async_client: AsyncClient, operator_token: str,
) -> None:
    """POST /systems with {} must return 422 -- name and host are required."""
    resp = await async_client.post(
        "/systems",
        json={},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_empty_body_system_update_succeeds(
    async_client: AsyncClient, operator_token: str, seeded_system,
) -> None:
    """PUT /systems/{id} with {} has all-optional fields -- should succeed."""
    resp = await async_client.put(
        f"/systems/{seeded_system.id}",
        json={},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"


async def test_empty_body_analyze_422(
    async_client: AsyncClient, operator_token: str,
) -> None:
    """POST /analyze with {} must return 422 -- query_text is required."""
    resp = await async_client.post(
        "/analyze",
        json={},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_empty_body_task_create_422(
    async_client: AsyncClient, admin_token: str,
) -> None:
    """POST /task with {} must return 422 -- query_text is required."""
    resp = await async_client.post(
        "/task",
        json={},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_empty_body_findings_bulk_422(
    async_client: AsyncClient, operator_token: str,
) -> None:
    """PATCH /vulnerability/findings/bulk with {} must return 422 -- finding_ids and status required."""
    resp = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# Additional empty body edge cases
# ---------------------------------------------------------------------------


async def test_empty_body_no_content_type_auth_token(async_client: AsyncClient) -> None:
    """POST /auth/token with no body at all (no Content-Type) must return 422, not 500."""
    resp = await async_client.post("/auth/token", content=b"")
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_null_json_body_auth_token(async_client: AsyncClient) -> None:
    """POST /auth/token with JSON null body must return 422, not 500."""
    resp = await async_client.post(
        "/auth/token",
        content=b"null",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


async def test_array_body_auth_token(async_client: AsyncClient) -> None:
    """POST /auth/token with JSON array body must return 422, not 500."""
    resp = await async_client.post(
        "/auth/token",
        content=b"[]",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# Task 2: Unicode/emoji/RTL fuzzing in string fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("label,payload", UNICODE_PAYLOADS, ids=[p[0] for p in UNICODE_PAYLOADS])
async def test_unicode_auth_key_label(
    async_client: AsyncClient, admin_token: str,
    label: str, payload: str,
) -> None:
    """POST /auth/keys with unicode label -- must not 500."""
    resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": payload},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code != 500, f"Got 500 with {label} unicode: {resp.text}"
    # Should succeed -- label is a plain string with no constraints
    assert resp.status_code == 201, f"Expected 201 for unicode label, got {resp.status_code}"


@pytest.mark.parametrize("label,payload", UNICODE_PAYLOADS, ids=[p[0] for p in UNICODE_PAYLOADS])
async def test_unicode_session_title(
    async_client: AsyncClient, admin_token: str,
    label: str, payload: str,
) -> None:
    """POST /sessions with unicode title -- must not 500."""
    resp = await async_client.post(
        "/sessions",
        json={"title": payload},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code != 500, f"Got 500 with {label} unicode: {resp.text}"
    assert resp.status_code == 201, f"Expected 201 for unicode title, got {resp.status_code}"
    data = resp.json()
    assert data["title"] == payload, f"Title round-trip failed for {label}"


@pytest.mark.parametrize("label,payload", UNICODE_PAYLOADS, ids=[p[0] for p in UNICODE_PAYLOADS])
async def test_unicode_system_fields(
    async_client: AsyncClient, operator_token: str,
    label: str, payload: str,
) -> None:
    """POST /systems with unicode name/description -- must not 500."""
    resp = await async_client.post(
        "/systems",
        json={
            "name": f"{payload}-{label}",
            "host": "192.168.1.200",
            "description": payload,
        },
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code != 500, f"Got 500 with {label} unicode in system: {resp.text}"
    # Should succeed -- name and description are plain strings
    assert resp.status_code == 201, f"Expected 201 for unicode system, got {resp.status_code}"
    data = resp.json()
    assert data["description"] == payload, f"Description round-trip failed for {label}"


@pytest.mark.parametrize("label,payload", UNICODE_PAYLOADS, ids=[p[0] for p in UNICODE_PAYLOADS])
async def test_unicode_task_query(
    async_client: AsyncClient, admin_token: str,
    label: str, payload: str,
) -> None:
    """POST /task with unicode query_text -- must not 500.

    Expected: 503 (platform not initialized in test) or 422 -- never 500.
    """
    resp = await async_client.post(
        "/task",
        json={"query_text": payload},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code != 500, f"Got 500 with {label} unicode in task query: {resp.text}"


@pytest.mark.parametrize("label,payload", UNICODE_PAYLOADS, ids=[p[0] for p in UNICODE_PAYLOADS])
async def test_unicode_session_message(
    async_client: AsyncClient, admin_token: str,
    label: str, payload: str,
) -> None:
    """POST /sessions/{id}/messages with unicode content -- must not 500.

    The message endpoint requires a platform for LLM response, so we expect
    either success or a graceful error (503/422) -- never 500.
    """
    # Create session first
    create_resp = await async_client.post(
        "/sessions",
        json={"title": "unicode-fuzz"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_resp.status_code == 201
    session_id = create_resp.json()["session_id"]

    resp = await async_client.post(
        f"/sessions/{session_id}/messages",
        json={"content": payload},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code != 500, f"Got 500 with {label} unicode in message: {resp.text}"


# ---------------------------------------------------------------------------
# Null byte handling
# ---------------------------------------------------------------------------


async def test_null_byte_rejected_or_handled(
    async_client: AsyncClient, admin_token: str,
) -> None:
    """Null bytes in string fields must not cause 500.

    Null bytes may be rejected (422) or stripped -- either is acceptable.
    A 500 crash is not.
    """
    # Session title with null byte
    resp = await async_client.post(
        "/sessions",
        json={"title": "test\x00value"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code != 500, f"Got 500 with null byte in session title: {resp.text}"

    # Auth key label with null byte
    resp = await async_client.post(
        "/auth/keys",
        json={"role": "reader", "label": "key\x00label"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code != 500, f"Got 500 with null byte in key label: {resp.text}"
