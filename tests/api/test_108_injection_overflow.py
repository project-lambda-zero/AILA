"""SQL injection and oversized payload tests -- Phase 108.

Proves parameterized queries prevent SQL injection in all filter endpoints
and that oversized payloads (>10MB) are rejected with 413 before processing.

Requirements covered:
  STRESS-11: SQL injection in filter params -- parameterized queries prevent execution
  STRESS-12: Oversized payload -- rejected with 413/422, not OOM
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

__all__ = [
    "test_sql_injection_audit_events",
    "test_sql_injection_vulnerability_findings",
    "test_sql_injection_vulnerability_facets",
    "test_sql_injection_no_table_damage",
    "test_oversized_payload_auth_token_413",
    "test_oversized_payload_systems_413",
    "test_normal_payload_still_works",
    "test_oversized_413_envelope",
]

pytestmark = pytest.mark.asyncio

# ---------------------------------------------------------------------------
# SQL injection payloads -- classic attack strings
# ---------------------------------------------------------------------------

SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE audit_events; --",
    "' UNION SELECT * FROM api_keys --",
    "1; DELETE FROM managed_systems",
    "' OR 1=1 --",
    "1' OR '1'='1' /*",
    "admin'--",
    "' AND 1=0 UNION SELECT hashed_key FROM apikeyrecord --",
]


# ---------------------------------------------------------------------------
# STRESS-11: SQL injection in audit filter params
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS, ids=lambda p: p[:30])
async def test_sql_injection_audit_events(
    async_client: AsyncClient,
    admin_token: str,
    seeded_audit_events,
    payload: str,
) -> None:
    """SQL injection in audit filter params returns 200 with empty results."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Test each filter param independently
    for param in ("stage", "action", "status", "user_id", "run_id"):
        resp = await async_client.get(
            "/audit/events",
            params={param: payload},
            headers=headers,
        )
        assert resp.status_code == 200, (
            f"Injection in {param}={payload!r} returned {resp.status_code}, expected 200"
        )
        data = resp.json()
        # Injection payloads should not match any real data
        assert data["items"] == [], (
            f"Injection in {param}={payload!r} returned non-empty results"
        )


# ---------------------------------------------------------------------------
# STRESS-11: SQL injection in vulnerability findings filter params
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS, ids=lambda p: p[:30])
async def test_sql_injection_vulnerability_findings(
    async_client: AsyncClient,
    admin_token: str,
    seeded_findings,
    payload: str,
) -> None:
    """SQL injection in findings filter params returns 200 with empty results."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    for param in ("severity", "host", "package"):
        resp = await async_client.get(
            "/vulnerability/findings",
            params={param: payload},
            headers=headers,
        )
        assert resp.status_code == 200, (
            f"Injection in {param}={payload!r} returned {resp.status_code}, expected 200"
        )
        data = resp.json()
        assert data["items"] == [], (
            f"Injection in {param}={payload!r} returned non-empty results"
        )


# ---------------------------------------------------------------------------
# STRESS-11: SQL injection in vulnerability facets filter params
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("payload", SQL_INJECTION_PAYLOADS, ids=lambda p: p[:30])
async def test_sql_injection_vulnerability_facets(
    async_client: AsyncClient,
    admin_token: str,
    seeded_findings,
    payload: str,
) -> None:
    """SQL injection in facets filter params returns 200 with empty facets."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    for param in ("severity", "host", "package"):
        resp = await async_client.get(
            "/vulnerability/findings/facets",
            params={param: payload},
            headers=headers,
        )
        assert resp.status_code == 200, (
            f"Injection in {param}={payload!r} returned {resp.status_code}, expected 200"
        )


# ---------------------------------------------------------------------------
# STRESS-11: Verify injection did not damage tables
# ---------------------------------------------------------------------------


async def test_sql_injection_no_table_damage(
    async_client: AsyncClient,
    admin_token: str,
    seeded_audit_events,
    seeded_findings,
) -> None:
    """After all injection attempts, verify tables still have their seeded data."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Run worst-case injection payloads across all endpoints first
    for payload in SQL_INJECTION_PAYLOADS:
        await async_client.get(
            "/audit/events",
            params={"stage": payload, "action": payload},
            headers=headers,
        )
        await async_client.get(
            "/vulnerability/findings",
            params={"severity": payload, "host": payload},
            headers=headers,
        )

    # Verify audit events still exist (seeded_audit_events has 3 rows)
    resp = await async_client.get("/audit/events", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 3, "Audit events table was damaged by injection"

    # Verify findings still exist (seeded_findings has 3 rows)
    resp = await async_client.get("/vulnerability/findings", headers=headers)
    assert resp.status_code == 200
    assert resp.json()["total"] == 3, "Findings table was damaged by injection"


# ---------------------------------------------------------------------------
# STRESS-12: Oversized payload rejection
# ---------------------------------------------------------------------------

_OVERSIZED_BODY = b"x" * (10 * 1024 * 1024 + 1)  # 10MB + 1 byte


async def test_oversized_payload_auth_token_413(
    async_client: AsyncClient,
) -> None:
    """POST /auth/token with >10MB body returns 413."""
    resp = await async_client.post(
        "/auth/token",
        content=_OVERSIZED_BODY,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413, f"Expected 413, got {resp.status_code}"


async def test_oversized_payload_systems_413(
    async_client: AsyncClient,
    admin_token: str,
) -> None:
    """POST /systems with >10MB body returns 413."""
    resp = await async_client.post(
        "/systems",
        content=_OVERSIZED_BODY,
        headers={
            "Authorization": f"Bearer {admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert resp.status_code == 413, f"Expected 413, got {resp.status_code}"


async def test_normal_payload_still_works(
    async_client: AsyncClient,
) -> None:
    """Normal-sized POST body is not rejected by size middleware."""
    # POST /auth/token with a small body -- will fail auth (422) but NOT 413
    resp = await async_client.post(
        "/auth/token",
        json={"api_key": "test-key-that-does-not-exist"},
    )
    assert resp.status_code != 413, "Normal payload was incorrectly rejected as oversized"
    # 401 or 422 are both acceptable -- just not 413 or 500
    assert resp.status_code in (401, 422), f"Unexpected status {resp.status_code}"


async def test_oversized_413_envelope(
    async_client: AsyncClient,
) -> None:
    """413 response uses ErrorResponse envelope with detail/code/errors keys."""
    resp = await async_client.post(
        "/auth/token",
        content=_OVERSIZED_BODY,
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 413
    data = resp.json()
    assert "detail" in data, "413 response missing 'detail' key"
    assert "code" in data, "413 response missing 'code' key"
    assert "errors" in data, "413 response missing 'errors' key"
