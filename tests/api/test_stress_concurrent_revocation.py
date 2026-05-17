"""Stress tests for concurrent key revocation -- Phase 110.

STRESS-15: In-flight requests fail gracefully during key revocation.

Three scenarios proven:
  1. In-flight requests using a JWT derived from a revoked key get 401, never 500.
  2. Concurrent revocation of the same key: exactly one 200, one 409.
  3. Race window: 10 requests + 1 revocation concurrently -- every response is
     200 (got in before revocation) or 401 (blacklisted), zero 500s.

The D-11 blacklist check in decode_and_blacklist_check queries the DB on every
request, so revocation is visible as soon as the transaction commits. The race
window is the SQLite commit latency between the DELETE handler and the next
auth check.
"""
from __future__ import annotations

import asyncio
from datetime import UTC

import pytest
from httpx import AsyncClient

from aila.api.auth import generate_api_key, hash_api_key, issue_jwt_token
from aila.storage.database import session_scope
from aila.storage.db_models import ApiKeyRecord

pytestmark = pytest.mark.asyncio

PROTECTED_ENDPOINT = "/auth/keys"  # GET /auth/keys requires admin JWT


def _utc_now():
    from datetime import datetime

    return datetime.now(UTC)


def _create_admin_key(created_by: str = "test-fixture") -> ApiKeyRecord:
    """Create a fresh admin API key in the DB and return the record with _raw_key."""
    raw_key = generate_api_key()
    record = ApiKeyRecord(
        hashed_key=hash_api_key(raw_key),
        key_prefix=raw_key[:12],
        role="admin",
        label="revocation-test",
        created_by=created_by,
        created_at=_utc_now(),
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    record._raw_key = raw_key  # type: ignore[attr-defined]
    return record


# ---------------------------------------------------------------------------
# Scenario 1: In-flight requests after revocation get 401
# ---------------------------------------------------------------------------


async def test_inflight_requests_fail_with_401_after_revocation(
    async_client: AsyncClient,
    admin_key_record,
    admin_token: str,
) -> None:
    """Revoke a key, then fire requests with its JWT -- all must get 401.

    Steps:
    1. Create a second admin key and issue a JWT for it.
    2. Revoke the second key via DELETE /auth/keys/{key_id} (using the primary
       admin token).
    3. Fire 5 concurrent requests using the revoked key's JWT.
    4. All 5 must return 401, zero 500s.
    """
    # Create a second admin key to revoke
    target_key = _create_admin_key(created_by=admin_key_record.id)
    target_token, _ = issue_jwt_token(target_key)

    # Verify the target token works before revocation
    pre_resp = await async_client.get(
        PROTECTED_ENDPOINT,
        headers={"Authorization": f"Bearer {target_token}"},
    )
    assert pre_resp.status_code == 200, (
        f"Target token should work before revocation, got {pre_resp.status_code}"
    )

    # Revoke the target key using the primary admin token
    revoke_resp = await async_client.delete(
        f"/auth/keys/{target_key.id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert revoke_resp.status_code == 200, (
        f"Revocation should succeed, got {revoke_resp.status_code}: {revoke_resp.text}"
    )

    # Fire 5 concurrent requests using the revoked key's JWT
    async def _use_revoked_token() -> int:
        resp = await async_client.get(
            PROTECTED_ENDPOINT,
            headers={"Authorization": f"Bearer {target_token}"},
        )
        return resp.status_code

    status_codes = await asyncio.gather(*(_use_revoked_token() for _ in range(5)))

    # All must be 401
    assert all(
        code == 401 for code in status_codes
    ), f"Expected all 401 after revocation, got {list(status_codes)}"


# ---------------------------------------------------------------------------
# Scenario 2: Concurrent duplicate revocation -- one 200, one 409
# ---------------------------------------------------------------------------


async def test_concurrent_duplicate_revocation_returns_409(
    async_client: AsyncClient,
    admin_key_record,
    admin_token: str,
) -> None:
    """Two simultaneous DELETE /auth/keys/{key_id} on the same key.

    Exactly one succeeds (200), the other gets 409 (already revoked).
    Neither returns 500.
    """
    target_key = _create_admin_key(created_by=admin_key_record.id)

    async def _revoke() -> int:
        resp = await async_client.delete(
            f"/auth/keys/{target_key.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        return resp.status_code

    codes = await asyncio.gather(_revoke(), _revoke())
    codes_sorted = sorted(codes)

    # No 500s
    assert 500 not in codes, f"Got 500 in concurrent revocation: {list(codes)}"

    # Exactly one 200 and one 409
    assert codes_sorted == [200, 409], (
        f"Expected [200, 409] from concurrent revocation, got {codes_sorted}"
    )


# ---------------------------------------------------------------------------
# Scenario 3: Race window -- 10 requests + 1 revocation, zero 500s
# ---------------------------------------------------------------------------


async def test_race_window_no_500(
    async_client: AsyncClient,
    admin_key_record,
    admin_token: str,
) -> None:
    """Fire 10 concurrent requests using a JWT while simultaneously revoking
    the underlying key. Every response is either 200 or 401. Zero 500s.

    This proves the D-11 blacklist check and SQLite transaction isolation
    handle the race without server errors.
    """
    target_key = _create_admin_key(created_by=admin_key_record.id)
    target_token, _ = issue_jwt_token(target_key)

    async def _use_token() -> int:
        resp = await async_client.get(
            PROTECTED_ENDPOINT,
            headers={"Authorization": f"Bearer {target_token}"},
        )
        return resp.status_code

    async def _revoke() -> int:
        resp = await async_client.delete(
            f"/auth/keys/{target_key.id}",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        return resp.status_code

    # Launch 10 readers + 1 revoker concurrently
    tasks = [_use_token() for _ in range(10)]
    tasks.append(_revoke())

    results = await asyncio.gather(*tasks)

    reader_codes = list(results[:10])
    revoke_code = results[10]

    # Revocation itself must succeed
    assert revoke_code == 200, (
        f"Revocation should return 200, got {revoke_code}"
    )

    # Reader codes: each must be 200 or 401, never 500
    for i, code in enumerate(reader_codes):
        assert code in (200, 401), (
            f"Reader {i} got {code}, expected 200 or 401"
        )

    # At least verify no 500s across all results
    all_codes = list(results)
    assert 500 not in all_codes, (
        f"Got 500 in race window: {all_codes}"
    )
