"""Bulk & atomicity stress tests -- Phase 104.

Proves the PATCH /findings/bulk endpoint handles 100 IDs atomically:
all-or-nothing updates with explicit rollback when any ID is invalid.

Requirements covered:
  STRESS-04: Bulk update 100 IDs, #50 invalid -- entire batch rolled back
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlmodel import select

__all__ = [
    "test_bulk_update_100_valid_ids_atomic_success",
    "test_bulk_update_1_invalid_in_100_full_rollback",
    "test_bulk_rollback_error_reports_mismatch",
]

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def seeded_100_findings(test_db, seeded_system):
    """Seed 100 LatestFindingRecord rows with unique CVE/package combos.

    All rows start with status='open'. Returns the list of committed records
    with populated .id fields for use in bulk update requests.
    """
    try:
        from aila.modules.vulnerability.db_models import LatestFindingRecord
    except ImportError:
        pytest.skip("LatestFindingRecord not available in test environment")
        return []

    from aila.platform.contracts._common import utc_now
    from aila.storage.database import session_scope

    records = []
    for i in range(100):
        records.append(
            LatestFindingRecord(
                system_id=seeded_system.id,
                system_name=seeded_system.name,
                host=seeded_system.host,
                cve_id=f"CVE-2024-{i:04d}",
                package_name=f"pkg-{i:04d}",
                criticality="HIGH" if i % 2 == 0 else "MEDIUM",
                score=7.5 if i % 2 == 0 else 4.0,
                nvd_url=f"https://nvd.nist.gov/vuln/detail/CVE-2024-{i:04d}",
                last_scanned_at=utc_now(),
                created_at=utc_now(),
            )
        )

    with session_scope() as session:
        for r in records:
            session.add(r)
        session.commit()
        for r in records:
            session.refresh(r)

    return records


# ---------------------------------------------------------------------------
# STRESS-04: Bulk update 100 valid IDs -- atomic success
# ---------------------------------------------------------------------------


async def test_bulk_update_100_valid_ids_atomic_success(
    async_client: AsyncClient,
    operator_token: str,
    seeded_100_findings,
) -> None:
    """100 valid IDs all update atomically to 'remediated'.

    Verifies:
    - HTTP 200 with count=100
    - Every row in DB has status='remediated' after the update
    """
    finding_ids = [f.id for f in seeded_100_findings]
    assert len(finding_ids) == 100

    resp = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": finding_ids, "status": "remediated"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )

    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["status"] == "updated"
    assert data["count"] == 100

    # Verify all 100 rows in DB have new status
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    with session_scope() as session:
        rows = list(
            session.exec(
                select(LatestFindingRecord).where(
                    LatestFindingRecord.id.in_(finding_ids)
                )
            ).all()
        )

    assert len(rows) == 100, f"Expected 100 rows, got {len(rows)}"
    for row in rows:
        assert row.status == "remediated", (
            f"Finding {row.id} (CVE {row.cve_id}) has status '{row.status}' "
            "instead of 'remediated' -- atomic update incomplete"
        )


# ---------------------------------------------------------------------------
# STRESS-04: 1 invalid ID in 100 -- full rollback
# ---------------------------------------------------------------------------


async def test_bulk_update_1_invalid_in_100_full_rollback(
    async_client: AsyncClient,
    operator_token: str,
    seeded_100_findings,
) -> None:
    """99 valid IDs + 1 invalid ID at position #50 causes full rollback.

    Verifies:
    - HTTP 422 with 'Atomic update aborted' detail
    - Not a single one of the 99 valid rows is updated
    - All 100 seeded rows retain original status='open'
    """
    valid_ids = [f.id for f in seeded_100_findings]
    assert len(valid_ids) == 100

    # Insert invalid ID at position 50 (0-indexed), replacing that valid ID
    invalid_id = 999999
    mixed_ids = valid_ids[:50] + [invalid_id] + valid_ids[51:]
    assert len(mixed_ids) == 100

    resp = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": mixed_ids, "status": "deferred"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )

    assert resp.status_code == 422, f"Expected 422, got {resp.status_code}: {resp.text}"
    detail = resp.json()["detail"]
    assert "Atomic update aborted" in detail, (
        f"Expected 'Atomic update aborted' in detail, got: {detail}"
    )

    # Verify ZERO rows were updated -- all 100 seeded rows still have status='open'
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    from aila.storage.database import session_scope

    with session_scope() as session:
        rows = list(
            session.exec(
                select(LatestFindingRecord).where(
                    LatestFindingRecord.id.in_(valid_ids)
                )
            ).all()
        )

    assert len(rows) == 100, f"Expected 100 rows, got {len(rows)}"
    for row in rows:
        assert row.status == "open", (
            f"Finding {row.id} (CVE {row.cve_id}) has status '{row.status}' "
            "instead of 'open' -- rollback failed, partial state persisted"
        )


# ---------------------------------------------------------------------------
# STRESS-04: Error response reports expected vs matched counts
# ---------------------------------------------------------------------------


async def test_bulk_rollback_error_reports_mismatch(
    async_client: AsyncClient,
    operator_token: str,
    seeded_100_findings,
) -> None:
    """422 response detail contains expected and matched row counts.

    Operators need to know: 'I sent 100 IDs but only 99 matched.'
    The detail message must include both numbers for debugging.
    """
    valid_ids = [f.id for f in seeded_100_findings]
    invalid_id = 999999
    all_ids = valid_ids + [invalid_id]  # 101 total, 100 match, 1 does not

    resp = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": all_ids, "status": "accepted"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )

    assert resp.status_code == 422
    detail = resp.json()["detail"]

    # Detail must report expected count (101) and matched count (100)
    assert "101" in detail, f"Expected '101' (requested count) in detail: {detail}"
    assert "100" in detail, f"Expected '100' (matched count) in detail: {detail}"
    assert "Atomic update aborted" in detail
