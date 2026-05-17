"""API endpoint tests for audit seal routes (Phase 120 Plan 02).

Covers: SEAL-03, SEAL-07 -- GET /audit/seals and GET /audit/seals/export
with admin auth, pagination, content gating, and date range filtering.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from httpx import AsyncClient

from aila.storage.db_models import AuditSealRecord


def _utc_now() -> datetime:
    return datetime.now(UTC)


# ---------------------------------------------------------------------------
# Fixtures: seed seal records
# ---------------------------------------------------------------------------


@pytest.fixture(scope="function")
def seal_records(test_db) -> list[AuditSealRecord]:
    """Seed 10 AuditSealRecord rows: 8 for run-seal-abc, 2 for run-other.

    Records use sequential timestamps and created_at values so ordering
    and date-range filtering are deterministic.
    """
    from aila.storage.database import session_scope

    base_time = datetime(2026, 3, 15, 12, 0, 0, tzinfo=UTC)
    records: list[AuditSealRecord] = []

    for i in range(8):
        records.append(
            AuditSealRecord(
                run_id="run-seal-abc",
                seal_hash=f"{'a' * 60}{i:04d}",
                input_hash=f"{'b' * 60}{i:04d}",
                output_hash=f"{'c' * 60}{i:04d}",
                model_id="test-model",
                task_type="scoring",
                timestamp=base_time + timedelta(minutes=i),
                classification="INTERNAL" if i % 2 == 0 else None,
                confidence="HIGH" if i % 3 == 0 else None,
                evidence_validation_pass=True if i == 0 else None,
                content_stored=(i == 2),
                prompt_content='[{"role": "user", "content": "secret prompt"}]' if i == 2 else None,
                response_content="secret response" if i == 2 else None,
                created_at=base_time + timedelta(minutes=i),
            )
        )

    # Two records for a different run
    for i in range(2):
        records.append(
            AuditSealRecord(
                run_id="run-other",
                seal_hash=f"{'d' * 60}{i:04d}",
                input_hash=f"{'e' * 60}{i:04d}",
                output_hash=f"{'f' * 60}{i:04d}",
                model_id="other-model",
                task_type="synthesis",
                timestamp=base_time + timedelta(hours=1, minutes=i),
                created_at=base_time + timedelta(hours=1, minutes=i),
            )
        )

    with session_scope() as session:
        for r in records:
            session.add(r)
        session.commit()
    return records


# ---------------------------------------------------------------------------
# GET /audit/seals tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_seals_by_run_id(
    async_client: AsyncClient, admin_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """GET /audit/seals?run_id=run-seal-abc returns 8 seals for that run."""
    resp = await async_client.get(
        "/audit/seals",
        params={"run_id": "run-seal-abc"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 8
    assert len(data["items"]) == 8
    assert all(item["run_id"] == "run-seal-abc" for item in data["items"])


@pytest.mark.asyncio
async def test_get_seals_empty_run(
    async_client: AsyncClient, admin_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """GET /audit/seals?run_id=nonexistent returns empty list."""
    resp = await async_client.get(
        "/audit/seals",
        params={"run_id": "nonexistent-run-id"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_seals_content_excluded_by_default(
    async_client: AsyncClient, admin_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """Content fields are null by default even when content_stored is true."""
    resp = await async_client.get(
        "/audit/seals",
        params={"run_id": "run-seal-abc"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # The record at index 2 has content_stored=True but content should be excluded
    for item in data["items"]:
        assert item["prompt_content"] is None
        assert item["response_content"] is None


@pytest.mark.asyncio
async def test_seals_content_included_when_requested(
    async_client: AsyncClient, admin_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """include_content=true returns prompt/response for records that have content."""
    resp = await async_client.get(
        "/audit/seals",
        params={"run_id": "run-seal-abc", "include_content": "true"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    # Record at index 2 (sorted by timestamp) has content
    content_items = [item for item in data["items"] if item["content_stored"]]
    assert len(content_items) == 1
    assert content_items[0]["prompt_content"] is not None
    assert "secret prompt" in content_items[0]["prompt_content"]
    assert content_items[0]["response_content"] == "secret response"


@pytest.mark.asyncio
async def test_seals_pagination(
    async_client: AsyncClient, admin_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """Pagination: page=2, page_size=3 returns correct slice of 8 records."""
    resp = await async_client.get(
        "/audit/seals",
        params={"run_id": "run-seal-abc", "page": 2, "page_size": 3},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 8
    assert data["page"] == 2
    assert data["page_size"] == 3
    assert len(data["items"]) == 3
    assert data["pages"] == 3  # ceil(8/3) = 3


@pytest.mark.asyncio
async def test_seals_requires_auth(
    async_client: AsyncClient, seal_records: list[AuditSealRecord]
) -> None:
    """GET /audit/seals without auth returns 401."""
    resp = await async_client.get(
        "/audit/seals",
        params={"run_id": "run-seal-abc"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_seals_requires_admin_role(
    async_client: AsyncClient, reader_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """GET /audit/seals with reader token returns 403 (admin required)."""
    resp = await async_client.get(
        "/audit/seals",
        params={"run_id": "run-seal-abc"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# GET /audit/seals/export tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_export_seals_date_range(
    async_client: AsyncClient, admin_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """Export returns only seals within the date range."""
    # Records for run-seal-abc are at base_time + 0..7 minutes
    # base_time = 2026-03-15T12:00:00Z
    since = "2026-03-15T12:00:00Z"
    until = "2026-03-15T12:03:59Z"  # Should capture first 4 records (minutes 0-3)
    resp = await async_client.get(
        "/audit/seals/export",
        params={"since": since, "until": until},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 4


@pytest.mark.asyncio
async def test_export_seals_empty_range(
    async_client: AsyncClient, admin_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """Export with date range containing no seals returns empty list."""
    resp = await async_client.get(
        "/audit/seals/export",
        params={
            "since": "2020-01-01T00:00:00Z",
            "until": "2020-01-02T00:00:00Z",
        },
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["items"] == []


@pytest.mark.asyncio
async def test_export_seals_requires_auth(
    async_client: AsyncClient, seal_records: list[AuditSealRecord]
) -> None:
    """GET /audit/seals/export without auth returns 401."""
    resp = await async_client.get(
        "/audit/seals/export",
        params={"since": "2026-01-01T00:00:00Z", "until": "2026-12-31T00:00:00Z"},
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_export_seals_requires_admin(
    async_client: AsyncClient, reader_token: str, seal_records: list[AuditSealRecord]
) -> None:
    """GET /audit/seals/export with reader token returns 403."""
    resp = await async_client.get(
        "/audit/seals/export",
        params={"since": "2026-01-01T00:00:00Z", "until": "2026-12-31T00:00:00Z"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403
