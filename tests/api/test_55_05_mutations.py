"""Tests for Phase 55 Plan 05: Bulk findings update, POST /task, explain endpoint.

Covers:
  API-16: PATCH /vulnerability/findings/bulk atomic status update
  TASK-01: POST /task freeform query -> 202 with task_id
  API-10: GET /vulnerability/reports/{run_id}/explain cache-first logic
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.platform.contracts._common import utc_now
from aila.storage.database import session_scope
from aila.storage.db_models import ExplainCacheRecord


@pytest.mark.asyncio
async def test_bulk_update_operator(
    async_client: AsyncClient,
    operator_token: str,
    seeded_findings,
) -> None:
    """PATCH /vulnerability/findings/bulk with operator token updates status atomically (API-16)."""
    ids = [f.id for f in seeded_findings]
    response = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": ids, "status": "remediated"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "updated"
    assert data["count"] == len(ids)


@pytest.mark.asyncio
async def test_bulk_update_reader_forbidden(
    async_client: AsyncClient,
    reader_token: str,
    seeded_findings,
) -> None:
    """PATCH /vulnerability/findings/bulk with reader token -> 403 (D-15, D-22)."""
    ids = [f.id for f in seeded_findings]
    response = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": ids, "status": "remediated"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_bulk_update_invalid_status(
    async_client: AsyncClient,
    operator_token: str,
    seeded_findings,
) -> None:
    """PATCH /vulnerability/findings/bulk with invalid status -> 422 (model_validator in schema)."""
    ids = [f.id for f in seeded_findings]
    response = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": ids, "status": "hacked"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_post_task_no_platform(
    async_client: AsyncClient, operator_token: str
) -> None:
    """POST /task with platform=None -> 503."""
    response = await async_client.post(
        "/task",
        json={"query_text": "list all critical CVEs"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_post_task_reader_forbidden(
    async_client: AsyncClient, reader_token: str
) -> None:
    """POST /task with reader token -> 403."""
    response = await async_client.post(
        "/task",
        json={"query_text": "list all critical CVEs"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_explain_cached(
    async_client: AsyncClient, operator_token: str, seeded_run
) -> None:
    """GET /vulnerability/reports/{run_id}/explain returns 200 if ExplainCacheRecord exists (D-17)."""
    # Pre-seed an ExplainCacheRecord
    with session_scope() as session:
        cache = ExplainCacheRecord(
            run_id=seeded_run.id,
            content="CVE-2023-0001 is critical because...",
            cached_at=utc_now(),
        )
        session.add(cache)
        session.commit()

    response = await async_client.get(
        f"/vulnerability/reports/{seeded_run.id}/explain",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "content" in data
    assert "CVE-2023-0001" in data["content"]


@pytest.mark.asyncio
async def test_explain_not_cached_no_platform(
    async_client: AsyncClient, operator_token: str, seeded_run
) -> None:
    """GET /vulnerability/reports/{run_id}/explain with cache miss + platform=None -> 503."""
    response = await async_client.get(
        f"/vulnerability/reports/{seeded_run.id}/explain",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 503
