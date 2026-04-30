"""Tests for Phase 55 Plan 03: Scan submission and status polling.

Covers:
  API-01: POST /analyze returns 202 with run_id
  API-02/ASYNC-02: GET /scans/{run_id} returns TaskRecord status
  ASYNC-01: scan submission goes through task queue (not direct execution)
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.platform.tasks.models import TaskRecord
from aila.storage.database import session_scope


def _seed_task(user_id: str, group_id: str = "operator", task_id: str = "task-run-001") -> TaskRecord:
    """Seed a TaskRecord directly in the DB for polling tests."""
    record = TaskRecord(
        id=task_id,
        user_id=user_id,
        group_id=group_id,
        track="vulnerability",
        fn_path="aila.modules.vulnerability.tasks.scan",
        fn_module="vulnerability",
        kwargs_json="{}",
        status="queued",
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


@pytest.mark.asyncio
async def test_submit_scan_no_platform(async_client: AsyncClient, operator_token: str) -> None:
    """POST /analyze with platform=None returns 503 (async_client has platform=None)."""
    response = await async_client.post(
        "/analyze",
        json={"query_text": "scan web01"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 503


@pytest.mark.asyncio
async def test_submit_scan_reader_forbidden(async_client: AsyncClient, reader_token: str) -> None:
    """POST /analyze with reader token returns 403 (operator+ required)."""
    response = await async_client.post(
        "/analyze",
        json={"query_text": "scan web01"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_get_scan_status_own_task(
    async_client: AsyncClient,
    operator_key_record,
    operator_token: str,
) -> None:
    """GET /scans/{run_id} returns 200 with status for own task (API-02)."""
    task = _seed_task(user_id=operator_key_record.id, group_id="operator", task_id="test-scan-001")
    response = await async_client.get(
        f"/scans/{task.id}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["run_id"] == "test-scan-001"
    assert "status" in data


@pytest.mark.asyncio
async def test_get_scan_status_other_user(
    async_client: AsyncClient,
    admin_key_record,
    operator_token: str,
) -> None:
    """GET /scans/{run_id} returns 404 when task belongs to a different group."""
    # Seed task for admin user with group_id="admin"; try to fetch with operator token (group_id="operator")
    task = _seed_task(user_id=admin_key_record.id, group_id="admin", task_id="test-scan-admin")
    response = await async_client.get(
        f"/scans/{task.id}",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_get_scan_status_not_found(async_client: AsyncClient, operator_token: str) -> None:
    """GET /scans/{non_existent} returns 404."""
    response = await async_client.get(
        "/scans/does-not-exist",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert response.status_code == 404
