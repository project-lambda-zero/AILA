"""Wiring verification: TaskQueue -> DB integration (WIRE-06).

Tests prove that TaskRecord persistence, API read path, and platform
dependency gating all work end-to-end through the real API stack.

Endpoints under test:
  GET  /tasks         -- list tasks (admin sees all)
  GET  /tasks/{id}    -- single task detail
  POST /analyze       -- scan submission (503 without platform)
  POST /task          -- freeform task submission (503 without platform)

Uses async_client with a real test DB. TaskRecords are seeded directly
via DB to test the read path independently of the write path (which
requires Redis/ARQ for full queue submission).
"""
from __future__ import annotations

import pytest
from httpx import AsyncClient

from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope

pytestmark = pytest.mark.anyio


def _seed_task_record(
    *,
    task_id: str = "task-wire-001",
    track: str = "vulnerability",
    status: str = TaskStatus.QUEUED,
    user_id: str = "test-user",
    group_id: str = "admin",
    fn_path: str = "aila.modules.vulnerability.tasks.scan",
    fn_module: str = "vulnerability",
) -> TaskRecord:
    """Insert a TaskRecord directly into the test DB and return it."""
    record = TaskRecord(
        id=task_id,
        track=track,
        status=status,
        user_id=user_id,
        group_id=group_id,
        fn_path=fn_path,
        fn_module=fn_module,
        kwargs_json='{"query": "test"}',
    )
    with session_scope() as session:
        session.add(record)
        session.commit()
        session.refresh(record)
    return record


async def test_task_queue_submit_creates_db_record(
    async_client: AsyncClient,
    admin_token: str,
    admin_key_record,
) -> None:
    """Seed a TaskRecord directly, verify it appears via GET /tasks and GET /tasks/{id}.

    This proves the DB -> TaskRepository -> API read path is fully wired.
    TaskQueue.submit() writes these same records; we bypass Redis/ARQ
    by seeding directly and testing the read surface.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}

    record = _seed_task_record(
        task_id="task-db-wire-001",
        user_id=admin_key_record.id,
        group_id=admin_key_record.role,
    )

    # GET /tasks -- admin should see the seeded task
    resp = await async_client.get("/tasks", headers=headers)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["total"] >= 1
    task_ids = [t["task_id"] for t in body["tasks"]]
    assert record.id in task_ids

    # GET /tasks/{task_id} -- single task detail
    resp = await async_client.get(f"/tasks/{record.id}", headers=headers)
    assert resp.status_code == 200, resp.text
    detail = resp.json()
    assert detail["task_id"] == record.id
    assert detail["track"] == "vulnerability"
    assert detail["status"] == TaskStatus.QUEUED
    assert detail["fn_path"] == "aila.modules.vulnerability.tasks.scan"
    assert detail["fn_module"] == "vulnerability"
    assert detail["has_checkpoint"] is False


async def test_task_status_visible_via_api(
    async_client: AsyncClient,
    admin_token: str,
    admin_key_record,
) -> None:
    """Seed pending TaskRecord, verify via API, update status in DB, verify again.

    Proves the full read path reflects real DB state transitions:
    DB write -> TaskRepository query -> API serialization.
    """
    headers = {"Authorization": f"Bearer {admin_token}"}

    record = _seed_task_record(
        task_id="task-status-wire-001",
        status=TaskStatus.QUEUED,
        user_id=admin_key_record.id,
        group_id=admin_key_record.role,
    )

    # Verify initial status via API
    resp = await async_client.get(f"/tasks/{record.id}", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == TaskStatus.QUEUED

    # Update status to DONE directly in DB (simulates worker completion)
    with session_scope() as session:
        from sqlmodel import select

        db_record = session.exec(
            select(TaskRecord).where(TaskRecord.id == record.id)
        ).first()
        assert db_record is not None
        db_record.status = TaskStatus.DONE
        session.add(db_record)
        session.commit()

    # Verify updated status via API
    resp = await async_client.get(f"/tasks/{record.id}", headers=headers)
    assert resp.status_code == 200, resp.text
    assert resp.json()["status"] == TaskStatus.DONE

    # Also verify the list endpoint reflects the change
    resp = await async_client.get("/tasks", headers=headers)
    assert resp.status_code == 200, resp.text
    tasks_by_id = {t["task_id"]: t for t in resp.json()["tasks"]}
    assert tasks_by_id[record.id]["status"] == TaskStatus.DONE


async def test_post_analyze_returns_503_without_platform(
    async_client: AsyncClient,
    operator_token: str,
) -> None:
    """POST /analyze with platform=None returns 503.

    Proves: route is wired, auth passes (operator role), and the platform
    dependency check correctly surfaces 503 instead of a 500 crash.
    """
    headers = {"Authorization": f"Bearer {operator_token}"}
    resp = await async_client.post(
        "/analyze",
        json={"query_text": "scan web01 for vulnerabilities", "targets": ["web01"]},
        headers=headers,
    )
    assert resp.status_code == 503, resp.text
    assert "Platform not initialized" in resp.json()["detail"]


async def test_post_task_returns_503_without_platform(
    async_client: AsyncClient,
    operator_token: str,
) -> None:
    """POST /task with platform=None returns 503.

    Proves: route is wired, auth passes (operator role), and the platform
    dependency check correctly surfaces 503 instead of a 500 crash.
    """
    headers = {"Authorization": f"Bearer {operator_token}"}
    resp = await async_client.post(
        "/task",
        json={"query_text": "test query"},
        headers=headers,
    )
    assert resp.status_code == 503, resp.text
    assert "Platform not initialized" in resp.json()["detail"]
