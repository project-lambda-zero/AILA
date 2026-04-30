"""Data isolation and bulk atomicity tests for AILA API.

RACE-03: Session isolation — users cannot see each other's session messages.
RACE-04: Task group isolation — reader gets 404 (not 403) on admin's task.
RACE-08: Bulk findings atomicity — invalid ID in batch causes full rollback.

Seeds test data directly into DB via session_scope (platform=None in test env).
"""
from __future__ import annotations

import pytest

from aila.storage.database import session_scope
from aila.storage.db_models import SessionMessageRecord, SessionRecord

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# RACE-03: Session isolation
# ---------------------------------------------------------------------------

async def test_race_session_isolation(
    async_client,
    admin_key_record,
    reader_key_record,
    admin_token,
    reader_token,
):
    """Neither user can see the other's session messages (D-25 bilateral isolation)."""

    # 1. Seed admin session + message directly into DB
    admin_session_id: str
    def _seed_admin_session() -> str:
        with session_scope() as db:
            sess = SessionRecord(user_id=admin_key_record.id, title="Admin secret session")
            db.add(sess)
            db.commit()
            db.refresh(sess)
            msg = SessionMessageRecord(
                session_id=sess.id,
                role="assistant",
                content="admin secret data",
            )
            db.add(msg)
            db.commit()
            return sess.id

    import asyncio
    admin_session_id = await asyncio.to_thread(_seed_admin_session)

    # 2. Admin sees their own session messages (200)
    resp = await async_client.get(
        f"/sessions/{admin_session_id}/messages",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, f"Admin should see own session, got {resp.status_code}: {resp.text}"
    data = resp.json()
    assert data["total"] >= 1
    contents = [item["content"] for item in data["items"]]
    assert "admin secret data" in contents

    # 3. Reader cannot see admin's session (404, not 403)
    resp = await async_client.get(
        f"/sessions/{admin_session_id}/messages",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 404, f"Reader should get 404 on admin's session, got {resp.status_code}"

    # 4. Seed reader session via API
    resp = await async_client.post(
        "/sessions",
        json={"title": "Reader private session"},
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 201
    reader_session_id = resp.json()["session_id"]

    # 5. Admin cannot see reader's session (404)
    resp = await async_client.get(
        f"/sessions/{reader_session_id}/messages",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404, f"Admin should get 404 on reader's session, got {resp.status_code}"


# ---------------------------------------------------------------------------
# RACE-04: Task group isolation
# ---------------------------------------------------------------------------

async def test_race_task_group_isolation(
    async_client,
    admin_key_record,
    reader_key_record,
    admin_token,
    reader_token,
):
    """Reader gets 404 (not 403) on admin's task; admin sees all tasks (D-04, D-22)."""
    from aila.platform.tasks.models import TaskRecord

    # Seed a task with group_id="admin" (simulating admin-submitted task)
    import asyncio

    def _seed_task() -> str:
        with session_scope() as db:
            task = TaskRecord(
                track="platform",
                fn_path="test.dummy_fn",
                fn_module="test",
                status="queued",
                user_id=admin_key_record.id,
                group_id="admin",
            )
            db.add(task)
            db.commit()
            db.refresh(task)
            return task.id

    task_id = await asyncio.to_thread(_seed_task)

    # Reader gets 404 on admin's task (group_id isolation, NOT 403)
    resp = await async_client.get(
        f"/tasks/{task_id}",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 404, f"Reader should get 404 on admin's task, got {resp.status_code}"

    # Admin sees the task (admin bypasses group_id filter)
    resp = await async_client.get(
        f"/tasks/{task_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, f"Admin should see all tasks, got {resp.status_code}: {resp.text}"
    assert resp.json()["task_id"] == task_id


# ---------------------------------------------------------------------------
# RACE-08: Bulk findings atomicity
# ---------------------------------------------------------------------------

async def test_race_bulk_findings_atomicity(
    async_client,
    seeded_findings,
    operator_token,
):
    """PATCH /findings/bulk with invalid ID fails atomically (422, zero updates).

    Proves RACE-08: partial batches are rejected, no rows are modified, and
    a fully valid batch succeeds with the correct count.
    """
    valid_ids = [f.id for f in seeded_findings]
    assert len(valid_ids) == 3, f"Expected 3 seeded findings, got {len(valid_ids)}"

    nonexistent_id = 99999

    # 1. Mixed batch (2 valid + 1 invalid) — must fail atomically (422)
    resp = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": [valid_ids[0], valid_ids[1], nonexistent_id], "status": "remediated"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 422, (
        f"Mixed batch should return 422, got {resp.status_code}: {resp.text}"
    )

    # 2. Verify rollback: all 3 valid findings still have status="open"
    resp = await async_client.get(
        "/vulnerability/findings",
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200
    findings = resp.json()["items"]
    for finding in findings:
        if finding["id"] in valid_ids:
            assert finding["status"] == "open", (
                f"Finding {finding['id']} should still be 'open' after rollback, "
                f"got '{finding['status']}'"
            )

    # 3. All-valid batch succeeds (200, count=3)
    resp = await async_client.patch(
        "/vulnerability/findings/bulk",
        json={"finding_ids": valid_ids, "status": "remediated"},
        headers={"Authorization": f"Bearer {operator_token}"},
    )
    assert resp.status_code == 200, f"All-valid batch should succeed, got {resp.status_code}: {resp.text}"
    assert resp.json()["count"] == 3
