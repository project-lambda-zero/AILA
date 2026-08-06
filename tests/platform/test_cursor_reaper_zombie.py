"""Tests for the platform zombie-task reaper (RFC-05 Phase 6).

``reap_zombie_tasks_and_cursors`` cancels a running task whose heartbeat
was reported and then went stale. It must NOT cancel a task that never
reported a heartbeat (``heartbeat_at`` NULL): single-shot tool tasks
(run_function_ranking, deep_audit) run for many minutes at NULL while
healthily awaiting one HTTP response, and killing them mid-flight is a
false positive. These tests pin that boundary on a real task row.
"""
from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from aila.platform.contracts import utc_now
from aila.platform.tasks.cursor_reaper import reap_zombie_tasks_and_cursors
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope

_HEARTBEAT_MIN = 10


def _seed_task(
    *,
    status: str = TaskStatus.RUNNING.value,
    heartbeat_delta_min: int | None,
    started_delta_min: int,
    track: str = "vulnerability",
) -> str:
    """Seed one task row; return its id.

    ``heartbeat_delta_min`` is minutes-ago for ``heartbeat_at`` (None keeps
    it NULL). ``started_delta_min`` is minutes-ago for ``started_at``.
    """
    now = utc_now()
    task_id = f"task-{uuid4().hex[:8]}"
    heartbeat_at = (
        None if heartbeat_delta_min is None
        else now - timedelta(minutes=heartbeat_delta_min)
    )
    with session_scope() as sess:
        sess.add(TaskRecord(
            id=task_id,
            track=track,
            fn_path="aila.modules.x.tasks.run",
            fn_module="x",
            user_id="u",
            group_id="operator",
            status=status,
            started_at=now - timedelta(minutes=started_delta_min),
            heartbeat_at=heartbeat_at,
        ))
        sess.commit()
    return task_id


def _status(task_id: str) -> str:
    with session_scope() as sess:
        row = sess.get(TaskRecord, task_id)
        assert row is not None
        return row.status


@pytest.mark.asyncio
async def test_stale_beating_task_is_reaped(test_db) -> None:
    """A running task that beat and then went stale is cancelled."""
    del test_db
    task_id = _seed_task(
        heartbeat_delta_min=_HEARTBEAT_MIN + 5, started_delta_min=60,
    )
    await reap_zombie_tasks_and_cursors(
        heartbeat_min=_HEARTBEAT_MIN, batch_cap=5000,
    )
    assert _status(task_id) == TaskStatus.CANCELLED.value


@pytest.mark.asyncio
async def test_null_heartbeat_task_is_not_reaped(test_db) -> None:
    """A running task that never beat is NOT cancelled even when its
    started_at is far older than the threshold -- a long single-shot tool
    task must not be killed mid-flight."""
    del test_db
    task_id = _seed_task(
        heartbeat_delta_min=None, started_delta_min=60,
    )
    await reap_zombie_tasks_and_cursors(
        heartbeat_min=_HEARTBEAT_MIN, batch_cap=5000,
    )
    assert _status(task_id) == TaskStatus.RUNNING.value


@pytest.mark.asyncio
async def test_fresh_beating_task_is_not_reaped(test_db) -> None:
    """A running task with a recent heartbeat is left alone."""
    del test_db
    task_id = _seed_task(
        heartbeat_delta_min=1, started_delta_min=60,
    )
    await reap_zombie_tasks_and_cursors(
        heartbeat_min=_HEARTBEAT_MIN, batch_cap=5000,
    )
    assert _status(task_id) == TaskStatus.RUNNING.value
