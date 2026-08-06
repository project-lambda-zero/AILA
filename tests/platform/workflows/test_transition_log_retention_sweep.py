"""DB-backed tests for the workflow transition-log retention sweep.

Mirrors the shape of ``tests/platform/llm/test_drift_retention_sweep.py``:
seed a mix of old and recent WorkflowStateTransition rows through the real
Postgres ``test_db`` fixture, run ``purge_old_transitions``, and assert the
DB state matches the sweep's returned count.

The table has a FK on ``workflowrunrecord.id`` so each test first creates a
parent ``WorkflowRunRecord`` before inserting transition rows.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import select

from aila.platform.workflows.log import (
    _DEFAULT_RETENTION_DAYS,
    purge_old_transitions,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateTransition


pytestmark = pytest.mark.asyncio


async def _seed_run(run_id: str) -> None:
    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(
                id=run_id,
                query_text="retention-sweep test",
                action_id="test",
                module_id="test",
            )
        )
        await session.commit()


async def _seed_transitions(
    rows: list[tuple[str, int, datetime]],
) -> None:
    """Insert transitions keyed by (run_id, seq, happened_at)."""
    async with async_session_scope() as session:
        for run_id, seq, happened_at in rows:
            session.add(
                WorkflowStateTransition(
                    run_id=run_id,
                    seq=seq,
                    from_state="start",
                    to_state="start" if seq == 0 else "__succeeded__",
                    event="entered" if seq == 0 else "exited:ok",
                    happened_at=happened_at,
                )
            )
        await session.commit()


async def _load_all_transition_keys() -> set[tuple[str, int]]:
    async with async_session_scope() as session:
        rows = (await session.exec(select(WorkflowStateTransition))).all()
        return {(row.run_id, row.seq) for row in rows}


@pytest.mark.usefixtures("test_db")
async def test_purge_deletes_only_rows_older_than_cutoff() -> None:
    """Rows older than the default retention window are dropped; recent
    rows are kept.
    """
    now = datetime.now(UTC)
    old = now - timedelta(days=_DEFAULT_RETENTION_DAYS + 5)
    recent = now - timedelta(days=1)

    await _seed_run("run-alpha")
    await _seed_run("run-bravo")
    await _seed_transitions([
        ("run-alpha", 0, old),
        ("run-alpha", 1, old),
        ("run-bravo", 0, recent),
        ("run-bravo", 1, recent),
    ])

    deleted = await purge_old_transitions()

    assert deleted == 2
    assert await _load_all_transition_keys() == {("run-bravo", 0), ("run-bravo", 1)}


@pytest.mark.usefixtures("test_db")
async def test_purge_return_matches_deleted_count() -> None:
    """Return value equals the exact number of rows removed."""
    now = datetime.now(UTC)
    old_ts = now - timedelta(days=_DEFAULT_RETENTION_DAYS + 30)

    await _seed_run("run-charlie")
    await _seed_transitions([
        ("run-charlie", seq, old_ts) for seq in range(7)
    ])

    deleted = await purge_old_transitions()

    assert deleted == 7
    assert await _load_all_transition_keys() == set()


@pytest.mark.usefixtures("test_db")
async def test_purge_idempotent_when_no_matches() -> None:
    """Two consecutive calls with nothing past the cutoff return 0 each."""
    now = datetime.now(UTC)
    fresh = now - timedelta(days=1)

    await _seed_run("run-delta")
    await _seed_transitions([
        ("run-delta", 0, fresh),
        ("run-delta", 1, fresh),
    ])

    first = await purge_old_transitions()
    second = await purge_old_transitions()

    assert first == 0
    assert second == 0
    assert await _load_all_transition_keys() == {("run-delta", 0), ("run-delta", 1)}


@pytest.mark.usefixtures("test_db")
async def test_purge_custom_retention_window() -> None:
    """A tighter ``retention_days`` argument sweeps rows the default would keep."""
    now = datetime.now(UTC)
    fifteen_days_old = now - timedelta(days=15)
    two_days_old = now - timedelta(days=2)

    await _seed_run("run-echo")
    await _seed_run("run-foxtrot")
    await _seed_transitions([
        ("run-echo", 0, fifteen_days_old),
        ("run-foxtrot", 0, two_days_old),
    ])

    deleted = await purge_old_transitions(retention_days=7)

    assert deleted == 1
    assert await _load_all_transition_keys() == {("run-foxtrot", 0)}


@pytest.mark.usefixtures("test_db")
async def test_purge_boundary_row_at_exact_cutoff_kept() -> None:
    """A row just inside the retention window is NOT older-than the cutoff
    and stays. Filter uses strict ``happened_at < cutoff``.
    """
    now = datetime.now(UTC)
    just_inside = now - timedelta(days=_DEFAULT_RETENTION_DAYS - 1)
    just_outside = now - timedelta(days=_DEFAULT_RETENTION_DAYS + 1)

    await _seed_run("run-golf")
    await _seed_transitions([
        ("run-golf", 0, just_outside),
        ("run-golf", 1, just_inside),
    ])

    deleted = await purge_old_transitions()

    assert deleted == 1
    assert await _load_all_transition_keys() == {("run-golf", 1)}


@pytest.mark.usefixtures("test_db")
async def test_purge_empty_table_returns_zero() -> None:
    """Empty table -> zero rows deleted; no exception, no partial state."""
    deleted = await purge_old_transitions()

    assert deleted == 0
    assert await _load_all_transition_keys() == set()
