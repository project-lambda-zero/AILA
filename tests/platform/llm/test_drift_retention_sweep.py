"""DB-backed tests for the confidence-drift retention sweep (issue #45-5).

Every call to ``ConfidenceDriftTracker.record_and_check`` inserts a fresh
``ConfidenceDriftRecord`` row -- there is no upsert and no windowed table.
Without the retention sweep the table grew without bound. These tests seed a
mix of old and recent rows through the real Postgres ``test_db`` fixture, run
``purge_old_records`` / ``run_purge_old_records_cron``, and assert the DB
state matches the sweep's returned count.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import select

from aila.platform.llm.drift import (
    _DEFAULT_RETENTION_DAYS,
    purge_old_records,
    run_purge_old_records_cron,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import ConfidenceDriftRecord


def _make_record(*, target: str, task_type: str, computed_at: datetime) -> ConfidenceDriftRecord:
    """Build a valid ConfidenceDriftRecord anchored at ``computed_at``.

    The window/stats fields are populated with the same shape a real drift
    check would produce so the row round-trips cleanly through the model.
    """
    return ConfidenceDriftRecord(
        target_name=target,
        task_type=task_type,
        window_size=5,
        confidence_scores_json="[0.8, 0.81, 0.79, 0.82, 0.8]",
        mean_confidence=0.804,
        std_deviation=0.011,
        drift_status="stable",
        alert_fired=False,
        computed_at=computed_at,
    )


async def _seed_records(records: list[ConfidenceDriftRecord]) -> None:
    async with async_session_scope() as session:
        for rec in records:
            session.add(rec)
        await session.commit()


async def _load_all_targets() -> set[str]:
    async with async_session_scope() as session:
        rows = (await session.exec(select(ConfidenceDriftRecord))).all()
        return {row.target_name for row in rows}


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_purge_old_records_deletes_only_old_rows() -> None:
    """Rows older than the 90-day default are dropped; recent rows are kept."""
    now = datetime.now(UTC)
    old = now - timedelta(days=_DEFAULT_RETENTION_DAYS + 5)
    fresh = now - timedelta(days=_DEFAULT_RETENTION_DAYS - 5)

    await _seed_records([
        _make_record(target="alpha", task_type="scoring", computed_at=old),
        _make_record(target="bravo", task_type="scoring", computed_at=old),
        _make_record(target="charlie", task_type="scoring", computed_at=fresh),
    ])

    async with async_session_scope() as session:
        deleted = await purge_old_records(session)

    assert deleted == 2

    remaining = await _load_all_targets()
    assert remaining == {"charlie"}


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_purge_old_records_return_matches_deleted_count() -> None:
    """Return value equals the exact number of rows removed."""
    now = datetime.now(UTC)
    old_ts = now - timedelta(days=_DEFAULT_RETENTION_DAYS + 30)

    records = [
        _make_record(target=f"tgt-{i}", task_type="seal", computed_at=old_ts)
        for i in range(7)
    ]
    await _seed_records(records)

    async with async_session_scope() as session:
        deleted = await purge_old_records(session)

    assert deleted == 7

    async with async_session_scope() as session:
        remaining = (await session.exec(select(ConfidenceDriftRecord))).all()
    assert remaining == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_purge_old_records_idempotent_when_no_matches() -> None:
    """Second call in the same tick with nothing past the cutoff returns 0."""
    now = datetime.now(UTC)
    fresh = now - timedelta(days=1)

    await _seed_records([
        _make_record(target="delta", task_type="scoring", computed_at=fresh),
    ])

    async with async_session_scope() as session:
        first = await purge_old_records(session)
    async with async_session_scope() as session:
        second = await purge_old_records(session)

    assert first == 0
    assert second == 0
    assert await _load_all_targets() == {"delta"}


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_purge_old_records_custom_retention_window() -> None:
    """A tighter retention_days argument sweeps rows the default would keep."""
    now = datetime.now(UTC)
    fifteen_days_old = now - timedelta(days=15)
    two_days_old = now - timedelta(days=2)

    await _seed_records([
        _make_record(target="echo", task_type="scoring", computed_at=fifteen_days_old),
        _make_record(target="foxtrot", task_type="scoring", computed_at=two_days_old),
    ])

    async with async_session_scope() as session:
        deleted = await purge_old_records(session, retention_days=7)

    assert deleted == 1
    assert await _load_all_targets() == {"foxtrot"}


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_purge_old_records_boundary_row_at_exact_cutoff_kept() -> None:
    """A row EXACTLY at the cutoff is NOT older-than the cutoff and stays.

    ``purge_old_records`` filters strictly with ``computed_at < cutoff``.
    """
    now = datetime.now(UTC)
    just_inside = now - timedelta(days=_DEFAULT_RETENTION_DAYS - 1)
    just_outside = now - timedelta(days=_DEFAULT_RETENTION_DAYS + 1)

    await _seed_records([
        _make_record(target="inside", task_type="scoring", computed_at=just_inside),
        _make_record(target="outside", task_type="scoring", computed_at=just_outside),
    ])

    async with async_session_scope() as session:
        deleted = await purge_old_records(session)

    assert deleted == 1
    assert await _load_all_targets() == {"inside"}


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_run_purge_old_records_cron_opens_own_session() -> None:
    """The cron wrapper opens its own session and returns the deleted count."""
    now = datetime.now(UTC)
    old = now - timedelta(days=_DEFAULT_RETENTION_DAYS + 10)
    fresh = now - timedelta(days=_DEFAULT_RETENTION_DAYS - 30)

    await _seed_records([
        _make_record(target="cron-old-1", task_type="scoring", computed_at=old),
        _make_record(target="cron-old-2", task_type="scoring", computed_at=old),
        _make_record(target="cron-fresh", task_type="scoring", computed_at=fresh),
    ])

    deleted = await run_purge_old_records_cron()

    assert deleted == 2
    assert await _load_all_targets() == {"cron-fresh"}


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_run_purge_old_records_cron_on_empty_table_returns_zero() -> None:
    """Empty table -> zero rows deleted; no exception, no partial state."""
    deleted = await run_purge_old_records_cron()

    assert deleted == 0
    assert await _load_all_targets() == set()
