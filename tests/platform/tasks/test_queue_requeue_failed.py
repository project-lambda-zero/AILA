"""Issue #40-1: ``TaskQueue.requeue_failed`` must enqueue an ARQ job for
every row it re-queues, not just flip ``TaskRecord.status``.

The pre-fix behaviour was to flip ``status='failed'`` -> ``'queued'`` and
commit without ever calling ``pool.enqueue_job`` for the row, so the DB
row read as 'queued' forever but no worker ever picked it up. The fix
enqueues via the shared ``_enqueue_arq_job`` helper (the same code path
:meth:`TaskQueue.submit` uses) BEFORE flipping the status; rows whose
enqueue fails stay 'failed' so the caller can retry.

These tests patch the ARQ pool so no live Redis is required. They
assert BOTH the ARQ side-effect (enqueue call issued with the right
fn short-name / queue key / job id / kwargs) AND the DB status
transition.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlmodel import Session

from aila.platform.exceptions import WorkerUnreachableError
from aila.platform.tasks.constants import ARQ_QUEUE_KEY_TEMPLATE
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.queue import TaskQueue

from .conftest import sqlite_db_env

_REDIS_URL = "redis://127.0.0.1:6379/15"


def _null_registry() -> MagicMock:
    """A ConfigRegistry-shaped mock whose ``get_sync`` returns None.

    ``TaskQueue._get_redis_url`` falls back to the registry when the env
    var is unset; passing ``config_registry=None`` would raise
    ``AttributeError`` on the registry call. The mock keeps the fallback
    path clean when we want to observe the ``WorkerUnreachableError``.
    """
    registry = MagicMock()
    registry.get_sync.return_value = None
    return registry


def _make_pool_mock() -> MagicMock:
    """Return a MagicMock arq pool with awaitable ``enqueue_job`` / ``aclose``."""
    pool = MagicMock()
    pool.enqueue_job = AsyncMock(return_value=MagicMock())
    pool.aclose = AsyncMock()
    return pool


def _insert_failed_row(
    session: Session,
    *,
    task_id: str | None = None,
    track: str = "platform",
    fn_path: str = "aila.platform.tasks.queue.dummy_fn",
    kwargs: dict[str, object] | None = None,
    kwargs_json: str | None = None,
    error: str = "prior failure",
    updated_at: datetime | None = None,
) -> str:
    """Insert a TaskRecord in status=FAILED and return its id."""
    row_id = task_id or str(uuid4())
    if kwargs_json is None:
        kwargs_json = json.dumps(kwargs if kwargs is not None else {"x": 1})
    rec = TaskRecord(
        id=row_id,
        track=track,
        fn_path=fn_path,
        fn_module="__platform__",
        status=TaskStatus.FAILED,
        user_id="u1",
        group_id="operator",
        kwargs_json=kwargs_json,
        error=error,
        updated_at=updated_at or datetime.now(UTC),
    )
    session.add(rec)
    session.commit()
    return row_id


@pytest.mark.asyncio
async def test_requeue_failed_enqueues_and_flips_status(tmp_path, monkeypatch) -> None:
    """Happy path: ``pool.enqueue_job`` fires with the row's fn short-name,
    queue key, job id, and kwargs; status flips FAILED -> QUEUED and the
    error field is cleared."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "requeue_ok") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_failed_row(
                s,
                fn_path="aila.platform.tasks.queue.some_fn",
                kwargs={"foo": "bar", "n": 3},
                track="platform",
            )

        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            queue = TaskQueue(config_registry=_null_registry(), module_id="__platform__")
            count = await queue.requeue_failed(max_age_hours=24)

        # DB side-effect: status flipped, error cleared.
        assert count == 1
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.QUEUED
            assert reloaded.error is None

        # ARQ side-effect: enqueue call issued for the requeued task id
        # with the expected shape.
        pool.enqueue_job.assert_awaited_once()
        call = pool.enqueue_job.await_args
        assert call.args == ("some_fn",), (
            "requeue_failed must pass the trailing segment of fn_path as the ARQ "
            "function name (short __qualname__)"
        )
        assert call.kwargs["_queue_name"] == ARQ_QUEUE_KEY_TEMPLATE.format(track="platform")
        assert call.kwargs["_job_id"] == task_id
        assert call.kwargs["foo"] == "bar"
        assert call.kwargs["n"] == 3
        pool.aclose.assert_awaited()


@pytest.mark.asyncio
async def test_requeue_failed_raises_when_redis_url_unconfigured(
    tmp_path, monkeypatch,
) -> None:
    """No Redis URL -> ``WorkerUnreachableError`` and NO DB flip.

    This mirrors :meth:`TaskQueue.submit`'s fail-fast contract so the
    caller sees a clean 503 instead of a silent no-op that leaves rows
    stuck 'queued' with no worker.
    """
    monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)
    with sqlite_db_env(tmp_path, "requeue_no_redis") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_failed_row(s)

        queue = TaskQueue(config_registry=_null_registry(), module_id="__platform__")
        with pytest.raises(WorkerUnreachableError):
            await queue.requeue_failed()

        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.FAILED
            assert reloaded.error == "prior failure"


@pytest.mark.asyncio
async def test_requeue_failed_skips_row_when_enqueue_fails(
    tmp_path, monkeypatch,
) -> None:
    """When ``pool.enqueue_job`` raises for a row, that row stays FAILED
    (with error preserved) while the sibling row still requeues cleanly.
    ``count`` excludes the skipped row."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "requeue_partial") as (engine, _):
        # Deterministic ordering: insert IDs we own so we can match the
        # per-call side_effect to a specific row.
        good_id = "aaaa1111-aaaa-1111-aaaa-111111111111"
        bad_id = "bbbb2222-bbbb-2222-bbbb-222222222222"
        with Session(engine) as s:
            _insert_failed_row(s, task_id=good_id, kwargs={"row": "good"})
            _insert_failed_row(s, task_id=bad_id, kwargs={"row": "bad"})

        pool = MagicMock()

        def _enqueue_side_effect(fn_name, **kwargs):
            _ = fn_name
            if kwargs.get("_job_id") == bad_id:
                raise OSError("connection reset")
            return MagicMock()

        pool.enqueue_job = AsyncMock(side_effect=_enqueue_side_effect)
        pool.aclose = AsyncMock()

        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            queue = TaskQueue(config_registry=_null_registry(), module_id="__platform__")
            count = await queue.requeue_failed()

        assert count == 1
        with Session(engine) as s:
            good_row = s.get(TaskRecord, good_id)
            bad_row = s.get(TaskRecord, bad_id)
            assert good_row is not None
            assert bad_row is not None
            assert good_row.status == TaskStatus.QUEUED
            assert good_row.error is None
            # Skipped row preserves prior failure signal so operators
            # / follow-up retries can still see WHY it failed the first time.
            assert bad_row.status == TaskStatus.FAILED
            assert bad_row.error == "prior failure"

        # Both rows went through the enqueue attempt -- we did not silently
        # skip one before contacting Redis.
        assert pool.enqueue_job.await_count == 2


@pytest.mark.asyncio
async def test_requeue_failed_skips_row_with_malformed_kwargs_json(
    tmp_path, monkeypatch,
) -> None:
    """A row whose kwargs_json is not valid JSON is skipped BEFORE any
    ARQ call, keeping the previous FAILED status intact."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "requeue_bad_kwargs") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_failed_row(s, kwargs_json="{not valid json")

        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            queue = TaskQueue(config_registry=_null_registry(), module_id="__platform__")
            count = await queue.requeue_failed()

        assert count == 0
        pool.enqueue_job.assert_not_awaited()
        with Session(engine) as s:
            row = s.get(TaskRecord, task_id)
            assert row is not None
            assert row.status == TaskStatus.FAILED
            assert row.error == "prior failure"


@pytest.mark.asyncio
async def test_requeue_failed_skips_row_with_empty_fn_path(
    tmp_path, monkeypatch,
) -> None:
    """A row with empty ``fn_path`` is skipped -- ARQ needs a callable name."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "requeue_no_fn") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_failed_row(s, fn_path="")

        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            queue = TaskQueue(config_registry=_null_registry(), module_id="__platform__")
            count = await queue.requeue_failed()

        assert count == 0
        pool.enqueue_job.assert_not_awaited()
        with Session(engine) as s:
            row = s.get(TaskRecord, task_id)
            assert row is not None
            assert row.status == TaskStatus.FAILED


@pytest.mark.asyncio
async def test_requeue_failed_ignores_rows_outside_age_window(
    tmp_path, monkeypatch,
) -> None:
    """Rows whose ``updated_at`` is older than ``max_age_hours`` are not
    even considered -- no ARQ call, no DB flip. Guards the pre-existing
    contract while confirming the enqueue path did not widen the window."""
    from datetime import timedelta as _td

    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "requeue_old") as (engine, _):
        old_ts = datetime.now(UTC) - _td(hours=72)
        with Session(engine) as s:
            fresh_id = _insert_failed_row(s, kwargs={"age": "fresh"})
            stale_id = _insert_failed_row(
                s, kwargs={"age": "stale"}, updated_at=old_ts,
            )

        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            queue = TaskQueue(config_registry=_null_registry(), module_id="__platform__")
            count = await queue.requeue_failed(max_age_hours=24)

        assert count == 1
        assert pool.enqueue_job.await_count == 1
        call = pool.enqueue_job.await_args
        assert call.kwargs["_job_id"] == fresh_id

        with Session(engine) as s:
            fresh = s.get(TaskRecord, fresh_id)
            stale = s.get(TaskRecord, stale_id)
            assert fresh is not None and fresh.status == TaskStatus.QUEUED
            assert stale is not None and stale.status == TaskStatus.FAILED
