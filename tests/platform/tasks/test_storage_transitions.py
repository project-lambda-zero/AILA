"""Issues #40-2 and #40-3: ``TaskRepository`` status transitions must
pair every DB flip with the required ARQ side-effect.

#40-2 ``set_queued_from_paused``: the pre-fix code flipped PAUSED ->
QUEUED and committed without ever re-enqueueing to ARQ, so
resume-from-pause left the task stuck 'queued' with no worker on it.
The fix enqueues via the shared ``_enqueue_arq_job`` helper (the same
code path :meth:`TaskQueue.submit` uses) BEFORE the DB flip. If enqueue
fails (broker outage, malformed kwargs_json, empty fn_path) the row
stays PAUSED so a retry can succeed later.

#40-3 ``set_cancelled``: the pre-fix code flipped a non-terminal task
to CANCELLED and committed without dropping ``arq:in-progress:<id>``,
so the worker slot stayed held until the cron reaper picked it up. It
also missed ``DEAD_LETTER`` in its terminal set, so dead-lettered rows
silently reverted to CANCELLED (erasing the poison-pill classification).
The fix adds DEAD_LETTER to the terminal set and best-effort deletes
the in-progress key after the flip commits, mirroring
``worker._sweep_orphan_running_tasks``'s key-drop pattern.

These tests patch the ARQ pool + the redis client so no live Redis is
required. They assert BOTH the ARQ side-effect AND the DB status
transition for every branch.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlmodel import Session

from aila.api.auth import AuthContext
from aila.api.constants import ROLE_ADMIN
from aila.platform.tasks.constants import (
    ARQ_IN_PROGRESS_PREFIX,
    ARQ_QUEUE_KEY_TEMPLATE,
)
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.storage import TaskRepository

from .conftest import _SyncSessionAdapter, sqlite_db_env

_REDIS_URL = "redis://127.0.0.1:6379/15"


def _admin_auth() -> AuthContext:
    """Admin auth so ``get_for_user`` does not filter by group_id."""
    return AuthContext(
        user_id="admin-1",
        role=ROLE_ADMIN,
        auth_type="api_key",
        team_id=None,
    )


def _make_pool_mock() -> MagicMock:
    pool = MagicMock()
    pool.enqueue_job = AsyncMock(return_value=MagicMock())
    pool.aclose = AsyncMock()
    return pool


def _make_redis_client_mock() -> MagicMock:
    client = MagicMock()
    client.delete = AsyncMock(return_value=1)
    client.aclose = AsyncMock()
    return client


def _insert_task(
    session: Session,
    *,
    status: TaskStatus,
    task_id: str | None = None,
    track: str = "platform",
    fn_path: str = "aila.platform.tasks.queue.dummy_fn",
    kwargs: dict[str, object] | None = None,
    kwargs_json: str | None = None,
    role: str = "operator",
) -> str:
    """Insert a TaskRecord and return its id."""
    row_id = task_id or str(uuid4())
    if kwargs_json is None:
        kwargs_json = json.dumps(kwargs if kwargs is not None else {"x": 1})
    rec = TaskRecord(
        id=row_id,
        track=track,
        fn_path=fn_path,
        fn_module="__platform__",
        status=status,
        user_id="u1",
        group_id=role,
        kwargs_json=kwargs_json,
        updated_at=datetime.now(UTC),
    )
    session.add(rec)
    session.commit()
    return row_id


# ---------------------------------------------------------------------------
# #40-2  set_queued_from_paused
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_queued_from_paused_enqueues_and_flips(
    tmp_path, monkeypatch,
) -> None:
    """Happy path: ``pool.enqueue_job`` fires with the row's fn short-name,
    queue key, job id, and kwargs; status flips PAUSED -> QUEUED."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "resume_ok") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(
                s,
                status=TaskStatus.PAUSED,
                fn_path="aila.platform.tasks.queue.some_fn",
                kwargs={"foo": "bar", "n": 3},
                track="platform",
            )

        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_queued_from_paused(
                    adapter, task_id, _admin_auth(),
                )

        assert result is True

        # ARQ side-effect: enqueue call issued with the right shape.
        pool.enqueue_job.assert_awaited_once()
        call = pool.enqueue_job.await_args
        assert call.args == ("some_fn",)
        assert call.kwargs["_queue_name"] == ARQ_QUEUE_KEY_TEMPLATE.format(track="platform")
        assert call.kwargs["_job_id"] == task_id
        assert call.kwargs["foo"] == "bar"
        assert call.kwargs["n"] == 3
        pool.aclose.assert_awaited()

        # DB side-effect: PAUSED -> QUEUED.
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.QUEUED


@pytest.mark.asyncio
async def test_set_queued_from_paused_leaves_paused_when_redis_unconfigured(
    tmp_path, monkeypatch,
) -> None:
    """No Redis URL -> False, DB stays PAUSED, no enqueue attempt."""
    monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)
    with sqlite_db_env(tmp_path, "resume_no_redis") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(s, status=TaskStatus.PAUSED)

        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_queued_from_paused(
                    adapter, task_id, _admin_auth(),
                )

        assert result is False
        pool.enqueue_job.assert_not_awaited()
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.PAUSED


@pytest.mark.asyncio
async def test_set_queued_from_paused_leaves_paused_when_enqueue_fails(
    tmp_path, monkeypatch,
) -> None:
    """Enqueue raising -> False, DB stays PAUSED, error still logged."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "resume_enq_fail") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(s, status=TaskStatus.PAUSED)

        pool = MagicMock()
        pool.enqueue_job = AsyncMock(side_effect=OSError("broker down"))
        pool.aclose = AsyncMock()

        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_queued_from_paused(
                    adapter, task_id, _admin_auth(),
                )

        assert result is False
        # Enqueue WAS attempted -- we didn't short-circuit past the ARQ call.
        pool.enqueue_job.assert_awaited_once()
        # DB unchanged.
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.PAUSED


@pytest.mark.asyncio
async def test_set_queued_from_paused_refuses_non_paused_row(
    tmp_path, monkeypatch,
) -> None:
    """A RUNNING row is not paused -> False, no enqueue call, status untouched."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "resume_wrong_state") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(s, status=TaskStatus.RUNNING)

        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_queued_from_paused(
                    adapter, task_id, _admin_auth(),
                )

        assert result is False
        pool.enqueue_job.assert_not_awaited()
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.RUNNING


@pytest.mark.asyncio
async def test_set_queued_from_paused_returns_false_for_missing_row(
    tmp_path, monkeypatch,
) -> None:
    """Task id that doesn't exist -> False, no enqueue call."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "resume_missing") as (engine, _):
        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_queued_from_paused(
                    adapter, "does-not-exist", _admin_auth(),
                )
        assert result is False
        pool.enqueue_job.assert_not_awaited()


@pytest.mark.asyncio
async def test_set_queued_from_paused_skips_malformed_kwargs_json(
    tmp_path, monkeypatch,
) -> None:
    """Unparseable kwargs_json -> False, no enqueue call, row stays PAUSED."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "resume_bad_kwargs") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(
                s, status=TaskStatus.PAUSED, kwargs_json="{not valid",
            )

        pool = _make_pool_mock()
        with patch(
            "aila.platform.tasks.queue.create_pool",
            new=AsyncMock(return_value=pool),
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_queued_from_paused(
                    adapter, task_id, _admin_auth(),
                )

        assert result is False
        pool.enqueue_job.assert_not_awaited()
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.PAUSED


# ---------------------------------------------------------------------------
# #40-3  set_cancelled
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_cancelled_flips_status_and_drops_in_progress_key(
    tmp_path, monkeypatch,
) -> None:
    """Non-terminal row: DB flips to CANCELLED and the ARQ in-progress key
    is dropped so the worker slot is released."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "cancel_running") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(s, status=TaskStatus.RUNNING)

        client = _make_redis_client_mock()
        with patch(
            "aila.platform.tasks.queue.aioredis.Redis.from_url",
            return_value=client,
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_cancelled(
                    adapter, task_id, _admin_auth(),
                )

        assert result is True

        # DB side-effect.
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.CANCELLED

        # ARQ side-effect: in-progress key dropped for this exact task id.
        client.delete.assert_awaited_once_with(f"{ARQ_IN_PROGRESS_PREFIX}{task_id}")
        client.aclose.assert_awaited()


@pytest.mark.asyncio
async def test_set_cancelled_refuses_dead_letter_source(
    tmp_path, monkeypatch,
) -> None:
    """DEAD_LETTER row: refused (False), status untouched, no key drop.

    DEAD_LETTER is a terminal state in the worker's model
    (``worker._TERMINAL_STATUSES``); flipping it to CANCELLED would erase
    the poison-pill classification.
    """
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "cancel_dead_letter") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(s, status=TaskStatus.DEAD_LETTER)

        client = _make_redis_client_mock()
        with patch(
            "aila.platform.tasks.queue.aioredis.Redis.from_url",
            return_value=client,
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_cancelled(
                    adapter, task_id, _admin_auth(),
                )

        assert result is False
        client.delete.assert_not_awaited()
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.DEAD_LETTER


@pytest.mark.parametrize(
    "terminal_state",
    [TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.CANCELLED],
)
@pytest.mark.asyncio
async def test_set_cancelled_refuses_pre_existing_terminal_state(
    tmp_path, monkeypatch, terminal_state,
) -> None:
    """DONE / FAILED / already-CANCELLED rows are refused with no ARQ call."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, f"cancel_{terminal_state.value}") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(s, status=terminal_state)

        client = _make_redis_client_mock()
        with patch(
            "aila.platform.tasks.queue.aioredis.Redis.from_url",
            return_value=client,
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_cancelled(
                    adapter, task_id, _admin_auth(),
                )
        assert result is False
        client.delete.assert_not_awaited()
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == terminal_state


@pytest.mark.asyncio
async def test_set_cancelled_returns_false_for_missing_row(
    tmp_path, monkeypatch,
) -> None:
    """Task id that doesn't exist -> False, no key drop."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "cancel_missing") as (engine, _):
        client = _make_redis_client_mock()
        with patch(
            "aila.platform.tasks.queue.aioredis.Redis.from_url",
            return_value=client,
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_cancelled(
                    adapter, "no-such-id", _admin_auth(),
                )
        assert result is False
        client.delete.assert_not_awaited()


@pytest.mark.asyncio
async def test_set_cancelled_still_flips_when_redis_unconfigured(
    tmp_path, monkeypatch,
) -> None:
    """No Redis URL: DB still flips to CANCELLED (cancel is user-driven and
    must not be blocked on broker health); key drop is skipped and the
    reaper reconciles orphan keys on the next sweep."""
    monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)
    with sqlite_db_env(tmp_path, "cancel_no_redis") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(s, status=TaskStatus.RUNNING)

        client = _make_redis_client_mock()
        with patch(
            "aila.platform.tasks.queue.aioredis.Redis.from_url",
            return_value=client,
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_cancelled(
                    adapter, task_id, _admin_auth(),
                )

        assert result is True
        client.delete.assert_not_awaited()
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.CANCELLED


@pytest.mark.asyncio
async def test_set_cancelled_survives_key_drop_failure(
    tmp_path, monkeypatch,
) -> None:
    """A raising ``client.delete`` must NOT reverse the DB flip -- the
    cron reaper picks up the orphan key on the next sweep, but the user's
    cancel request MUST be honoured immediately."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", _REDIS_URL)
    with sqlite_db_env(tmp_path, "cancel_drop_fail") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_task(s, status=TaskStatus.RUNNING)

        client = MagicMock()
        client.delete = AsyncMock(side_effect=OSError("redis reset"))
        client.aclose = AsyncMock()

        with patch(
            "aila.platform.tasks.queue.aioredis.Redis.from_url",
            return_value=client,
        ):
            with Session(engine) as raw:
                adapter = _SyncSessionAdapter(raw)
                result = await TaskRepository.set_cancelled(
                    adapter, task_id, _admin_auth(),
                )

        assert result is True
        client.delete.assert_awaited_once_with(f"{ARQ_IN_PROGRESS_PREFIX}{task_id}")
        with Session(engine) as s:
            reloaded = s.get(TaskRecord, task_id)
            assert reloaded is not None
            assert reloaded.status == TaskStatus.CANCELLED
