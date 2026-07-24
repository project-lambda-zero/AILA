"""Deep review tests for tasks/progress.py and tasks/storage.py (Phase 83).

FILE-29: ProgressStream emit/catchup/stream work, MAXLEN from ConfigRegistry,
         late-connect replay correct.
FILE-30: TaskRepository scoping correct, admin bypass works, group isolation
         proven, cross-user data leaks impossible.

Async migration:
  - ProgressStream.__init__ takes only (maxlen=None) -- the Redis URL
    positional was removed.  ProgressStream.emit/catchup/stream_events are
    now async and use the shared aila.platform.services.redis_pool.get_redis
    context manager, so the mocks patch that name instead of the removed
    redis.Redis.from_url path.
  - TaskRepository.list_for_user/get_for_user/set_paused/
    set_queued_from_paused/set_cancelled are async and take an AsyncSession
    plus an AuthContext (was ApiKeyRecord).
  - The old per-file SQLite engine setup is removed: the tests depend on the
    shared ``test_db`` fixture (root conftest) which points AILA at the
    aila_test PostgreSQL database and truncates on teardown.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.storage.database import async_session_scope, session_scope

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_redis_cm(mock_client):
    """Wrap ``mock_client`` in an async context manager compatible with
    ``async with get_redis() as client``.  Returned callable stands in for
    ``aila.platform.tasks.progress.get_redis``.
    """

    @asynccontextmanager
    async def _cm():
        yield mock_client

    return _cm


def _make_auth(role: str = "operator", user_id: str = "key-1") -> AuthContext:
    """Return a minimal AuthContext (role + user_id) matching TaskRepository's usage."""
    return AuthContext(user_id=user_id, role=role, auth_type="api_key", team_id=None)


def _create_task(group_id: str = "operator", track: str = "vuln",
                 status: str = "queued", user_id: str = "u1") -> str:
    """Insert a TaskRecord via the shared sync session_scope and return its id."""
    from aila.platform.tasks.models import TaskRecord

    with session_scope() as s:
        rec = TaskRecord(
            track=track,
            fn_path="aila.modules.vulnerability.tasks.scan",
            fn_module="vulnerability",
            user_id=user_id,
            group_id=group_id,
            status=status,
        )
        s.add(rec)
        s.commit()
        s.refresh(rec)
        return rec.id


# ===========================================================================
# Group 1: ProgressStream.emit() (FILE-29)
# ===========================================================================


class TestProgressStreamEmit:
    """Prove emit() writes events to Redis Stream with MAXLEN cap."""

    async def test_emit_calls_xadd_with_correct_fields(self) -> None:
        """FILE-29: emit() writes stage, message, percent, timestamp to Redis Stream."""
        mock_client = MagicMock()
        mock_client.xadd = AsyncMock()

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=500)
            await ps.emit("task-abc", "inventory", "Scanning hosts", 25)

        mock_client.xadd.assert_awaited_once()
        call_args = mock_client.xadd.call_args
        key = call_args[0][0]
        fields = call_args[0][1]

        assert key == "task:task-abc:progress"
        assert fields["stage"] == "inventory"
        assert fields["message"] == "Scanning hosts"
        assert fields["percent"] == "25"
        assert "timestamp" in fields

    async def test_emit_uses_maxlen_with_exact_trim(self) -> None:
        """FILE-29: emit() passes maxlen and approximate=False for exact trim."""
        mock_client = MagicMock()
        mock_client.xadd = AsyncMock()

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=1000)
            await ps.emit("task-abc", "s", "m", 0)

        call_kwargs = mock_client.xadd.call_args
        assert call_kwargs[1]["maxlen"] == 1000
        assert call_kwargs[1]["approximate"] is False

    async def test_emit_maxlen_from_constructor_parameter(self) -> None:
        """FILE-29: Custom maxlen parameter overrides default."""
        mock_client = MagicMock()
        mock_client.xadd = AsyncMock()

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=42)
            await ps.emit("task-1", "s", "m", 0)

        assert mock_client.xadd.call_args[1]["maxlen"] == 42

    async def test_emit_maxlen_from_get_task_tuning_fallback(self) -> None:
        """FILE-29: When maxlen is None, constructor reads from get_task_tuning."""
        mock_client = MagicMock()
        mock_client.xadd = AsyncMock()

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)), \
             patch("aila.platform.tasks.get_task_tuning", return_value=777):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=None)
            await ps.emit("task-1", "s", "m", 0)

        assert mock_client.xadd.call_args[1]["maxlen"] == 777


# ===========================================================================
# Group 2: ProgressStream.catchup() (FILE-29)
# ===========================================================================


class TestProgressStreamCatchup:
    """Prove catchup() returns all events for late-connect replay."""

    async def test_catchup_returns_all_events_from_start(self) -> None:
        """FILE-29: catchup(last_id='0') returns full event history."""
        mock_client = MagicMock()
        mock_client.xrange = AsyncMock(return_value=[
            ("1-0", {"stage": "init", "message": "Starting", "percent": "0", "timestamp": "t1"}),
            ("2-0", {"stage": "scan", "message": "Scanning", "percent": "50", "timestamp": "t2"}),
            ("3-0", {"stage": "done", "message": "Complete", "percent": "100", "timestamp": "t3"}),
        ])

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=1000)
            events = await ps.catchup("task-xyz")

        mock_client.xrange.assert_awaited_once_with("task:task-xyz:progress", "0", "+")
        assert len(events) == 3
        assert events[0]["stage"] == "init"
        assert events[1]["percent"] == "50"
        assert events[2]["message"] == "Complete"

    async def test_catchup_returns_empty_list_when_no_events(self) -> None:
        """FILE-29: catchup() returns [] for task with no progress events."""
        mock_client = MagicMock()
        mock_client.xrange = AsyncMock(return_value=[])

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=1000)
            events = await ps.catchup("task-empty")

        assert events == []

    async def test_catchup_with_custom_last_id(self) -> None:
        """FILE-29: catchup(last_id='5-0') reads only events after ID 5-0."""
        mock_client = MagicMock()
        mock_client.xrange = AsyncMock(return_value=[
            ("6-0", {"stage": "s", "message": "m", "percent": "60", "timestamp": "t"}),
        ])

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=1000)
            events = await ps.catchup("task-1", last_id="5-0")

        mock_client.xrange.assert_awaited_once_with("task:task-1:progress", "5-0", "+")
        assert len(events) == 1


# ===========================================================================
# Group 3: ProgressStream.stream_events() (FILE-29)
# ===========================================================================


class TestProgressStreamStreamEvents:
    """Prove stream_events() yields live events and ping sentinels."""

    async def test_stream_events_yields_live_events(self) -> None:
        """FILE-29: stream_events() yields event dicts from XREAD."""
        mock_client = MagicMock()
        event_data = {"stage": "scan", "message": "In progress", "percent": "30", "timestamp": "t1"}
        # First call returns data, second call raises to break the loop
        mock_client.xread = AsyncMock(side_effect=[
            [("task:task-1:progress", [("1-0", event_data)])],
            KeyboardInterrupt,
        ])

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=1000)
            gen = ps.stream_events("task-1")

            result = await gen.__anext__()
            assert result == event_data

            with pytest.raises(KeyboardInterrupt):
                await gen.__anext__()

    async def test_stream_events_yields_ping_on_timeout(self) -> None:
        """FILE-29: stream_events() yields {"type": "ping"} when XREAD times out."""
        mock_client = MagicMock()
        # First call: empty (timeout), second call: break
        mock_client.xread = AsyncMock(side_effect=[
            [],  # timeout, no data
            KeyboardInterrupt,
        ])

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=1000)
            gen = ps.stream_events("task-1")

            result = await gen.__anext__()
            assert result == {"type": "ping"}

    async def test_stream_events_advances_current_id(self) -> None:
        """FILE-29: After receiving event '5-0', next XREAD uses '5-0' as current_id."""
        mock_client = MagicMock()
        event1 = {"stage": "a", "message": "m", "percent": "10", "timestamp": "t"}
        event2 = {"stage": "b", "message": "n", "percent": "20", "timestamp": "t"}
        mock_client.xread = AsyncMock(side_effect=[
            [("task:t:progress", [("5-0", event1)])],
            [("task:t:progress", [("6-0", event2)])],
            KeyboardInterrupt,
        ])

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=1000)
            gen = ps.stream_events("t")

            await gen.__anext__()  # event1
            await gen.__anext__()  # event2

        # Verify XREAD calls used advancing IDs
        calls = mock_client.xread.call_args_list
        assert calls[0][0][0] == {"task:t:progress": "0"}   # initial
        assert calls[1][0][0] == {"task:t:progress": "5-0"}  # after first event

    async def test_stream_events_uses_xread_block_ms(self) -> None:
        """FILE-29: XREAD block parameter matches XREAD_BLOCK_MS constant."""
        from aila.platform.tasks.constants import XREAD_BLOCK_MS

        mock_client = MagicMock()
        mock_client.xread = AsyncMock(side_effect=[[], KeyboardInterrupt])

        with patch("aila.platform.tasks.progress.get_redis", _mock_redis_cm(mock_client)):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream(maxlen=1000)
            gen = ps.stream_events("task-1")
            await gen.__anext__()  # trigger first XREAD

        call_kwargs = mock_client.xread.call_args_list[0][1]
        assert call_kwargs["block"] == XREAD_BLOCK_MS


# ===========================================================================
# Group 4: ProgressStream __all__ exports (FILE-29)
# ===========================================================================


class TestProgressStreamExports:
    """Verify __all__ exports for progress module."""

    def test_progress_all_exports(self) -> None:
        """FILE-29: progress.py exports MAX_STREAM_LIFETIME_S + ProgressStream."""
        from aila.platform.tasks import progress

        assert progress.__all__ == ["MAX_STREAM_LIFETIME_S", "ProgressStream"]


# ===========================================================================
# Group 5: TaskRepository.list_for_user scoping (FILE-30)
# ===========================================================================


class TestTaskRepositoryListForUser:
    """Prove list_for_user scopes by group_id for non-admin users."""

    async def test_non_admin_sees_only_own_group(self, test_db) -> None:
        """FILE-30: Operator only sees tasks with matching group_id."""
        from aila.platform.tasks.storage import TaskRepository

        _create_task(group_id="operator", user_id="u1")
        _create_task(group_id="operator", user_id="u2")
        _create_task(group_id="reader", user_id="u3")

        auth = _make_auth(role="operator")
        async with async_session_scope() as s:
            results = await TaskRepository.list_for_user(s, auth)

        assert len(results) == 2
        for r in results:
            assert r.group_id == "operator"

    async def test_admin_sees_all_tasks(self, test_db) -> None:
        """FILE-30: Admin user sees all tasks regardless of group_id."""
        from aila.platform.tasks.storage import TaskRepository

        _create_task(group_id="operator")
        _create_task(group_id="reader")
        _create_task(group_id="admin")

        auth = _make_auth(role="admin")
        async with async_session_scope() as s:
            results = await TaskRepository.list_for_user(s, auth)

        assert len(results) == 3

    async def test_filter_by_track(self, test_db) -> None:
        """FILE-30: list_for_user with track filter returns only matching tasks."""
        from aila.platform.tasks.storage import TaskRepository

        _create_task(track="vuln", group_id="operator")
        _create_task(track="network", group_id="operator")

        auth = _make_auth(role="operator")
        async with async_session_scope() as s:
            results = await TaskRepository.list_for_user(s, auth, track="vuln")

        assert len(results) == 1
        assert results[0].track == "vuln"

    async def test_filter_by_status(self, test_db) -> None:
        """FILE-30: list_for_user with status filter returns only matching tasks."""
        from aila.platform.tasks.storage import TaskRepository

        _create_task(status="queued", group_id="operator")
        _create_task(status="running", group_id="operator")
        _create_task(status="done", group_id="operator")

        auth = _make_auth(role="operator")
        async with async_session_scope() as s:
            results = await TaskRepository.list_for_user(s, auth, status="running")

        assert len(results) == 1
        assert results[0].status == "running"

    async def test_combined_track_and_status_filter(self, test_db) -> None:
        """FILE-30: list_for_user with both track and status returns intersection."""
        from aila.platform.tasks.storage import TaskRepository

        _create_task(track="vuln", status="queued", group_id="operator")
        _create_task(track="vuln", status="done", group_id="operator")
        _create_task(track="network", status="queued", group_id="operator")

        auth = _make_auth(role="operator")
        async with async_session_scope() as s:
            results = await TaskRepository.list_for_user(s, auth, track="vuln", status="queued")

        assert len(results) == 1
        assert results[0].track == "vuln"
        assert results[0].status == "queued"


# ===========================================================================
# Group 6: TaskRepository.get_for_user scoping (FILE-30)
# ===========================================================================


class TestTaskRepositoryGetForUser:
    """Prove get_for_user scopes by group_id and admin bypass."""

    async def test_operator_cannot_see_other_group_task(self, test_db) -> None:
        """FILE-30: Operator cannot get a task belonging to a different group."""
        from aila.platform.tasks.storage import TaskRepository

        admin_task_id = _create_task(group_id="admin")

        auth = _make_auth(role="operator")
        async with async_session_scope() as s:
            result = await TaskRepository.get_for_user(s, admin_task_id, auth)

        assert result is None, "Operator must NOT see admin's task"

    async def test_admin_can_see_any_task(self, test_db) -> None:
        """FILE-30: Admin can see tasks from any group."""
        from aila.platform.tasks.storage import TaskRepository

        operator_task_id = _create_task(group_id="operator")

        auth = _make_auth(role="admin")
        async with async_session_scope() as s:
            result = await TaskRepository.get_for_user(s, operator_task_id, auth)

        assert result is not None
        assert result.id == operator_task_id

    async def test_returns_none_for_nonexistent_task(self, test_db) -> None:
        """FILE-30: get_for_user returns None for non-existent task_id."""
        from aila.platform.tasks.storage import TaskRepository

        auth = _make_auth(role="admin")
        async with async_session_scope() as s:
            result = await TaskRepository.get_for_user(s, "nonexistent-id", auth)

        assert result is None

    async def test_operator_sees_own_group_task(self, test_db) -> None:
        """FILE-30: Operator can see task with matching group_id."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(group_id="operator")

        auth = _make_auth(role="operator")
        async with async_session_scope() as s:
            result = await TaskRepository.get_for_user(s, task_id, auth)

        assert result is not None
        assert result.id == task_id


# ===========================================================================
# Group 7: TaskRepository state transitions (FILE-30)
# ===========================================================================


class TestTaskRepositorySetPaused:
    """Prove set_paused transitions RUNNING -> PAUSED."""

    async def test_running_to_paused(self, test_db) -> None:
        """FILE-30: set_paused transitions RUNNING task to PAUSED."""
        from aila.platform.tasks.models import TaskRecord
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="running", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_paused(s, task_id, auth)

        assert result is True

        with session_scope() as s:
            rec = s.exec(select(TaskRecord).where(TaskRecord.id == task_id)).first()
            assert rec.status == "paused"

    async def test_paused_returns_false_for_non_running(self, test_db) -> None:
        """FILE-30: set_paused returns False for queued task (not RUNNING)."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="queued", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_paused(s, task_id, auth)

        assert result is False

    async def test_paused_returns_false_for_other_group(self, test_db) -> None:
        """FILE-30: set_paused returns False when operator tries to pause admin's task."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="running", group_id="admin")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_paused(s, task_id, auth)

        assert result is False, "Operator must not pause admin's task"


class TestTaskRepositorySetQueuedFromPaused:
    """Prove set_queued_from_paused transitions PAUSED -> QUEUED."""

    async def test_paused_to_queued(self, test_db) -> None:
        """FILE-30: set_queued_from_paused transitions PAUSED task to QUEUED."""
        from aila.platform.tasks.models import TaskRecord
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="paused", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_queued_from_paused(s, task_id, auth)

        assert result is True

        with session_scope() as s:
            rec = s.exec(select(TaskRecord).where(TaskRecord.id == task_id)).first()
            assert rec.status == "queued"

    async def test_queued_from_paused_returns_false_for_non_paused(self, test_db) -> None:
        """FILE-30: set_queued_from_paused returns False for RUNNING task."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="running", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_queued_from_paused(s, task_id, auth)

        assert result is False


class TestTaskRepositorySetCancelled:
    """Prove set_cancelled marks non-terminal task as CANCELLED."""

    async def test_queued_to_cancelled(self, test_db) -> None:
        """FILE-30: set_cancelled transitions QUEUED task to CANCELLED."""
        from aila.platform.tasks.models import TaskRecord
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="queued", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_cancelled(s, task_id, auth)

        assert result is True

        with session_scope() as s:
            rec = s.exec(select(TaskRecord).where(TaskRecord.id == task_id)).first()
            assert rec.status == "cancelled"

    async def test_running_to_cancelled(self, test_db) -> None:
        """FILE-30: set_cancelled transitions RUNNING task to CANCELLED."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="running", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_cancelled(s, task_id, auth)

        assert result is True

    async def test_cancelled_returns_false_for_done_task(self, test_db) -> None:
        """FILE-30: set_cancelled returns False for already DONE task (terminal)."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="done", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_cancelled(s, task_id, auth)

        assert result is False

    async def test_cancelled_returns_false_for_failed_task(self, test_db) -> None:
        """FILE-30: set_cancelled returns False for FAILED task (terminal)."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="failed", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_cancelled(s, task_id, auth)

        assert result is False

    async def test_cancelled_returns_false_for_already_cancelled(self, test_db) -> None:
        """FILE-30: set_cancelled returns False for already CANCELLED task."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(status="cancelled", group_id="operator")
        auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_cancelled(s, task_id, auth)

        assert result is False


# ===========================================================================
# Group 8: Cross-user isolation (FILE-30)
# ===========================================================================


class TestCrossUserIsolation:
    """Prove cross-user data leak is impossible through TaskRepository."""

    async def test_operator_a_invisible_to_operator_b(self, test_db) -> None:
        """FILE-30: Tasks created by operator (group_id=operator) are visible
        to users with the same group_id but NOT to users with different group_id."""
        from aila.platform.tasks.storage import TaskRepository

        op_task_id = _create_task(group_id="operator", user_id="op-user-1")
        rd_task_id = _create_task(group_id="reader", user_id="rd-user-1")

        op_auth = _make_auth(role="operator")
        async with async_session_scope() as s:
            op_list = await TaskRepository.list_for_user(s, op_auth)
        assert len(op_list) == 1
        assert op_list[0].id == op_task_id

        rd_auth = _make_auth(role="reader")
        async with async_session_scope() as s:
            rd_list = await TaskRepository.list_for_user(s, rd_auth)
        assert len(rd_list) == 1
        assert rd_list[0].id == rd_task_id

        async with async_session_scope() as s:
            cross = await TaskRepository.get_for_user(s, rd_task_id, op_auth)
            assert cross is None, "Operator must NOT see reader's task via get_for_user"

        async with async_session_scope() as s:
            cross = await TaskRepository.get_for_user(s, op_task_id, rd_auth)
            assert cross is None, "Reader must NOT see operator's task via get_for_user"

    async def test_cross_group_set_paused_blocked(self, test_db) -> None:
        """FILE-30: Operator cannot pause a reader's RUNNING task."""
        from aila.platform.tasks.storage import TaskRepository

        reader_task_id = _create_task(group_id="reader", status="running")
        op_auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_paused(s, reader_task_id, op_auth)

        assert result is False, "Cross-group pause must be blocked"

    async def test_cross_group_set_cancelled_blocked(self, test_db) -> None:
        """FILE-30: Operator cannot cancel a reader's task."""
        from aila.platform.tasks.storage import TaskRepository

        reader_task_id = _create_task(group_id="reader", status="queued")
        op_auth = _make_auth(role="operator")

        async with async_session_scope() as s:
            result = await TaskRepository.set_cancelled(s, reader_task_id, op_auth)

        assert result is False, "Cross-group cancel must be blocked"

    async def test_admin_can_operate_on_any_group(self, test_db) -> None:
        """FILE-30: Admin can pause, resume, and cancel tasks from any group."""
        from aila.platform.tasks.storage import TaskRepository

        task_id = _create_task(group_id="reader", status="running")
        admin_auth = _make_auth(role="admin")

        async with async_session_scope() as s:
            result = await TaskRepository.set_paused(s, task_id, admin_auth)
        assert result is True

        async with async_session_scope() as s:
            result = await TaskRepository.set_queued_from_paused(s, task_id, admin_auth)
        assert result is True

        async with async_session_scope() as s:
            result = await TaskRepository.set_cancelled(s, task_id, admin_auth)
        assert result is True


# ===========================================================================
# Group 9: TaskRepository __all__ exports (FILE-30)
# ===========================================================================


class TestTaskRepositoryExports:
    """Verify __all__ exports for storage module."""

    def test_storage_all_exports(self) -> None:
        """FILE-30: storage.py exports exactly ['TaskRepository']."""
        from aila.platform.tasks import storage

        assert storage.__all__ == ["TaskRepository"]


class TestProgressStreamKey:
    """stream_key is the single public accessor for the stream-key format."""

    def test_stream_key_matches_template(self) -> None:
        """FILE-29: callers derive the key through stream_key, not _KEY_FMT."""
        from aila.platform.tasks.constants import TASK_PROGRESS_KEY_TEMPLATE
        from aila.platform.tasks.progress import ProgressStream

        assert ProgressStream.stream_key("task-abc") == "task:task-abc:progress"
        assert ProgressStream.stream_key("t") == TASK_PROGRESS_KEY_TEMPLATE.format(
            task_id="t",
        )
