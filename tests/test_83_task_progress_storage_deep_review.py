"""Deep review tests for tasks/progress.py and tasks/storage.py (Phase 83).

FILE-29: ProgressStream emit/catchup/stream work, MAXLEN from ConfigRegistry,
         late-connect replay correct.
FILE-30: TaskRepository scoping correct, admin bypass works, group isolation
         proven, cross-user data leaks impossible.

Coverage targets:
  - emit() XADD with MAXLEN cap and correct field mapping
  - catchup() XRANGE from start for late-connect replay
  - catchup() returns empty list when no events exist
  - stream_events() yields live events from XREAD
  - stream_events() yields ping sentinel on timeout
  - MAXLEN from constructor parameter or get_task_tuning fallback
  - TaskRepository.list_for_user scopes by group_id for non-admin
  - TaskRepository.list_for_user returns all for admin
  - TaskRepository.list_for_user filters by track and status
  - TaskRepository.get_for_user scopes by group_id
  - TaskRepository.get_for_user admin bypass
  - TaskRepository.set_paused transition: RUNNING -> PAUSED
  - TaskRepository.set_queued_from_paused transition: PAUSED -> QUEUED
  - TaskRepository.set_cancelled marks non-terminal as CANCELLED
  - Cross-user isolation: operator A invisible to operator B
  - __all__ exports for both modules
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlmodel import SQLModel, Session


# ---------------------------------------------------------------------------
# DB isolation helpers (same pattern as Phase 81/82)
# ---------------------------------------------------------------------------


def _make_test_engine(db_url: str):
    """Create a fresh SQLite engine with all SQLModel tables registered."""
    import aila.platform.tasks.models  # noqa: F401
    import aila.storage.db_models  # noqa: F401
    import aila.modules.vulnerability.db_models  # noqa: F401

    engine = create_engine(db_url, connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return engine


def _inject_engine(engine, db_url: str) -> None:
    import aila.storage.database as _db_module

    with _db_module._ENGINE_LOCK:
        _db_module._ENGINES[db_url] = engine
        _db_module._INITIALIZED_URLS.add(db_url)


def _remove_engine(db_url: str) -> None:
    import aila.storage.database as _db_module

    with _db_module._ENGINE_LOCK:
        _db_module._ENGINES.pop(db_url, None)
        _db_module._INITIALIZED_URLS.discard(db_url)


@contextmanager
def _real_scope(engine):
    with Session(engine) as s:
        yield s


def _make_api_key(role: str = "operator", key_id: str = "key-1") -> MagicMock:
    """Create a minimal ApiKeyRecord stub with the given role."""
    key = MagicMock()
    key.role = role
    key.id = key_id
    return key


def _create_task(engine, group_id: str = "operator", track: str = "vuln",
                 status: str = "queued", user_id: str = "u1") -> str:
    """Insert a TaskRecord and return its id."""
    from aila.platform.tasks.models import TaskRecord

    with Session(engine) as s:
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

    def test_emit_calls_xadd_with_correct_fields(self) -> None:
        """FILE-29: emit() writes stage, message, percent, timestamp to Redis Stream."""
        mock_redis = MagicMock()

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=500)
            ps.emit("task-abc", "inventory", "Scanning hosts", 25)

        mock_redis.xadd.assert_called_once()
        call_args = mock_redis.xadd.call_args
        key = call_args[0][0]
        fields = call_args[0][1]

        assert key == "task:task-abc:progress"
        assert fields["stage"] == "inventory"
        assert fields["message"] == "Scanning hosts"
        assert fields["percent"] == "25"
        assert "timestamp" in fields

    def test_emit_uses_maxlen_with_exact_trim(self) -> None:
        """FILE-29: emit() passes maxlen and approximate=False for exact trim."""
        mock_redis = MagicMock()

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=1000)
            ps.emit("task-abc", "s", "m", 0)

        call_kwargs = mock_redis.xadd.call_args
        assert call_kwargs[1]["maxlen"] == 1000
        assert call_kwargs[1]["approximate"] is False

    def test_emit_maxlen_from_constructor_parameter(self) -> None:
        """FILE-29: Custom maxlen parameter overrides default."""
        mock_redis = MagicMock()

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=42)
            ps.emit("task-1", "s", "m", 0)

        assert mock_redis.xadd.call_args[1]["maxlen"] == 42

    def test_emit_maxlen_from_get_task_tuning_fallback(self) -> None:
        """FILE-29: When maxlen is None, constructor reads from get_task_tuning."""
        mock_redis = MagicMock()

        with patch("redis.Redis.from_url", return_value=mock_redis), \
             patch("aila.platform.tasks.get_task_tuning", return_value=777):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=None)
            ps.emit("task-1", "s", "m", 0)

        assert mock_redis.xadd.call_args[1]["maxlen"] == 777


# ===========================================================================
# Group 2: ProgressStream.catchup() (FILE-29)
# ===========================================================================


class TestProgressStreamCatchup:
    """Prove catchup() returns all events for late-connect replay."""

    def test_catchup_returns_all_events_from_start(self) -> None:
        """FILE-29: catchup(last_id='0') returns full event history."""
        mock_redis = MagicMock()
        mock_redis.xrange.return_value = [
            ("1-0", {"stage": "init", "message": "Starting", "percent": "0", "timestamp": "t1"}),
            ("2-0", {"stage": "scan", "message": "Scanning", "percent": "50", "timestamp": "t2"}),
            ("3-0", {"stage": "done", "message": "Complete", "percent": "100", "timestamp": "t3"}),
        ]

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=1000)
            events = ps.catchup("task-xyz")

        mock_redis.xrange.assert_called_once_with("task:task-xyz:progress", "0", "+")
        assert len(events) == 3
        assert events[0]["stage"] == "init"
        assert events[1]["percent"] == "50"
        assert events[2]["message"] == "Complete"

    def test_catchup_returns_empty_list_when_no_events(self) -> None:
        """FILE-29: catchup() returns [] for task with no progress events."""
        mock_redis = MagicMock()
        mock_redis.xrange.return_value = []

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=1000)
            events = ps.catchup("task-empty")

        assert events == []

    def test_catchup_with_custom_last_id(self) -> None:
        """FILE-29: catchup(last_id='5-0') reads only events after ID 5-0."""
        mock_redis = MagicMock()
        mock_redis.xrange.return_value = [
            ("6-0", {"stage": "s", "message": "m", "percent": "60", "timestamp": "t"}),
        ]

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=1000)
            events = ps.catchup("task-1", last_id="5-0")

        mock_redis.xrange.assert_called_once_with("task:task-1:progress", "5-0", "+")
        assert len(events) == 1


# ===========================================================================
# Group 3: ProgressStream.stream_events() (FILE-29)
# ===========================================================================


class TestProgressStreamStreamEvents:
    """Prove stream_events() yields live events and ping sentinels."""

    def test_stream_events_yields_live_events(self) -> None:
        """FILE-29: stream_events() yields event dicts from XREAD."""
        mock_redis = MagicMock()
        event_data = {"stage": "scan", "message": "In progress", "percent": "30", "timestamp": "t1"}
        # First call returns data, second call we break out
        mock_redis.xread.side_effect = [
            [("task:task-1:progress", [("1-0", event_data)])],
            KeyboardInterrupt,  # break the loop
        ]

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=1000)
            gen = ps.stream_events("task-1")

            result = next(gen)
            assert result == event_data

            with pytest.raises(KeyboardInterrupt):
                next(gen)

    def test_stream_events_yields_ping_on_timeout(self) -> None:
        """FILE-29: stream_events() yields {"type": "ping"} when XREAD times out."""
        mock_redis = MagicMock()
        # First call: empty (timeout), second call: break
        mock_redis.xread.side_effect = [
            [],  # timeout, no data
            KeyboardInterrupt,
        ]

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=1000)
            gen = ps.stream_events("task-1")

            result = next(gen)
            assert result == {"type": "ping"}

    def test_stream_events_advances_current_id(self) -> None:
        """FILE-29: After receiving event '5-0', next XREAD uses '5-0' as current_id."""
        mock_redis = MagicMock()
        event1 = {"stage": "a", "message": "m", "percent": "10", "timestamp": "t"}
        event2 = {"stage": "b", "message": "n", "percent": "20", "timestamp": "t"}
        mock_redis.xread.side_effect = [
            [("task:t:progress", [("5-0", event1)])],
            [("task:t:progress", [("6-0", event2)])],
            KeyboardInterrupt,
        ]

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=1000)
            gen = ps.stream_events("t")

            next(gen)  # event1
            next(gen)  # event2

        # Verify XREAD calls used advancing IDs
        calls = mock_redis.xread.call_args_list
        assert calls[0][0][0] == {"task:t:progress": "0"}   # initial
        assert calls[1][0][0] == {"task:t:progress": "5-0"}  # after first event

    def test_stream_events_uses_xread_block_ms(self) -> None:
        """FILE-29: XREAD block parameter matches XREAD_BLOCK_MS constant."""
        from aila.platform.tasks.constants import XREAD_BLOCK_MS

        mock_redis = MagicMock()
        mock_redis.xread.side_effect = [[], KeyboardInterrupt]

        with patch("redis.Redis.from_url", return_value=mock_redis):
            from aila.platform.tasks.progress import ProgressStream

            ps = ProgressStream("redis://localhost:6379", maxlen=1000)
            gen = ps.stream_events("task-1")
            next(gen)  # trigger first XREAD

        call_kwargs = mock_redis.xread.call_args_list[0][1]
        assert call_kwargs["block"] == XREAD_BLOCK_MS


# ===========================================================================
# Group 4: ProgressStream __all__ exports (FILE-29)
# ===========================================================================


class TestProgressStreamExports:
    """Verify __all__ exports for progress module."""

    def test_progress_all_exports(self) -> None:
        """FILE-29: progress.py exports exactly ['ProgressStream']."""
        from aila.platform.tasks import progress

        assert progress.__all__ == ["ProgressStream"]


# ===========================================================================
# Group 5: TaskRepository.list_for_user scoping (FILE-30)
# ===========================================================================


class TestTaskRepositoryListForUser:
    """Prove list_for_user scopes by group_id for non-admin users."""

    def test_non_admin_sees_only_own_group(self, tmp_path) -> None:
        """FILE-30: Operator only sees tasks with matching group_id."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_list.db'}"
        engine = _make_test_engine(db_url)

        # Create tasks for two groups
        _create_task(engine, group_id="operator", user_id="u1")
        _create_task(engine, group_id="operator", user_id="u2")
        _create_task(engine, group_id="reader", user_id="u3")

        key = _make_api_key(role="operator")
        with Session(engine) as s:
            results = TaskRepository.list_for_user(s, key)

        assert len(results) == 2
        for r in results:
            assert r.group_id == "operator"

    def test_admin_sees_all_tasks(self, tmp_path) -> None:
        """FILE-30: Admin user sees all tasks regardless of group_id."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_admin.db'}"
        engine = _make_test_engine(db_url)

        _create_task(engine, group_id="operator")
        _create_task(engine, group_id="reader")
        _create_task(engine, group_id="admin")

        key = _make_api_key(role="admin")
        with Session(engine) as s:
            results = TaskRepository.list_for_user(s, key)

        assert len(results) == 3

    def test_filter_by_track(self, tmp_path) -> None:
        """FILE-30: list_for_user with track filter returns only matching tasks."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_track.db'}"
        engine = _make_test_engine(db_url)

        _create_task(engine, track="vuln", group_id="operator")
        _create_task(engine, track="network", group_id="operator")

        key = _make_api_key(role="operator")
        with Session(engine) as s:
            results = TaskRepository.list_for_user(s, key, track="vuln")

        assert len(results) == 1
        assert results[0].track == "vuln"

    def test_filter_by_status(self, tmp_path) -> None:
        """FILE-30: list_for_user with status filter returns only matching tasks."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_status.db'}"
        engine = _make_test_engine(db_url)

        _create_task(engine, status="queued", group_id="operator")
        _create_task(engine, status="running", group_id="operator")
        _create_task(engine, status="done", group_id="operator")

        key = _make_api_key(role="operator")
        with Session(engine) as s:
            results = TaskRepository.list_for_user(s, key, status="running")

        assert len(results) == 1
        assert results[0].status == "running"

    def test_combined_track_and_status_filter(self, tmp_path) -> None:
        """FILE-30: list_for_user with both track and status returns intersection."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_combined.db'}"
        engine = _make_test_engine(db_url)

        _create_task(engine, track="vuln", status="queued", group_id="operator")
        _create_task(engine, track="vuln", status="done", group_id="operator")
        _create_task(engine, track="network", status="queued", group_id="operator")

        key = _make_api_key(role="operator")
        with Session(engine) as s:
            results = TaskRepository.list_for_user(s, key, track="vuln", status="queued")

        assert len(results) == 1
        assert results[0].track == "vuln"
        assert results[0].status == "queued"


# ===========================================================================
# Group 6: TaskRepository.get_for_user scoping (FILE-30)
# ===========================================================================


class TestTaskRepositoryGetForUser:
    """Prove get_for_user scopes by group_id and admin bypass."""

    def test_operator_cannot_see_other_group_task(self, tmp_path) -> None:
        """FILE-30: Operator cannot get a task belonging to a different group."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_get_scope.db'}"
        engine = _make_test_engine(db_url)

        admin_task_id = _create_task(engine, group_id="admin")

        key = _make_api_key(role="operator")
        with Session(engine) as s:
            result = TaskRepository.get_for_user(s, admin_task_id, key)

        assert result is None, "Operator must NOT see admin's task"

    def test_admin_can_see_any_task(self, tmp_path) -> None:
        """FILE-30: Admin can see tasks from any group."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_get_admin.db'}"
        engine = _make_test_engine(db_url)

        operator_task_id = _create_task(engine, group_id="operator")

        key = _make_api_key(role="admin")
        with Session(engine) as s:
            result = TaskRepository.get_for_user(s, operator_task_id, key)

        assert result is not None
        assert result.id == operator_task_id

    def test_returns_none_for_nonexistent_task(self, tmp_path) -> None:
        """FILE-30: get_for_user returns None for non-existent task_id."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_get_none.db'}"
        engine = _make_test_engine(db_url)

        key = _make_api_key(role="admin")
        with Session(engine) as s:
            result = TaskRepository.get_for_user(s, "nonexistent-id", key)

        assert result is None

    def test_operator_sees_own_group_task(self, tmp_path) -> None:
        """FILE-30: Operator can see task with matching group_id."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_get_own.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, group_id="operator")

        key = _make_api_key(role="operator")
        with Session(engine) as s:
            result = TaskRepository.get_for_user(s, task_id, key)

        assert result is not None
        assert result.id == task_id


# ===========================================================================
# Group 7: TaskRepository state transitions (FILE-30)
# ===========================================================================


class TestTaskRepositorySetPaused:
    """Prove set_paused transitions RUNNING -> PAUSED."""

    def test_running_to_paused(self, tmp_path) -> None:
        """FILE-30: set_paused transitions RUNNING task to PAUSED."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_pause.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="running", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_paused(s, task_id, key)

        assert result is True

        with Session(engine) as s:
            from aila.platform.tasks.models import TaskRecord
            rec = s.get(TaskRecord, task_id)
            assert rec.status == "paused"

    def test_paused_returns_false_for_non_running(self, tmp_path) -> None:
        """FILE-30: set_paused returns False for queued task (not RUNNING)."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_pause_fail.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="queued", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_paused(s, task_id, key)

        assert result is False

    def test_paused_returns_false_for_other_group(self, tmp_path) -> None:
        """FILE-30: set_paused returns False when operator tries to pause admin's task."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_pause_scope.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="running", group_id="admin")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_paused(s, task_id, key)

        assert result is False, "Operator must not pause admin's task"


class TestTaskRepositorySetQueuedFromPaused:
    """Prove set_queued_from_paused transitions PAUSED -> QUEUED."""

    def test_paused_to_queued(self, tmp_path) -> None:
        """FILE-30: set_queued_from_paused transitions PAUSED task to QUEUED."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_unpause.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="paused", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_queued_from_paused(s, task_id, key)

        assert result is True

        with Session(engine) as s:
            from aila.platform.tasks.models import TaskRecord
            rec = s.get(TaskRecord, task_id)
            assert rec.status == "queued"

    def test_queued_from_paused_returns_false_for_non_paused(self, tmp_path) -> None:
        """FILE-30: set_queued_from_paused returns False for RUNNING task."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_unpause_fail.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="running", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_queued_from_paused(s, task_id, key)

        assert result is False


class TestTaskRepositorySetCancelled:
    """Prove set_cancelled marks non-terminal task as CANCELLED."""

    def test_queued_to_cancelled(self, tmp_path) -> None:
        """FILE-30: set_cancelled transitions QUEUED task to CANCELLED."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_cancel.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="queued", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_cancelled(s, task_id, key)

        assert result is True

        with Session(engine) as s:
            from aila.platform.tasks.models import TaskRecord
            rec = s.get(TaskRecord, task_id)
            assert rec.status == "cancelled"

    def test_running_to_cancelled(self, tmp_path) -> None:
        """FILE-30: set_cancelled transitions RUNNING task to CANCELLED."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_cancel_run.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="running", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_cancelled(s, task_id, key)

        assert result is True

    def test_cancelled_returns_false_for_done_task(self, tmp_path) -> None:
        """FILE-30: set_cancelled returns False for already DONE task (terminal)."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_cancel_done.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="done", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_cancelled(s, task_id, key)

        assert result is False

    def test_cancelled_returns_false_for_failed_task(self, tmp_path) -> None:
        """FILE-30: set_cancelled returns False for FAILED task (terminal)."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_cancel_failed.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="failed", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_cancelled(s, task_id, key)

        assert result is False

    def test_cancelled_returns_false_for_already_cancelled(self, tmp_path) -> None:
        """FILE-30: set_cancelled returns False for already CANCELLED task."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_cancel_dup.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, status="cancelled", group_id="operator")
        key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_cancelled(s, task_id, key)

        assert result is False


# ===========================================================================
# Group 8: Cross-user isolation (FILE-30)
# ===========================================================================


class TestCrossUserIsolation:
    """Prove cross-user data leak is impossible through TaskRepository."""

    def test_operator_a_invisible_to_operator_b(self, tmp_path) -> None:
        """FILE-30: Tasks created by operator (group_id=operator) are visible
        to users with the same group_id but NOT to users with different group_id."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_isolation.db'}"
        engine = _make_test_engine(db_url)

        # Operator group tasks
        op_task_id = _create_task(engine, group_id="operator", user_id="op-user-1")
        # Reader group tasks
        rd_task_id = _create_task(engine, group_id="reader", user_id="rd-user-1")

        # Operator key -- should see only operator tasks
        op_key = _make_api_key(role="operator")
        with Session(engine) as s:
            op_list = TaskRepository.list_for_user(s, op_key)
            assert len(op_list) == 1
            assert op_list[0].id == op_task_id

        # Reader key -- should see only reader tasks
        rd_key = _make_api_key(role="reader")
        with Session(engine) as s:
            rd_list = TaskRepository.list_for_user(s, rd_key)
            assert len(rd_list) == 1
            assert rd_list[0].id == rd_task_id

        # Cross-access: operator cannot get reader's task
        with Session(engine) as s:
            cross = TaskRepository.get_for_user(s, rd_task_id, op_key)
            assert cross is None, "Operator must NOT see reader's task via get_for_user"

        # Cross-access: reader cannot get operator's task
        with Session(engine) as s:
            cross = TaskRepository.get_for_user(s, op_task_id, rd_key)
            assert cross is None, "Reader must NOT see operator's task via get_for_user"

    def test_cross_group_set_paused_blocked(self, tmp_path) -> None:
        """FILE-30: Operator cannot pause a reader's RUNNING task."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_cross_pause.db'}"
        engine = _make_test_engine(db_url)

        reader_task_id = _create_task(engine, group_id="reader", status="running")
        op_key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_paused(s, reader_task_id, op_key)

        assert result is False, "Cross-group pause must be blocked"

    def test_cross_group_set_cancelled_blocked(self, tmp_path) -> None:
        """FILE-30: Operator cannot cancel a reader's task."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_cross_cancel.db'}"
        engine = _make_test_engine(db_url)

        reader_task_id = _create_task(engine, group_id="reader", status="queued")
        op_key = _make_api_key(role="operator")

        with Session(engine) as s:
            result = TaskRepository.set_cancelled(s, reader_task_id, op_key)

        assert result is False, "Cross-group cancel must be blocked"

    def test_admin_can_operate_on_any_group(self, tmp_path) -> None:
        """FILE-30: Admin can pause, resume, and cancel tasks from any group."""
        from aila.platform.tasks.storage import TaskRepository

        db_url = f"sqlite:///{tmp_path / 'repo_admin_ops.db'}"
        engine = _make_test_engine(db_url)

        task_id = _create_task(engine, group_id="reader", status="running")
        admin_key = _make_api_key(role="admin")

        # Admin pauses reader's running task
        with Session(engine) as s:
            result = TaskRepository.set_paused(s, task_id, admin_key)
        assert result is True

        # Admin resumes it
        with Session(engine) as s:
            result = TaskRepository.set_queued_from_paused(s, task_id, admin_key)
        assert result is True

        # Admin cancels it
        with Session(engine) as s:
            result = TaskRepository.set_cancelled(s, task_id, admin_key)
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
