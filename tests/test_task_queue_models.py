"""Tests for platform task queue data models (Phase 54, Plan 01).

TDD RED phase: These tests verify the foundational data contracts for the
task queue infrastructure -- TaskRecord, TaskStatus, TaskHandle,
TaskExecutionContext, and ProgressEvent.
"""

from __future__ import annotations

import json
from datetime import datetime
from unittest.mock import MagicMock

import pytest


class TestTaskStatus:
    """TaskStatus is a str enum with exactly 7 lifecycle values."""

    def test_all_seven_status_values_exist(self) -> None:
        from aila.platform.tasks import TaskStatus

        expected = {"queued", "waiting", "running", "paused", "done", "failed", "cancelled"}
        assert set(TaskStatus) == expected

    def test_task_status_is_str(self) -> None:
        from aila.platform.tasks import TaskStatus

        assert isinstance(TaskStatus.QUEUED, str)
        assert TaskStatus.QUEUED == "queued"

    def test_task_status_values(self) -> None:
        from aila.platform.tasks import TaskStatus

        assert TaskStatus.QUEUED == "queued"
        assert TaskStatus.WAITING == "waiting"
        assert TaskStatus.RUNNING == "running"
        assert TaskStatus.PAUSED == "paused"
        assert TaskStatus.DONE == "done"
        assert TaskStatus.FAILED == "failed"
        assert TaskStatus.CANCELLED == "cancelled"


class TestTaskRecord:
    """TaskRecord is a SQLModel table with required lifecycle columns."""

    def test_task_record_tablename(self) -> None:
        from aila.platform.tasks import TaskRecord

        assert TaskRecord.__tablename__ == "taskrecord"

    def test_task_record_has_uuid_pk(self) -> None:
        from aila.platform.tasks import TaskRecord

        record = TaskRecord(
            track="vuln",
            fn_path="aila.modules.vulnerability.tasks.scan",
            fn_module="aila.modules.vulnerability.tasks",
            user_id="user-uuid-1",
            group_id="operator",
        )
        assert isinstance(record.id, str)
        assert len(record.id) == 36  # UUID format

    def test_task_record_default_status_is_queued(self) -> None:
        from aila.platform.tasks import TaskRecord, TaskStatus

        record = TaskRecord(
            track="vuln",
            fn_path="aila.modules.vulnerability.tasks.scan",
            fn_module="aila.modules.vulnerability.tasks",
            user_id="user-uuid-1",
            group_id="operator",
        )
        assert record.status == TaskStatus.QUEUED

    def test_task_record_required_columns_exist(self) -> None:
        from aila.platform.tasks import TaskRecord

        record = TaskRecord(
            track="vuln",
            fn_path="aila.modules.vulnerability.tasks.scan",
            fn_module="aila.modules.vulnerability.tasks",
            user_id="user-uuid-1",
            group_id="operator",
        )
        # Required string columns
        assert record.track == "vuln"
        assert record.fn_path == "aila.modules.vulnerability.tasks.scan"
        assert record.fn_module == "aila.modules.vulnerability.tasks"
        assert record.user_id == "user-uuid-1"
        assert record.group_id == "operator"

    def test_task_record_nullable_columns_default_none(self) -> None:
        from aila.platform.tasks import TaskRecord

        record = TaskRecord(
            track="vuln",
            fn_path="aila.modules.vulnerability.tasks.scan",
            fn_module="aila.modules.vulnerability.tasks",
            user_id="user-uuid-1",
            group_id="operator",
        )
        # INFRA-06: result_path stores file path, not blob
        assert record.result_path is None
        # Phase 179: legacy cursor column dropped; state lives in
        # workflow_state_cursor (migration 023).
        assert record.error is None
        assert record.depends_on_json is None
        assert record.started_at is None
        assert record.heartbeat_at is None
        assert record.completed_at is None

    def test_task_record_timestamps_auto_populated(self) -> None:
        from aila.platform.tasks import TaskRecord

        record = TaskRecord(
            track="vuln",
            fn_path="aila.modules.vulnerability.tasks.scan",
            fn_module="aila.modules.vulnerability.tasks",
            user_id="user-uuid-1",
            group_id="operator",
        )
        assert isinstance(record.created_at, datetime)
        assert isinstance(record.updated_at, datetime)

    def test_task_record_kwargs_json_defaults_empty_dict(self) -> None:
        from aila.platform.tasks import TaskRecord

        record = TaskRecord(
            track="vuln",
            fn_path="aila.modules.vulnerability.tasks.scan",
            fn_module="aila.modules.vulnerability.tasks",
            user_id="user-uuid-1",
            group_id="operator",
        )
        assert record.kwargs_json == "{}"
        assert json.loads(record.kwargs_json) == {}

    def test_task_record_in_sqlmodel_metadata(self) -> None:
        from sqlmodel import SQLModel

        # Import db_models to trigger SQLModel metadata registration
        import aila.storage.db_models  # noqa: F401  # side-effect import

        assert "taskrecord" in SQLModel.metadata.tables


class TestTaskHandle:
    """TaskHandle is a frozen dataclass wrapping task_id for status polling."""

    def test_task_handle_is_frozen(self) -> None:
        from aila.platform.tasks import TaskHandle

        handle = TaskHandle(task_id="abc-123")
        with pytest.raises((AttributeError, TypeError)):
            handle.task_id = "other"  # type: ignore[misc]

    def test_task_handle_task_id(self) -> None:
        from aila.platform.tasks import TaskHandle

        handle = TaskHandle(task_id="test-task-id")
        assert handle.task_id == "test-task-id"


class TestProgressEvent:
    """ProgressEvent carries task progress signals to Redis Streams."""

    def test_progress_event_fields(self) -> None:
        from aila.platform.tasks import ProgressEvent

        event = ProgressEvent(
            task_id="t-001",
            stage="scanning",
            message="Collecting packages",
            percent=25,
        )
        assert event.task_id == "t-001"
        assert event.stage == "scanning"
        assert event.message == "Collecting packages"
        assert event.percent == 25
        assert isinstance(event.timestamp, datetime)

    def test_progress_event_is_frozen(self) -> None:
        from aila.platform.tasks import ProgressEvent

        event = ProgressEvent(
            task_id="t-001",
            stage="scanning",
            message="msg",
            percent=10,
        )
        with pytest.raises((AttributeError, TypeError)):
            event.percent = 50  # type: ignore[misc]


class TestTaskExecutionContext:
    """TaskExecutionContext carries the runtime injection context for background tasks."""

    def test_task_execution_context_required_fields(self) -> None:
        from aila.platform.tasks import TaskExecutionContext

        session_factory = MagicMock()
        ctx = TaskExecutionContext(task_id="t-001", session_factory=session_factory)
        assert ctx.task_id == "t-001"
        assert ctx.session_factory is session_factory

    def test_task_execution_context_defaults(self) -> None:
        from aila.platform.tasks import TaskExecutionContext

        ctx = TaskExecutionContext(task_id="t-001", session_factory=lambda: None)
        assert ctx.emitter is None
        assert ctx.memory_store is None
        assert ctx.settings is None
        assert ctx.is_cancelled is False

    def test_checkpoint_method_calls_checkpoint_fn(self) -> None:
        from aila.platform.tasks import TaskExecutionContext

        received: list[dict] = []

        ctx = TaskExecutionContext(
            task_id="t-001",
            session_factory=lambda: None,
            _checkpoint_fn=received.append,
        )
        ctx.checkpoint({"step": 3, "data": "partial"})
        assert received == [{"step": 3, "data": "partial"}]

    def test_checkpoint_method_is_noop_when_fn_not_set(self) -> None:
        from aila.platform.tasks import TaskExecutionContext

        ctx = TaskExecutionContext(task_id="t-001", session_factory=lambda: None)
        # Should not raise even with no _checkpoint_fn wired
        ctx.checkpoint({"step": 1})

    def test_is_cancelled_can_be_set(self) -> None:
        from aila.platform.tasks import TaskExecutionContext

        ctx = TaskExecutionContext(task_id="t-001", session_factory=lambda: None)
        ctx.is_cancelled = True
        assert ctx.is_cancelled is True


class TestPackageExports:
    """All public symbols are exported from aila.platform.tasks."""

    def test_all_five_exports_importable(self) -> None:
        from aila.platform.tasks import (
            ProgressEvent,
            TaskExecutionContext,
            TaskHandle,
            TaskRecord,
            TaskStatus,
        )

        assert TaskRecord is not None
        assert TaskStatus is not None
        assert TaskHandle is not None
        assert TaskExecutionContext is not None
        assert ProgressEvent is not None
