"""Tests for platform task queue data models (Phase 54, Plan 01).

TDD RED phase: These tests verify the foundational data contracts for the
task queue infrastructure -- TaskRecord, TaskStatus, TaskHandle,
TaskExecutionContext, and ProgressEvent.
"""

from __future__ import annotations

from datetime import datetime

import pytest


class TestTaskStatus:
    """TaskStatus is a str enum with exactly 7 lifecycle values."""


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


class TestProgressEvent:
    """ProgressEvent carries task progress signals to Redis Streams."""


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


