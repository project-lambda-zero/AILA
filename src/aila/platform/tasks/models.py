"""Platform task queue data model definitions.

Phase 179 rewrite: legacy per-row retry counter and in-row cursor column
are REMOVED from TaskRecord. ``ctx['job_try']`` replaces the former; the
workflow cursor table (migration 023) replaces the latter.
``TaskExecutionContext.checkpoint()`` is removed -- handlers that still
need a per-run cursor should use the Phase 178 engine.

Ownership: Platform -- not module-specific.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from typing import TYPE_CHECKING
from uuid import uuid4

import sqlalchemy as sa
from sqlalchemy import Column, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now
from aila.storage.mixins import TeamScopedMixin

if TYPE_CHECKING:
    from aila.platform.config import ApplicationSettings
    from aila.platform.events import EventEmitter
    from aila.storage.memory import PermanentMemoryStore

__all__ = [
    "ProgressEvent",
    "TaskExecutionContext",
    "TaskHandle",
    "TaskRecord",
    "TaskStatus",
]


class TaskStatus(StrEnum):
    """Lifecycle enum for platform task records.

    Phase 179: ``paused`` is retained for schema compatibility only; no
    Phase 179 code path transitions into or out of it. The durable
    workflows engine (Phase 178) owns pause semantics via its cursor
    table, not this enum.
    """

    QUEUED = "queued"
    WAITING = "waiting"
    RUNNING = "running"
    PAUSED = "paused"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"
    DEAD_LETTER = "dead_letter"


class TaskRecord(TeamScopedMixin, SQLModel, table=True):
    """Platform-owned task lifecycle record.

    Written by ``TaskQueue.submit``; updated by the ARQ hook layer on
    state transitions. ``user_id`` comes from ApiKeyRecord.id; ``group_id``
    from ApiKeyRecord.role (MOD-13). ``result_path`` stores a file-system
    path to the task output (INFRA-06). ``kwargs_json`` is the enqueue
    payload. ``depends_on_json`` is a JSON list of task_id strings for
    dependency ordering (TASK-12).
    """

    __tablename__ = "taskrecord"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    track: str = Field(sa_column=Column(Text, index=True))
    fn_path: str = Field(sa_column=Column(Text))
    fn_module: str = Field(sa_column=Column(Text, index=True))
    status: str = Field(
        default=TaskStatus.QUEUED,
        sa_column=Column(Text, server_default="queued", index=True),
    )
    user_id: str = Field(sa_column=Column(Text, index=True))
    group_id: str = Field(sa_column=Column(Text, index=True))
    kwargs_json: str = Field(default="{}", sa_column=Column(Text, server_default="{}"))
    result_path: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    error: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    depends_on_json: str | None = Field(default=None, sa_column=Column(Text, nullable=True))
    input_hash: str | None = Field(default=None, sa_column=Column(Text, nullable=True, index=True))
    version: int = Field(default=1, sa_column=Column(sa.Integer, server_default="1", nullable=False))
    started_at: datetime | None = Field(default=None, sa_column=Column(sa.DateTime(timezone=True), nullable=True))
    heartbeat_at: datetime | None = Field(default=None, sa_column=Column(sa.DateTime(timezone=True), nullable=True))
    completed_at: datetime | None = Field(default=None, sa_column=Column(sa.DateTime(timezone=True), nullable=True))
    created_at: datetime = Field(default_factory=utc_now, sa_column=Column(sa.DateTime(timezone=True), nullable=False))
    updated_at: datetime = Field(default_factory=utc_now, sa_column=Column(sa.DateTime(timezone=True), nullable=False))


@dataclass(frozen=True, slots=True)
class TaskHandle:
    """Returned by TaskQueue.submit(); wraps task_id for status polling."""

    task_id: str


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """Progress event emitted to Redis Streams by background tasks."""

    task_id: str
    stage: str
    message: str
    percent: int
    timestamp: datetime = field(default_factory=utc_now)


@dataclass(frozen=False, slots=False)
class TaskExecutionContext:
    """Legacy runtime context for single-stage tasks (pre-Phase 179).

    Phase 179: ``checkpoint()`` and the ``_checkpoint_fn`` slot are
    REMOVED. Remaining callers should migrate to :class:`TaskContext`
    from :mod:`aila.platform.tasks.context` (Phase 180).
    """

    task_id: str
    session_factory: Callable[[], object]
    emitter: EventEmitter | None = None
    memory_store: PermanentMemoryStore | None = None
    settings: ApplicationSettings | None = None
    is_cancelled: bool = False
