"""Platform task queue infrastructure -- public API surface.

Phase 179 rewrite. Re-exports the new template primitives
(``@platform_task``, :class:`TaskContext`, :class:`WorkflowMigratedError`)
alongside the existing persistence / submission contracts.

Module entry-point files are imported by
tasks/worker.py:_bootstrap_platform_tasks() at worker start so
``@platform_task`` decorators execute once before
``WorkerSettings.functions`` is read.
"""

from __future__ import annotations

import logging

from sqlalchemy.exc import SQLAlchemyError

from .context import TaskContext
from .errors import WorkflowMigratedError
from .models import (
    ProgressEvent,
    TaskExecutionContext,
    TaskHandle,
    TaskRecord,
    TaskStatus,
)
from .queue import TaskQueue
from .template import platform_task

_log = logging.getLogger(__name__)

# Phase 179 registry bootstrap:
# Modules that declare @platform_task handlers register themselves at
# module import time. The bootstrap lives in :mod:`aila.platform.tasks.worker`
# (invoked at ARQ worker start) rather than here, because importing
# router modules from this package init triggers a circular chain via
# ``db_models.py``. worker.py:_bootstrap_platform_tasks() discovers
# per-module entry points dynamically.

__all__ = [
    "ProgressEvent",
    "TaskContext",
    "TaskExecutionContext",
    "TaskHandle",
    "TaskQueue",
    "TaskRecord",
    "TaskStatus",
    "WorkflowMigratedError",
    "get_task_tuning",
    "platform_task",
]


def get_task_tuning(key: str, default: int) -> int:
    """Return a task-queue tuning knob, reading namespace='platform' config live.

    Resolves the ConfigEntryRecord row (namespace='platform', ``key``) through the
    synchronous ConfigRegistry path (``get_sync`` -> psycopg ``session_scope``),
    which is safe from sync call sites and from worker startup (no event loop, no
    ``asyncio.run`` -- the crash mode the old deferral guarded against). A fresh
    registry instance is used per call so no in-memory cache masks a live config
    change (XCUT-14). Falls back to the compiled ``default`` when the value is
    unset, uncastable, or the DB is unreachable (e.g. bootstrap before the DB is
    configured).
    """
    # Deferred import: importing the registry at module top pulls db_models and
    # forms an import cycle through the tasks package init.
    from aila.storage.registry import ConfigRegistry

    try:
        value = ConfigRegistry().get_sync("platform", key)
    except (OSError, RuntimeError, ValueError, TypeError, SQLAlchemyError):
        return default
    if value is None:
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
