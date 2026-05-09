"""Platform task queue infrastructure — public API surface.

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
    """Return the compiled default for a task queue tuning knob.

    The ``key`` parameter names a ConfigEntryRecord row (namespace='platform')
    that a future async-capable path can read at runtime. During worker startup
    and module import there is no event loop, so attempting ``asyncio.run()``
    creates stale asyncpg connections that crash ARQ on Windows. Until an async
    caller is wired, this always returns the compiled ``default``.
    """
    _ = key  # reserved for future DB-backed override
    return default
