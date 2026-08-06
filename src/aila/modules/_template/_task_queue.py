"""Template task-queue factory used by workers to submit follow-up jobs.

Mirrors :mod:`aila.modules.vr._task_queue`. The outcome dispatcher and
the emit state's auto-continue path submit tasks from inside a running
worker (no FastAPI :class:`Request` available), so we build a
:class:`TaskQueue` directly from :class:`ConfigRegistry` here rather
than reaching for ``aila.api.deps.get_task_queue``.
"""
from __future__ import annotations

from typing import Any

from aila.platform.tasks.queue import TaskQueue
from aila.storage.registry import ConfigRegistry

__all__ = ["default_task_queue"]


def default_task_queue() -> Any:
    """Construct a platform :class:`TaskQueue` bound to the template module."""
    return TaskQueue(config_registry=ConfigRegistry(), module_id="template")
