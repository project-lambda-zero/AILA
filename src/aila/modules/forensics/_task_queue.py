"""Helpers for enqueueing forensics background tasks from worker contexts.

Introduced in #18. The panel spawn (:func:`spawn_persona_siblings`) needs
a ``TaskQueue`` to enqueue per-sibling worker tasks; it runs inside an
ARQ worker (not a FastAPI request) so it cannot depend on
``aila.api.deps.get_task_queue`` (which needs a Request).

Mirrors :mod:`aila.modules.vr._task_queue` and
:mod:`aila.modules.malware._task_queue` -- one thin factory that binds
the platform :class:`TaskQueue` to the ``forensics`` module id.
"""
from __future__ import annotations

from typing import Any

from aila.platform.tasks.queue import TaskQueue
from aila.storage.registry import ConfigRegistry

__all__ = ["default_task_queue"]


def default_task_queue() -> Any:
    """Construct a platform TaskQueue bound to the ``forensics`` module."""
    return TaskQueue(
        config_registry=ConfigRegistry(),
        module_id="forensics",
    )
