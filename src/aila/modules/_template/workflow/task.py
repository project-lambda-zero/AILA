"""Template investigation task-function scaffold (RFC-02).

This file is the copy-me stub for the ARQ-callable task function that the
investigation lifecycle enqueues. The real thing is a ``@platform_task``-
decorated ``async def`` whose body is a single ``...`` and whose behavior
is driven entirely by the ``definition=`` kwarg the decorator receives.
See ``aila.modules.vr.workflow.task.run_vr_investigate`` for the
production shape.

Scaffold constraints
--------------------
* Plain ``async def`` (not decorated with ``@platform_task``). The scaffold
  intentionally does NOT register with the platform ARQ task registry --
  that registration runs at import time and would collide with a live
  ``run_<module>_investigate`` if this scaffold is ever imported. A real
  module replaces the body below with ``@platform_task(..., definition=...)``
  above the ``async def`` and re-exports it from ``workflow/task.py`` so
  the worker bootstrap picks it up.
* The signature is what the lifecycle service and persona-spawn helper
  call the task_fn with when they submit through ``TaskQueue.submit``.
  The kwargs list is intentionally minimal here; add investigation-
  specific kwargs (branch id, kind, strategy, etc.) as the module grows.
"""
from __future__ import annotations

from typing import Any

__all__ = ["run_template_investigate"]


async def run_template_investigate(
    ctx: dict[str, Any],
    **kwargs: Any,
) -> dict[str, Any]:
    """Scaffold task-function stub.

    A real module replaces this with the ``@platform_task``-decorated
    version bound to the module's ``WorkflowDefinition`` so the platform
    dispatch path drives the engine instead of executing this body. The
    return contract is a JSON-serialisable dict; the platform layer
    threads it back into the ``TaskRecord.result_payload_json``.
    """
    del ctx, kwargs
    return {"status": "template_scaffold_no_op"}
