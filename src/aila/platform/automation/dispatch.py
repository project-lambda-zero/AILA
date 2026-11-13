"""Worker-side execution of scheduled automation actions.

:class:`~aila.platform.automation.runner.AutomationRunner` submits every due
schedule as this one registered ``@platform_task`` on the ``default`` queue,
which the default worker consumes. The worker resolves the schedule's action
id through the platform automation registry and awaits the handler. Action
handlers stay plain callables; only :func:`run_automation_action` is an ARQ
function, so adding an action never requires a worker queue or task entry.
"""
from __future__ import annotations

__all__ = ["AUTOMATION_TRACK", "run_automation_action"]

import inspect
from typing import Any

from aila.platform.automation.maintenance import register_maintenance_actions
from aila.platform.automation.registry import AutomationRegistry
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

# The queue ``python -m aila worker`` consumes when started without ``-q``;
# the default ``start.sh`` worker set includes it.
AUTOMATION_TRACK: str = "default"


@platform_task(
    track=AUTOMATION_TRACK,
    module_id="__platform__",
    max_tries=1,
    timeout_s=3600.0,
)
async def run_automation_action(
    ctx: TaskContext,
    *,
    action_id: str,
    action_kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Run the handler registered under ``action_id`` with the schedule kwargs.

    The registry is built from the same registration the API process uses, so
    an action the runner accepted resolves here. An action id that is not
    registered raises ``KeyError`` and fails the task.
    """
    del ctx  # identity and team scope are bound by the platform_task wrapper
    registry = AutomationRegistry()
    register_maintenance_actions(registry)
    action = registry.require_action(action_id)
    result = action.handler_fn(**action_kwargs)
    if inspect.isawaitable(result):
        result = await result
    return {"action_id": action_id, "result": result}
