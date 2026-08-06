"""Platform task entry point for the forensics panel investigation (#18).

Module-prefixed task name (``run_forensics_panel_investigate``) so it
does not collide with :func:`aila.modules.vr.workflow.task.run_vr_investigate`
or :func:`aila.modules.malware.workflow.task.run_malware_investigate` on the
``@platform_task`` ARQ registry (RFC-00 Common Mistake #19).

The task is a pure seed stub -- all orchestration (WorkflowRunRecord
creation, DurableStateMachine execution, cursor persistence,
retries) is owned by ``@platform_task`` bound to the panel definition.
"""
from __future__ import annotations

from typing import Any

from aila.modules.forensics.workflow.panel.definitions import (
    FORENSICS_INVESTIGATE_PANEL_V1,
)
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_forensics_panel_investigate"]


@platform_task(
    track="forensics",
    module_id="forensics",
    max_tries=3,
    timeout_s=7200.0,
    definition=FORENSICS_INVESTIGATE_PANEL_V1,
)
async def run_forensics_panel_investigate(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed -- panel dispatch is owned by ``@platform_task``."""
    ...
