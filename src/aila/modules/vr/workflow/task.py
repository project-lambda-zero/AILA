"""Platform task entry point for the VR (vulnerability research) workflow.

The function is a pure seed stub decorated with ``@platform_task``.
All platform orchestration (WorkflowRunRecord creation, plan_json writes,
DurableStateMachine execution, state transitions) is owned by
``@platform_task`` via the workflow-engine dispatch path when a
``definition`` is supplied — the same pattern used by the forensics and
vulnerability modules.

This satisfies the v5.0 core principle: modules write pure state handlers
and nothing else.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.workflow.definitions import VR_NDAY_V1
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_vr_nday"]


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=10800.0,  # 3 hours — covers full setup -> research -> PoC -> advisory
    definition=VR_NDAY_V1,
)
async def run_vr_nday(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed — platform dispatch handles workflow execution via VR_NDAY_V1."""
    ...
