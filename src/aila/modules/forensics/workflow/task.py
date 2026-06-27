"""Platform task entry points for forensics workflows.

Both functions are pure seed stubs decorated with ``@platform_task``.
All platform orchestration (WorkflowRunRecord creation, plan_json writes,
DurableStateMachine execution, inner definition resolution) is owned by
``@platform_task`` via ``_run_two_phase_dispatch`` when
``definition.is_dispatcher=True`` -- the same pattern used by the
vulnerability module (Phase 183).

This satisfies the v5.0 core principle: modules write pure state handlers
and nothing else.
"""
from __future__ import annotations

from typing import Any

from aila.modules.forensics.workflow.definitions import FORENSICS_DISPATCHER_V1
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_forensics_analysis", "run_forensics_investigation"]


@platform_task(
    track="forensics",
    module_id="forensics",
    max_tries=3,
    timeout_s=10800.0,
    definition=FORENSICS_DISPATCHER_V1,
)
async def run_forensics_analysis(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed -- platform dispatch handles two-phase execution via FORENSICS_DISPATCHER_V1."""
    ...


@platform_task(
    track="forensics",
    module_id="forensics",
    max_tries=3,
    timeout_s=7200.0,
    definition=FORENSICS_DISPATCHER_V1,
)
async def run_forensics_investigation(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed -- platform dispatch handles two-phase execution via FORENSICS_DISPATCHER_V1."""
    ...
