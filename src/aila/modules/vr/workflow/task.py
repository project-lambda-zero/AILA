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

from aila.modules.vr.workflow.definitions import VR_INVESTIGATE_V1, VR_NDAY_V1
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_target_analysis", "run_vr_investigate", "run_vr_nday"]


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


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=1,
    timeout_s=7800.0,  # 2h+ — covers a full investigation_loop run
    definition=VR_INVESTIGATE_V1,
)
async def run_vr_investigate(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed — platform dispatch handles workflow execution via VR_INVESTIGATE_V1.

    Required kwarg: ``investigation_id``. The setup state resolves the
    primary branch from the DB; operator does not provide branch_id.
    """
    ...


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=1800.0,  # 30 min — covers a clone + index + poll cycle
)
async def run_target_analysis(
    ctx: TaskContext,
    target_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Backend ingestion for one target. Idempotent.

    Calls audit_mcp.index_codebase or ida.upload depending on kind,
    polls until ready, stores backend handles + auto-detected language
    on the row, and transitions analysis_state through INGESTING → READY
    (or → FAILED with operator-visible message).
    """
    del ctx
    from aila.modules.vr.services import TargetAnalysisService  # noqa: PLC0415  (lazy: avoids cycle)

    svc = TargetAnalysisService()
    await svc.analyze(target_id)
    return {"target_id": target_id, "status": "ok"}
