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

# Re-export enrichment-pipeline tasks so the platform worker bootstrap
# (which loads only ``<module>/workflow/task.py``) picks them up and
# registers them with the ARQ function table. Without these re-exports
# the API can enqueue rank/profile jobs but the worker rejects them
# with ``function 'run_function_ranking' not found``.
from aila.modules.vr.enrichment.workers import (  # noqa: F401  (re-export for ARQ registration)
    run_capability_profile_build,
    run_function_ranking,
)
from aila.modules.vr.workflow.definitions import VR_INVESTIGATE_V1, VR_NDAY_V1
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = [
    "run_capability_profile_build",
    "run_function_ranking",
    "run_fuzz_campaign_launch",
    "run_target_analysis",
    "run_vr_investigate",
    "run_vr_nday",
]


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


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=1,
    timeout_s=120.0,  # SSH connect + start fuzzer; not the campaign itself
)
async def run_fuzz_campaign_launch(
    ctx: TaskContext,
    campaign_id: str,
    **_: Any,
) -> dict[str, Any]:
    """SSH to the campaign's analysis_system_id workstation, start
    the fuzzer per its engine_id, capture remote PID + corpus/crashes
    paths back onto the campaign row.

    Per D-33 the workstation is dedicated — AILA never runs the
    fuzzer in-process. This task only kicks off the remote process;
    the sidecar at ``tools/aila_fuzz_reporter/`` reports its progress
    back via PATCH /fuzz/campaigns/{id} + POST /fuzz/crashes.
    """
    del ctx
    from aila.modules.vr.services.fuzz_service import (  # noqa: PLC0415
        FuzzCampaignService,
    )

    svc = FuzzCampaignService()
    return await svc.launch_campaign(campaign_id)
