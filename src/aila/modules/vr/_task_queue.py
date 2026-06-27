"""Helpers for enqueueing VR background tasks from worker contexts.

Used by the OutcomeDispatcher (which runs inside an ARQ worker, not a
FastAPI request) so it can submit follow-up tasks without depending on
``aila.api.deps.get_task_queue`` (which needs a Request).
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts.target_stages import StageName, StageState
from aila.modules.vr.enrichment.workers import (
    run_capability_profile_build,
    run_function_ranking,
)
from aila.modules.vr.services.stage_tracker import load_target_stages
from aila.platform.tasks.queue import TaskQueue
from aila.storage.registry import ConfigRegistry

__all__ = [
    "default_task_queue",
    "enqueue_vr_nday",
    "enqueue_downstream_target_stages",
]


def default_task_queue() -> Any:
    """Construct a platform TaskQueue bound to the ``vr`` module."""
    return TaskQueue(
        config_registry=ConfigRegistry(),
        module_id="vr",
    )


# Module-level reference used by OutcomeDispatcher when no test-injected
# factory is supplied. Tests pass their own factory via the constructor.
_default_task_queue_factory_ref = default_task_queue


async def enqueue_vr_nday(
    task_queue: Any,
    *,
    source_outcome_id: str,
    patch_descriptor: dict[str, Any],
    assessment: dict[str, Any],
    parent_investigation_id: str,
    target_id: str,
    team_id: str | None,
) -> Any:
    """Submit the VR N-day workflow with the engine's patch assessment.

    Returns whatever ``task_queue.submit()`` returns (a TaskHandle in
    production, a fake in tests). The kwargs are JSON-serializable per
    the platform-task contract.
    """
    from .workflow.task import run_vr_nday

    return await task_queue.submit(
        track="vr",
        fn=run_vr_nday,
        kwargs={
            "source_outcome_id": source_outcome_id,
            "patch_descriptor": patch_descriptor,
            "assessment": assessment,
            "parent_investigation_id": parent_investigation_id,
            "target_id": target_id,
        },
        user_id="system",
        group_id="vr_dispatcher",
        team_id=team_id,
    )


async def enqueue_downstream_target_stages(
    target_id: str,
    task_queue: Any,
    *,
    user_id: str = "system",
    group_id: str = "system",
    team_id: str | None = None,
) -> list[dict[str, str]]:
    """Fan out the post-ingestion enrichment stages for a target.

    Reads the target's ``analysis_stages_json`` and enqueues
    ``run_capability_profile_build`` and ``run_function_ranking`` for
    any stage that is not already DONE. Both depend on INGESTION; if
    ingestion is not yet DONE this is a no-op (the worker running
    ``run_target_analysis`` calls this helper at task-end after
    ingestion has flipped to DONE).

    Idempotent. Safe to call from:
      - inside ``run_target_analysis`` (auto-chain after ingestion).
      - the operator-facing ``POST /vr/targets/:id/resume-analysis``
        endpoint (which used to inline this fan-out logic).

    StageTracker handles the "stage already DONE" / "stage RUNNING
    within timeout" cases by raising StageAlreadyDoneError /
    StageInFlightError inside each task; the task body catches those
    and returns cleanly, so a stale duplicate enqueue is wasteful but
    not corrupting.
    """
    stages = await load_target_stages(target_id)
    if stages.ingestion.state != StageState.DONE:
        # Ingestion not finished yet -- caller is responsible for
        # enqueuing ingestion itself. Downstream stages depend on the
        # mcp handles produced by ingestion.
        return []

    enqueued: list[dict[str, str]] = []

    async def _enqueue(stage_label: str, fn: object) -> None:
        handle = await task_queue.submit(
            track="vr",
            fn=fn,
            kwargs={"target_id": target_id},
            user_id=user_id,
            group_id=group_id,
            team_id=team_id,
        )
        enqueued.append({"stage": stage_label, "task_id": handle.task_id})

    if stages.capability_profile.state != StageState.DONE:
        await _enqueue(StageName.CAPABILITY_PROFILE.value, run_capability_profile_build)
    if stages.function_ranking.state != StageState.DONE:
        await _enqueue(StageName.FUNCTION_RANKING.value, run_function_ranking)

    return enqueued
