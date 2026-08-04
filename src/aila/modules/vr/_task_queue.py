"""Helpers for enqueueing VR background tasks from worker contexts.

Used by the OutcomeDispatcher (which runs inside an ARQ worker, not a
FastAPI request) so it can submit follow-up tasks without depending on
``aila.api.deps.get_task_queue`` (which needs a Request).
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.enrichment.workers import run_target_enrichment
from aila.modules.vr.services.stage_tracker import load_target_stages
from aila.platform.contracts.target_stages import StageState
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
    """Fan out the post-ingestion enrichment work for a target.

    Enqueues a single ``run_target_enrichment`` job (the M3.T-4
    orchestrator, ``enrichment/workers/orchestrator_worker.py``) that
    sequences capability-profile build then function ranking inside
    one worker slot instead of the two parallel jobs this helper used
    to submit. Both stages depend on INGESTION -- if ingestion is not
    yet DONE this is a no-op (the worker running ``run_target_analysis``
    calls this helper at task-end after ingestion has flipped to DONE),
    and if BOTH downstream stages are already DONE the helper skips the
    enqueue entirely so a stale resume click doesn't re-run finished
    work.

    Idempotent. Safe to call from:
      - inside ``run_target_analysis`` (auto-chain after ingestion).
      - the operator-facing ``POST /vr/targets/:id/resume-analysis``
        endpoint (which used to inline this fan-out logic).

    StageTracker inside each service handles the "stage already DONE" /
    "stage RUNNING within timeout" cases by raising
    StageAlreadyDoneError / StageInFlightError; the service body
    catches those and returns ``None``, so a stale duplicate enqueue
    is wasteful but not corrupting.
    """
    stages = await load_target_stages(target_id)
    if stages.ingestion.state != StageState.DONE:
        # Ingestion not finished yet -- caller is responsible for
        # enqueuing ingestion itself. Downstream stages depend on the
        # mcp handles produced by ingestion.
        return []

    if (
        stages.capability_profile.state == StageState.DONE
        and stages.function_ranking.state == StageState.DONE
    ):
        # Both downstream stages already finished -- nothing to do.
        return []

    handle = await task_queue.submit(
        track="vr",
        fn=run_target_enrichment,
        kwargs={"target_id": target_id},
        user_id=user_id,
        group_id=group_id,
        team_id=team_id,
    )
    return [{"stage": "enrichment", "task_id": handle.task_id}]
