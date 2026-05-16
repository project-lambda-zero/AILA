"""Helpers for enqueueing VR background tasks from worker contexts.

Used by the OutcomeDispatcher (which runs inside an ARQ worker, not a
FastAPI request) so it can submit follow-up tasks without depending on
``aila.api.deps.get_task_queue`` (which needs a Request).
"""
from __future__ import annotations

from typing import Any

from aila.storage.registry import ConfigRegistry

__all__ = [
    "default_task_queue",
    "enqueue_vr_nday",
]


def default_task_queue() -> Any:
    """Construct a platform TaskQueue bound to the ``vr`` module.

    Imports are lazy to avoid pulling the platform-tasks module on import
    of contracts/dispatcher modules at test collection time.
    """
    from aila.platform.tasks.queue import TaskQueue  # noqa: PLC0415

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
    from .workflow.task import run_vr_nday  # noqa: PLC0415

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
