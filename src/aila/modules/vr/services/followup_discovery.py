"""VR binding of the platform follow-up-discovery take-over primitive.

Composes :func:`aila.platform.services.followup_discovery.maybe_spawn_followup_discovery`
with VR's ORM record models, VR's outcome-polarity reducer, VR's
recommendations extractor (which reads
``payload['panel_summary']['recommended_next_actions']`` -- the shape
:class:`aila.modules.vr.agents.synthesis_agent.SynthesisAgent` writes),
and a VR enqueue closure that submits :func:`run_vr_investigate` on
the ``vr`` track.

Wired into :func:`aila.modules.vr.workflow.task.run_vr_synthesis`
immediately after the synthesis agent commits its ``panel_summary``.
A follow-up failure NEVER fails the synthesis task -- the caller
wraps this in ``try / except (OSError, RuntimeError, TimeoutError,
ValueError)`` and logs.

Mirrors the binding pattern used by
:mod:`aila.modules.vr.services.investigation_finalizers`: the platform
primitive is the implementation, this module supplies the module-side
identity (record models + module-specific callables + module-specific
enqueue) so the platform code never names ``vr`` and never imports
from ``aila.modules.vr.*``.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr._task_queue import default_task_queue
from aila.modules.vr.contracts.investigation import InvestigationKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.services.outcome_polarity import derive_outcome_polarity
from aila.platform.services.followup_discovery import (
    maybe_spawn_followup_discovery,
)

__all__ = [
    "extract_vr_recommendations",
    "maybe_spawn_vr_followup",
]


_VR_STRATEGY_FAMILY: str = "vulnerability_research.discovery_research"
_VR_ENQUEUE_GROUP: str = "vr_followup_discovery"


def extract_vr_recommendations(payload: dict[str, Any]) -> list[str]:
    """Pull the panel-synthesised follow-up actions off a VR outcome payload.

    Reads ``payload['panel_summary']['recommended_next_actions']``, the
    shape :class:`~aila.modules.vr.agents.synthesis_agent.SynthesisAgent`
    persists under
    :meth:`~aila.modules.vr.agents.synthesis_agent.SynthesisAgent._update_payload_extras`.
    Returns an empty list when either key is absent, non-dict, or the
    action list is empty -- the platform primitive's own emptiness
    guard then skips the spawn with ``no_recommendations``.
    """
    panel_summary = payload.get("panel_summary")
    if not isinstance(panel_summary, dict):
        return []
    recs = panel_summary.get("recommended_next_actions") or []
    if not isinstance(recs, list):
        return []
    return [str(r) for r in recs]


async def _enqueue_vr_investigate(
    child_investigation_id: str,
    team_id: str | None,
) -> Any:
    """Submit ``run_vr_investigate`` for a freshly-spawned child.

    Imports the task inside the function so the module's public
    surface stays a single top-level closure -- the workflow-task
    module already pulls services during its own import, and a
    top-level import here would loop that pull. Matches the deferred-
    import pattern the OutcomeDispatcher uses when it enqueues
    ``run_vr_investigate`` for a variant-hunt child.
    """
    from aila.modules.vr.workflow.task import run_vr_investigate

    task_queue = default_task_queue()
    return await task_queue.submit(
        track="vr",
        fn=run_vr_investigate,
        kwargs={"investigation_id": child_investigation_id},
        user_id="system",
        group_id=_VR_ENQUEUE_GROUP,
        team_id=team_id,
    )


async def maybe_spawn_vr_followup(investigation_id: str) -> dict[str, Any]:
    """Take-over binding: spawn AT MOST ONE VR follow-up-discovery child.

    Thin wrapper around
    :func:`aila.platform.services.followup_discovery.maybe_spawn_followup_discovery`
    supplying VR's models + polarity fn + recommendations extractor +
    enqueue closure. Every guard (depth cap, budget floor, polarity
    gate, idempotency) lives on the platform primitive so a second
    module (malware / forensics) can bind the same take-over on its
    own terms.
    """
    return await maybe_spawn_followup_discovery(
        investigation_id,
        investigation_model=VRInvestigationRecord,
        branch_model=VRInvestigationBranchRecord,
        outcome_model=VRInvestigationOutcomeRecord,
        discovery_kind=InvestigationKind.DISCOVERY.value,
        strategy_family=_VR_STRATEGY_FAMILY,
        derive_polarity=derive_outcome_polarity,
        extract_recommendations=extract_vr_recommendations,
        enqueue_investigate=_enqueue_vr_investigate,
    )
