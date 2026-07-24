"""Investigation emit state (M3.R-7).

Finalizes the investigation row based on the loop's exit reason:
  terminal_submit             → COMPLETED, primary_outcome_id linked
  max_turns                   → AUTO-RE-ENQUEUE (status stays RUNNING)
                                if branch.turn_count < _OVERALL_TURN_CAP
                                AND no terminal outcome -- the agent
                                keeps reasoning across multiple task
                                runs until it converges or hits the
                                cumulative cap. Operator can pause via
                                the API at any time.
  max_turns + cumulative cap  → COMPLETED with reason "exhausted --
                                operator should review or re-enqueue"
  status_flipped:paused       → PAUSED stays PAUSED (don't overwrite)
  status_flipped:failed       → FAILED stays FAILED
  researcher_error:*          → FAILED, error recorded in observables
                                of the primary branch
"""
from __future__ import annotations

import logging
from typing import Any

from aila.modules.vr._task_queue import default_task_queue
from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules.vr.agents.pattern_extractor import (
    PatternExtractor,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.services.config_helpers import get_float, get_int
from aila.modules.vr.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    evaluate_quorum,
    post_draft_review_request,
)
from aila.modules.vr.services.pattern_store import PatternStore
from aila.modules.vr.workflow.finalize import finalize_investigation
from aila.platform.services.factory import ServiceFactory
from aila.platform.workflows.investigation_emit_base import (
    state_investigation_emit as _build_emit_state,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)
from aila.platform.workflows.types import StateResult

__all__ = ["state_investigation_emit"]

_log = logging.getLogger(__name__)


# The emit handler is the platform factory bound to VR's models + agents.
# Built lazily on first call: the synthesis / verifier / investigate task
# functions live in vr.workflow.task, which imports vr.workflow.definitions
# (which imports this state module), so a module-level task import would be
# circular. First-call build defers them to a point where every module is
# fully imported.
_HANDLER: Any = None


def _build_emit_handler() -> Any:
    from aila.modules.vr.workflow.task import (
        run_vr_claim_verifier,
        run_vr_investigate,
        run_vr_synthesis,
    )

    bindings = InvestigationStateBindings(
        inv_model=VRInvestigationRecord,
        branch_model=VRInvestigationBranchRecord,
        message_model=VRInvestigationMessageRecord,
        outcome_model=VRInvestigationOutcomeRecord,
        task_fn=run_vr_investigate,
        synthesis_task_fn=run_vr_synthesis,
        verifier_task_fn=run_vr_claim_verifier,
        track="vr",
        task_queue_factory=default_task_queue,
        get_int=get_int,
        get_float=get_float,
        outcome_dispatcher_cls=OutcomeDispatcher,
        pattern_extractor_cls=PatternExtractor,
        pattern_store_factory=lambda: PatternStore(
            knowledge=ServiceFactory().knowledge,
        ),
        approved_state=OUTCOME_STATE_APPROVED,
        evaluate_quorum=evaluate_quorum,
        post_draft_review_request=post_draft_review_request,
        finalize=finalize_investigation,
        branch_table="vr_investigation_branches",
    )
    # VR has no post-completion proposers.
    return _build_emit_state(bindings, InvestigationStateHooks())


async def state_investigation_emit(
    input: dict[str, Any], services: Any,
) -> StateResult:
    """VR binding of the platform emit factory (lazy first-call build)."""
    global _HANDLER
    if _HANDLER is None:
        _HANDLER = _build_emit_handler()
    return await _HANDLER(input, services)
