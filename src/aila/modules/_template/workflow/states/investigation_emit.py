"""Investigation emit state scaffold (RFC-02 Phase 4c).

Copy-me scaffold demonstrating the canonical binding shape for a new
module's ``investigation_emit`` state. The full emit engine -- auto-
continue, investigation-level cap-exceeded halt (turns / messages /
wall-clock with idle grace), terminal status resolution, orphan-branch
cleanup, draft-outcome review + dispatch, synthesis + verifier trigger
fan-out, knowledge pattern extraction, finalize chokepoint -- lives on
the platform in :mod:`aila.platform.workflows.investigation_emit_base`.
This module supplies its record models, task functions, ARQ track,
config readers, outcome dispatcher + pattern extractor classes,
pattern-store factory, outcome-review helpers, finalize function, and
branch table; the platform never names a module.

Rename ``Template`` / ``template`` throughout when copying: every
binding below points at a template record model or a template-scoped
factory that keeps this scaffold isolated from live modules.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.modules._template._task_queue import default_task_queue
from aila.modules._template.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules._template.agents.pattern_extractor import PatternExtractor
from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationMessageRecord,
    TemplateInvestigationOutcomeRecord,
    TemplateInvestigationRecord,
)
from aila.modules._template.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    evaluate_quorum,
    post_draft_review_request,
)
from aila.modules._template.services.pattern_store import PatternStore
from aila.modules._template.workflow.finalize import finalize_investigation
from aila.platform.config_base import ModuleConfigReader
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

# Module-scoped typed config reader. Resolves the ``template`` namespace
# through :class:`ConfigRegistry` (env -> DB -> schema default) and
# replaces the deleted ``services.config_helpers`` shim (RFC-04).
_config = ModuleConfigReader("template")

# Deferred emit handler singleton. workflow/task.py imports back into
# workflow/definitions.py which imports THIS module; wiring the task
# functions here at module load would form a circular import. First-
# call build resolves the imports at a point where every dependency
# is fully imported. See vr's investigation_emit for the same shape.
_HANDLER: Any = None


def _build_emit_handler() -> Any:
    """Build the emit handler once, on first call.

    Wires every optional binding the platform emit factory reads:
    task functions, task-queue factory, config readers, outcome
    dispatcher + pattern extractor classes, pattern-store factory,
    outcome-review helpers, finalize function, and branch table.

    The template scaffold leaves ``record_experience`` unset -- the
    experience-writer wire-in is opt-in and a copier binds it once the
    module has a live PatternStore worth writing signed patterns into.
    """
    from aila.modules._template.workflow.task import (
        run_template_investigate,
    )

    bindings = InvestigationStateBindings(
        inv_model=TemplateInvestigationRecord,
        branch_model=TemplateInvestigationBranchRecord,
        message_model=TemplateInvestigationMessageRecord,
        outcome_model=TemplateInvestigationOutcomeRecord,
        task_fn=run_template_investigate,
        # Template scaffold ships no synthesis / verifier tasks yet;
        # a copier binds these once the module has a real panel to
        # consolidate + a verifier prompt.
        synthesis_task_fn=None,
        verifier_task_fn=None,
        track="template",
        task_queue_factory=default_task_queue,
        get_int=_config.get_int,
        get_float=_config.get_float,
        outcome_dispatcher_cls=OutcomeDispatcher,
        pattern_extractor_cls=PatternExtractor,
        pattern_store_factory=lambda: PatternStore(
            knowledge=ServiceFactory().knowledge,
        ),
        approved_state=OUTCOME_STATE_APPROVED,
        evaluate_quorum=evaluate_quorum,
        post_draft_review_request=post_draft_review_request,
        finalize=finalize_investigation,
        branch_table="template_investigation_branches",
        module_id="template",
    )
    return _build_emit_state(bindings, InvestigationStateHooks())


async def state_investigation_emit(
    input: dict[str, Any], services: Any,
) -> StateResult:
    """Template binding of the platform emit factory (lazy first-call build).

    Delegates every call to the singleton handler built on first entry.
    No local body: the factory owns the entire emit engine and rule 41
    in ``aila.tools.honesty_audit`` locks the vr/malware copies out of
    drifting a body back in. This scaffold sits outside rule 41's
    scope but keeps the same discipline.
    """
    global _HANDLER
    if _HANDLER is None:
        _HANDLER = _build_emit_handler()
    return await _HANDLER(input, services)
