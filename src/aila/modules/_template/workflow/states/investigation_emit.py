"""Investigation emit state scaffold (RFC-02 Phase 4c).

Copy-me scaffold demonstrating the canonical binding shape for a new
module's ``investigation_emit`` state. The full emit engine -- auto-
continue, investigation-level cap-exceeded halt (turns / messages /
wall-clock with idle grace), terminal status resolution, orphan-branch
cleanup, draft-outcome review + dispatch, synthesis + verifier trigger
fan-out, knowledge pattern extraction, finalize chokepoint -- lives on
the platform in :mod:`aila.platform.workflows.investigation_emit_base`.
This module supplies its record models, task functions, ARQ track,
config readers, outcome dispatcher + pattern extractor classes, pattern-
store factory, outcome-review helpers, finalize function, and branch
table; the platform never names a module.

Rename ``Template`` / ``template`` throughout and wire the remaining
bindings once the module's agents / config schema / finalize path
exist. A minimal binding compiles and demonstrates the pattern; a real
build-out fills the rest in over subsequent phases.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationRecord,
)
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

# Deferred emit handler singleton. A real module wires the task
# functions here from ``workflow/task.py`` (which imports back into
# ``workflow/definitions`` and would form a circular import if bound at
# module load); the first-call build resolves the imports at a point
# where every module is fully imported. See
# ``aila.modules.vr.workflow.states.investigation_emit`` for the
# production shape.
_HANDLER: Any = None


def _build_emit_handler() -> Any:
    """Build the emit handler once, on first call.

    Wires the module's task functions, task-queue factory, config
    readers, outcome-dispatcher + pattern-extractor classes, evaluate-
    quorum callback, outcome-review helpers, finalize function, and
    branch table into :class:`InvestigationStateBindings`. A real module
    fills every optional field before the handler is exercised in a
    live worker; the scaffold below wires only the mandatory record
    models to keep the file compiling.
    """
    from aila.modules._template.workflow.task import run_template_investigate

    bindings = InvestigationStateBindings(
        inv_model=TemplateInvestigationRecord,
        branch_model=TemplateInvestigationBranchRecord,
        task_fn=run_template_investigate,
        track="template",
        branch_table="template_investigation_branches",
        module_id="template",
    )
    return _build_emit_state(bindings, InvestigationStateHooks())


async def state_investigation_emit(
    input: dict[str, Any], services: Any,
) -> StateResult:
    """Template binding of the platform emit factory (lazy first-call build).

    Delegates every subsequent call to the singleton handler built on
    first entry. No local body: rule 41 in ``aila.tools.honesty_audit``
    locks this file out of drifting a copy of the platform emit engine
    back in.
    """
    global _HANDLER
    if _HANDLER is None:
        _HANDLER = _build_emit_handler()
    return await _HANDLER(input, services)
