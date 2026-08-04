"""Investigation loop state scaffold (RFC-02 Phase 4b).

Copy-me scaffold demonstrating the canonical binding shape for a new
module's ``investigation_loop`` state. The bounded per-turn engine --
liveness poll (inv status, branch status, cursor SSOT, cancellation
token), researcher ``run_turn`` dispatch, tool executor loop, terminal /
cap handling, HARD-BLOCK breaker -- lives on the platform in
:mod:`aila.platform.workflows.investigation_loop_base`. This module
supplies its record models, researcher factory, tool-executor factory,
per-task max-turns reader, and researcher-error type; the platform
never names a module.

Rename ``Template`` / ``template`` throughout, wire the researcher +
tool-executor factories to the module's real agent classes, and set
``max_turns_reader`` to the module's ``ConfigRegistry``-backed reader so
an operator can retune the per-task turn budget without a worker
restart.
"""
from __future__ import annotations

import logging

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationRecord,
)
from aila.platform.workflows.investigation_loop_base import (
    state_investigation_loop as _build_loop_state,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)

__all__ = ["state_investigation_loop"]

_log = logging.getLogger(__name__)

# Loop-only bindings. A real module also wires:
#   * ``researcher_factory`` -- builds the module's per-branch
#     researcher agent from services + case_state.
#   * ``executor_factory`` -- returns the per-worker-process
#     ``ToolExecutor`` singleton (mirror the vr / malware
#     ``_get_executor`` pattern so httpx pools + LRU caches are shared
#     across every task on a worker).
#   * ``max_turns_reader`` -- async reader against ConfigRegistry
#     (``get_int("max_turns_per_task")``) so operator retunes take
#     effect without a worker restart.
#   * ``researcher_error`` -- the module's researcher-agent exception
#     type; a raise from the researcher exits the loop cleanly and lets
#     ``investigation_emit`` auto-re-enqueue instead of failing the
#     branch.
_LOOP_BINDINGS = InvestigationStateBindings(
    inv_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    module_id="template",
)

# The loop handler IS the platform factory bound to the template's
# models. No local body: the factory owns the entire loop behavior and
# rule 41 in ``aila.tools.honesty_audit`` locks this file out of
# drifting a copy back in.
state_investigation_loop = _build_loop_state(
    _LOOP_BINDINGS, InvestigationStateHooks(),
)
