"""Investigation loop state scaffold (RFC-02 Phase 4b).

Copy-me scaffold demonstrating the canonical binding shape for a new
module's ``investigation_loop`` state. The bounded per-turn engine --
liveness poll (inv status, branch status, cursor SSOT, cancellation
token), researcher ``run_turn`` dispatch, tool executor loop, terminal
/ cap handling, HARD-BLOCK breaker -- lives on the platform in
:mod:`aila.platform.workflows.investigation_loop_base`. This module
supplies its record models, researcher factory, tool-executor factory,
per-task max-turns reader, and researcher-error type; the platform
never names a module.

Rename ``Template`` / ``template`` throughout when copying: every
binding below points at a template record model or a template-scoped
factory that keeps this scaffold isolated from live modules.
"""
from __future__ import annotations

import logging

from aila.modules._template.agents.researcher import (
    TemplateResearcher,
    TemplateResearcherError,
)
from aila.modules._template.agents.tool_executor import ToolExecutor
from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationRecord,
)
from aila.modules._template.services.config_helpers import get_int
from aila.platform.workflows.investigation_loop_base import (
    state_investigation_loop as _build_loop_state,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)

__all__ = ["state_investigation_loop"]

_log = logging.getLogger(__name__)

# Per-worker-process executor singleton. Ties the bridge httpx pools +
# LRU caches on the executor's lifetime to the worker process, so
# tasks sharing an investigation reuse the same warm state instead of
# paying construction cost each task. Mirrors the vr pattern.
_EXECUTOR_SINGLETON: ToolExecutor | None = None


def _get_executor() -> ToolExecutor:
    """Return the per-worker-process :class:`ToolExecutor` singleton."""
    global _EXECUTOR_SINGLETON
    if _EXECUTOR_SINGLETON is None:
        _EXECUTOR_SINGLETON = ToolExecutor()
    return _EXECUTOR_SINGLETON


_LOOP_BINDINGS = InvestigationStateBindings(
    inv_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    researcher_factory=lambda engine, iid, bid, cve, pat, retrieved: (
        TemplateResearcher(
            reasoning_engine=engine,
            investigation_id=iid,
            branch_id=bid,
            applicable_patterns=pat,
            retrieved_knowledge=retrieved,
        )
    ),
    executor_factory=_get_executor,
    max_turns_reader=lambda: get_int("max_turns_per_task"),
    researcher_error=TemplateResearcherError,
    module_id="template",
)

# The loop handler IS the platform factory bound to the template
# researcher. No local body: the factory owns the entire loop
# behavior and rule 41 in ``aila.tools.honesty_audit`` locks the
# vr/malware copies out of drifting a body back in. The template file
# stays out of that rule's scope but mirrors the same discipline --
# no state body ever lands here.
state_investigation_loop = _build_loop_state(
    _LOOP_BINDINGS, InvestigationStateHooks(),
)
