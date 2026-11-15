"""Forensics panel phase graph (#18).

Wires the module-owned :func:`state_forensics_panel_setup` and
:func:`state_forensics_panel_emit` handlers and the platform
:func:`state_investigation_loop` (bound to the panel researcher and the
analyzer action dispatcher) as a phase graph via the platform primitive
:func:`build_phase_workflow` (RFC-13 substrate).

The graph shape is:

    setup -> investigate -> emit -> __succeeded__

Setup spawns the sibling branches (halvar / maddie / renzo); every
non-primary sibling is enqueued as its own worker task that re-enters
setup with its explicit ``branch_id`` and skips the spawn. The
investigate phase runs turns for one branch until it submits, spends
``forensics.max_turns_per_task``, leaves the running state (operator stop,
sibling approval), or the researcher raises (cost ceiling reached). Emit
settles the sibling-review quorum and finalizes the investigation once no
branch is still working.

``FORENSICS_INVESTIGATE_PANEL_V1`` runs when an investigation is started in
panel mode (via the task in :mod:`.task`).
"""
from __future__ import annotations

from typing import cast

from aila.modules.forensics.agents.panel_actions import PanelActionDispatcher
from aila.modules.forensics.agents.panel_researcher import (
    ForensicsPanelResearcher,
    ForensicsPanelResearcherError,
    read_panel_max_turns,
)
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.workflow.definitions import _build_services
from aila.modules.forensics.workflow.panel.emit import (
    state_forensics_panel_emit,
)
from aila.modules.forensics.workflow.panel.setup import (
    state_forensics_panel_setup,
)
from aila.platform.workflows.investigation_loop_base import (
    state_investigation_loop,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)
from aila.platform.workflows.phase_graph import (
    PhaseGraphSpec,
    PhaseSpec,
    build_phase_workflow,
)
from aila.platform.workflows.types import HandlerFn

__all__ = ["FORENSICS_INVESTIGATE_PANEL_V1"]


_INVESTIGATE_DIRECTIVE = (
    "PANEL INVESTIGATE PHASE. Objective: answer the forensic question as a "
    "panel. The lead examiner builds the answer from primary evidence, the "
    "critic falsifies weak claims, and the corroboration examiner verifies "
    "the chain of evidence independently. The first submit becomes the "
    "panel's draft answer; the other examiners vote on it before it is "
    "recorded."
)


def _setup_builder(next_state: str) -> HandlerFn:
    return cast("HandlerFn", state_forensics_panel_setup(next_state))


_LOOP_BINDINGS = InvestigationStateBindings(
    inv_model=InvestigationRunRecord,
    branch_model=ForensicsInvestigationBranchRecord,
    researcher_factory=lambda engine, iid, bid, cve, pat, retrieved: ForensicsPanelResearcher(
        reasoning_engine=engine, investigation_id=iid, branch_id=bid,
        applicable_patterns=pat, retrieved_knowledge=retrieved,
    ),
    action_dispatcher=PanelActionDispatcher(),
    max_turns_reader=read_panel_max_turns,
    researcher_error=ForensicsPanelResearcherError,
    # The unknown-confidence pause gate calls the platform lifecycle
    # service, which needs the queue track and the branch table name.
    track="forensics",
    branch_table="forensics_investigation_branches",
)


def _loop_builder(phase: PhaseSpec, next_state: str) -> HandlerFn:
    return state_investigation_loop(
        _LOOP_BINDINGS,
        InvestigationStateHooks(),
        next_state=next_state,
        phase_directive=phase.directive,
    )


_GRAPH = PhaseGraphSpec(
    start="investigate",
    phases=(
        PhaseSpec(
            name="investigate",
            directive=_INVESTIGATE_DIRECTIVE,
        ),
    ),
)


FORENSICS_INVESTIGATE_PANEL_V1 = build_phase_workflow(
    "forensics.investigate.panel.v1",
    _GRAPH,
    services_factory=_build_services,
    setup_builder=_setup_builder,
    loop_builder=_loop_builder,
    emit_handler=cast("HandlerFn", state_forensics_panel_emit),
)
