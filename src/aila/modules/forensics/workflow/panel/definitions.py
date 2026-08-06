"""Forensics panel phase graph (#18).

Wires the module-owned :func:`state_forensics_panel_setup`,
:func:`state_forensics_panel_loop`, and
:func:`state_forensics_panel_emit` handlers as a phase graph via the
platform primitive :func:`build_phase_workflow` (RFC-13 substrate).

The graph shape is:

    setup -> investigate -> emit -> __succeeded__

Setup spawns the sibling branches (halvar / maddie / renzo); every
non-primary sibling is enqueued as its own worker task that re-enters
setup with its explicit ``branch_id`` and skips the spawn. The
investigate phase drives one panel branch's role turn(s) and submits a
draft outcome. Emit runs the platform sibling-review quorum on every
draft outcome and, for the primary branch, finalizes the investigation
status.

``FORENSICS_INVESTIGATE_PANEL_V1`` is opt-in -- a project that wants the
panel spine dispatches to this definition (via the task in :mod:`.task`);
the pre-existing free-flow / raw-directory / full-analysis /
dispatcher / hub graphs stay unchanged.
"""
from __future__ import annotations

from typing import cast

from aila.modules.forensics.workflow.definitions import _build_services
from aila.modules.forensics.workflow.panel.emit import (
    state_forensics_panel_emit,
)
from aila.modules.forensics.workflow.panel.loop import (
    state_forensics_panel_loop,
)
from aila.modules.forensics.workflow.panel.setup import (
    state_forensics_panel_setup,
)
from aila.platform.workflows.phase_graph import (
    PhaseGraphSpec,
    PhaseSpec,
    build_phase_workflow,
)
from aila.platform.workflows.types import HandlerFn

__all__ = ["FORENSICS_INVESTIGATE_PANEL_V1"]


_INVESTIGATE_DIRECTIVE = (
    "PANEL INVESTIGATE PHASE. Objective: fulfill your role on the "
    "forensics panel -- researcher proposes a finding grounded in the "
    "evidence, critic falsifies weak claims, implementer verifies the "
    "chain of evidence. Submit a terminal draft finding so the panel can "
    "vote via sibling-review quorum before it dispatches."
)


def _setup_builder(next_state: str) -> HandlerFn:
    return cast("HandlerFn", state_forensics_panel_setup(next_state))


def _loop_builder(phase: PhaseSpec, next_state: str) -> HandlerFn:
    # The panel phase is intentionally single-role today (see loop.py). A
    # follow-up ticket splits it into per-role phases with a router and
    # richer directives; the phase-graph substrate is ready for that (VR
    # uses the same builder shape).
    del phase
    return cast("HandlerFn", state_forensics_panel_loop(next_state))


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
