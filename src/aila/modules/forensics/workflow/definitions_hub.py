"""Forensics dispatch-hub graph (opt-in) over the shared substrate.

RFC-13 (#68). Where ``FORENSICS_DISPATCHER_V1`` routes to a linear mode
pipeline, this graph runs the same proven stage handlers as a
discovery-driven dispatch: setup (intake), then the hub, then a stage,
then back to the hub, until emit. Intake enumerates evidence and posts the
active lanes; the hub then activates a collector lane only when a matching
evidence type was discovered -- a disk image opens the disk (and binary)
lane, a pcap opens the network lane -- reusing the existing
``_LANE_EVIDENCE_TYPES`` classification. The deterministic post-collection
tail (deep_analysis, promotion, resolution, writeup) runs unconditionally
after the lanes, in order.

This reuses every existing forensics stage handler unchanged: each phase
adapter runs the real stage and only overrides the next transition back to
the hub, and each lane phase scopes ``state_collection`` to its single lane
via ``active_lanes``. No collector machinery is rewritten and the live
``FORENSICS_DISPATCHER_V1`` is untouched; the definition ships bound
nowhere and is enabled by an operator seed rebind after a smoke.

The shared ledger is the evidence board: :func:`record_evidence` posts a
discovered evidence item as a ledger ``discovery`` with its type, path, and
source so the hub conditions (and other branches) read a common board.
"""
from __future__ import annotations

from typing import Any, cast

from sqlalchemy.ext.asyncio import AsyncSession

from aila.modules.forensics.workflow.definitions import (
    FORENSICS_MODE_DEFINITIONS,
    _build_services,
    _state_response_emit,
)
from aila.modules.forensics.workflow.states.collection import (
    _LANE_EVIDENCE_TYPES,
    state_collection,
)
from aila.modules.forensics.workflow.states.deep_analysis import state_deep_analysis
from aila.modules.forensics.workflow.states.intake import state_intake
from aila.modules.forensics.workflow.states.promotion import state_promotion
from aila.modules.forensics.workflow.states.resolution import state_resolution
from aila.modules.forensics.workflow.states.writeup import state_writeup
from aila.platform.services.ledger import LedgerService, make_evidence_condition
from aila.platform.workflows.phase_graph import (
    PhaseSpec,
    build_dispatch_workflow,
)
from aila.platform.workflows.types import HandlerFn, StateResult

__all__ = [
    "FORENSICS_HUB_PHASES",
    "FORENSICS_INVESTIGATE_HUB",
    "record_evidence",
]

# Hub phase name -> collection lane key. The "binary" phase drives the
# "binary_analysis" collection lane (capa/FLOSS/strings on samples the disk
# lane surfaces).
_PHASE_LANE: dict[str, str] = {
    "disk": "disk",
    "memory": "memory",
    "network": "network",
    "log": "log",
    "binary": "binary_analysis",
}

# Hub phase name -> deterministic tail stage handler (unconditional).
_TAIL_HANDLERS: dict[str, HandlerFn] = {
    "deep_analysis": state_deep_analysis,
    "promotion": state_promotion,
    "resolution": state_resolution,
    "writeup": state_writeup,
}


async def record_evidence(
    investigation_id: str,
    author_branch_id: str,
    evidence_type: str,
    path: str,
    source: str,
    *,
    session: AsyncSession | None = None,
) -> int:
    """Post a discovered evidence item to the shared ledger (evidence board).

    Recorded as a ``discovery`` entry carrying the evidence type, path, and
    source so the hub's evidence conditions and other branches read one
    board. Idempotency-keyed by path so re-enumerating the same evidence
    does not double-post.
    """
    return await LedgerService().append_general(
        investigation_id,
        author_branch_id,
        "discovery",
        {"evidence_type": evidence_type, "path": path, "source": source},
        idempotency_key=f"evidence:{path}",
        session=session,
    )


def _setup_builder(next_state: str) -> HandlerFn:
    """Run intake, then transition to the hub instead of a static edge."""
    async def _handler(state_input: dict[str, Any], services: Any) -> StateResult:
        result = await state_intake(state_input, services)
        return StateResult(
            next_state=next_state, output={**state_input, **result.output},
        )
    return _handler


def _loop_builder(phase: PhaseSpec, next_state: str) -> HandlerFn:
    """Run a lane collector or a tail stage, then loop back to the hub."""
    lane = _PHASE_LANE.get(phase.name)
    tail = _TAIL_HANDLERS.get(phase.name)

    async def _handler(state_input: dict[str, Any], services: Any) -> StateResult:
        if lane is not None:
            scoped = {**state_input, "active_lanes": [lane]}
            result = await state_collection(scoped, services)
        else:
            result = await tail(state_input, services)
        output = result.output if isinstance(result, StateResult) else dict(result)
        return StateResult(next_state=next_state, output={**state_input, **output})
    return _handler


FORENSICS_HUB_PHASES: tuple[PhaseSpec, ...] = (
    PhaseSpec(
        name="disk",
        condition=make_evidence_condition(_LANE_EVIDENCE_TYPES["disk"]),
        trust="advisory",
    ),
    PhaseSpec(
        name="memory",
        condition=make_evidence_condition(_LANE_EVIDENCE_TYPES["memory"]),
        trust="advisory",
    ),
    PhaseSpec(
        name="network",
        condition=make_evidence_condition(_LANE_EVIDENCE_TYPES["network"]),
        trust="advisory",
    ),
    PhaseSpec(
        name="log",
        condition=make_evidence_condition(_LANE_EVIDENCE_TYPES["log"]),
        trust="advisory",
    ),
    PhaseSpec(
        name="binary",
        condition=make_evidence_condition(_LANE_EVIDENCE_TYPES["binary_analysis"]),
        trust="advisory",
    ),
    PhaseSpec(name="deep_analysis"),
    PhaseSpec(name="promotion"),
    PhaseSpec(name="resolution"),
    PhaseSpec(name="writeup"),
)


FORENSICS_INVESTIGATE_HUB = build_dispatch_workflow(
    "forensics.investigate.hub",
    FORENSICS_HUB_PHASES,
    services_factory=_build_services,
    setup_builder=_setup_builder,
    loop_builder=_loop_builder,
    emit_handler=cast("HandlerFn", _state_response_emit),
    # Runs as the inner definition of FORENSICS_DISPATCHER_V1 (two-phase
    # dispatch), sharing the dispatcher's run_id -- reset the cursor from the
    # dispatcher's terminal to this graph's start_state, like the fixed-mode
    # definitions (FORENSICS_FULL_ANALYSIS_V1 etc.) that also set this.
    allow_phase_handoff=True,
)


# RFC-13 (#68): register the discovery-driven hub as a dispatch target so the
# two-phase dispatcher (``FORENSICS_DISPATCHER_V1.dispatches_to`` is this same
# dict) can resolve ``forensics.investigate.hub`` by id. This module depends on
# ``definitions`` for its builders, so the registration lives here (downstream)
# rather than in ``definitions`` (upstream) to keep the import edge acyclic.
FORENSICS_MODE_DEFINITIONS[FORENSICS_INVESTIGATE_HUB.definition_id] = (
    FORENSICS_INVESTIGATE_HUB
)
