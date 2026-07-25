"""VR investigation phase graph (V2, opt-in) over the shared substrate.

``VR_INVESTIGATE_V2`` expresses the vulnerability-research lifecycle as a
graph of bounded adaptive loops on the platform phase-graph substrate,
instead of V1's single loop:

    setup -> recon [kind router]
          -> source_audit | variant_hunt | binary_audit | mobile_audit
          -> emit

Each phase scopes the shared panel to a distinct tool regime -- the VR
module exposes three agent MCP servers (source auditing via audit_mcp,
binary RE via ida_headless, mobile via android_mcp), so a phase's tool
allowlist is a real, enforced restriction (a call to an off-phase server
is rejected the same way an off-module server is). The recon phase scopes
the target under a tighter turn cap; the kind router then sends the run to
the deep phase that matches the investigation kind:

- discovery / audit -> source_audit (audit_mcp only)
- variant_hunt      -> variant_hunt (audit_mcp + ida_headless)
- n_day             -> binary_audit (ida_headless only)
- masvs_audit       -> mobile_audit (android_mcp + audit_mcp)
- triage            -> emit (the recon characterization is the deliverable)

Each phase carries a mission directive surfaced to the panel as the
``_directive.phase_mission`` observable. Every phase runs the same panel
over the module's proven base prompt; phases differ in control flow (route,
tool allowlist, turn cap) and mission, not in a per-phase system prompt.
V2 is not selected by any task; V1 stays the bound definition until an
operator rebinds the seed after a live smoke.
"""
from __future__ import annotations

from typing import Any, cast

from sqlmodel import select

from aila.modules.vr.db_models import VRInvestigationRecord
from aila.modules.vr.workflow.definitions import _build_services
from aila.modules.vr.workflow.states.investigation_emit import (
    state_investigation_emit,
)
from aila.modules.vr.workflow.states.investigation_loop import _LOOP_BINDINGS
from aila.modules.vr.workflow.states.investigation_setup import (
    _SETUP_BINDINGS,
    _SETUP_HOOKS,
)
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.investigation_loop_base import (
    state_investigation_loop as _build_loop_state,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateHooks,
)
from aila.platform.workflows.investigation_setup_base import (
    state_investigation_setup as _build_setup_state,
)
from aila.platform.workflows.phase_graph import (
    EMIT_STATE,
    PhaseGraphSpec,
    PhaseSpec,
    build_phase_workflow,
)
from aila.platform.workflows.types import HandlerFn

__all__ = ["VR_INVESTIGATE_V2"]

# Recon only scopes the target, so it is capped tighter than the deep
# phases (which fall back to the module turn-cap reader).
_RECON_MAX_TURNS = 20

_RECON_DIRECTIVE = (
    "RECON PHASE. Objective: characterize the target scope and entry "
    "points, and identify the most promising surfaces to audit. Do NOT "
    "start a systematic audit or develop a proof of concept yet. Submit a "
    "short scoping outcome so the panel can route to the right deep phase."
)
_SOURCE_AUDIT_DIRECTIVE = (
    "SOURCE AUDIT PHASE. Objective: systematically audit the source for "
    "exploitable vulnerability classes -- trace untrusted input to "
    "dangerous sinks, read the candidate function bodies, and confirm each "
    "finding with evidence. Submit confirmed findings."
)
_VARIANT_HUNT_DIRECTIVE = (
    "VARIANT HUNT PHASE. Objective: find variants of the seed bug pattern "
    "across the codebase and its binaries -- match the vulnerable shape, "
    "not just the exact strings. Confirm each variant with evidence before "
    "submitting it."
)
_BINARY_AUDIT_DIRECTIVE = (
    "BINARY AUDIT PHASE. Objective: analyze the binary for the vulnerable "
    "condition -- follow the decompilation, check the guards, and confirm "
    "reachability. Submit confirmed findings with the responsible "
    "addresses."
)
_MOBILE_AUDIT_DIRECTIVE = (
    "MOBILE AUDIT PHASE. Objective: audit the mobile application against "
    "the MASVS controls -- storage, crypto, network, platform interaction "
    "-- and confirm each gap with evidence. Submit the MASVS findings."
)

# Investigation kind -> deep phase after recon. A triage-kind run needs no
# deep phase (the recon characterization is its deliverable), so it routes
# to the terminal emit. Unmapped kinds fall through to source audit.
_KIND_TO_PHASE: dict[str, str] = {
    "triage": EMIT_STATE,
    "discovery": "source_audit",
    "audit": "source_audit",
    "variant_hunt": "variant_hunt",
    "n_day": "binary_audit",
    "masvs_audit": "mobile_audit",
}


async def _classify_kind(state_input: dict[str, Any]) -> str:
    """Route past recon by the investigation kind."""
    investigation_id = str(state_input.get("investigation_id") or "")
    if not investigation_id:
        return "source_audit"
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            )
        )).first()
    kind = ((inv.kind if inv else "") or "").strip().lower()
    return _KIND_TO_PHASE.get(kind, "source_audit")


def _setup_builder(next_state: str) -> HandlerFn:
    """Bind the VR setup handler with the graph start transition."""
    return _build_setup_state(_SETUP_BINDINGS, _SETUP_HOOKS, next_state=next_state)


def _loop_builder(phase: PhaseSpec, next_state: str) -> HandlerFn:
    """Bind the VR loop handler with the phase mission, cap, and tool regime."""
    return _build_loop_state(
        _LOOP_BINDINGS,
        InvestigationStateHooks(),
        next_state=next_state,
        phase_directive=phase.directive,
        phase_max_turns=phase.max_turns,
        phase_allowed_servers=phase.allowed_servers,
    )


_GRAPH = PhaseGraphSpec(
    start="recon",
    phases=(
        PhaseSpec(
            name="recon",
            directive=_RECON_DIRECTIVE,
            max_turns=_RECON_MAX_TURNS,
            allowed_servers=("audit_mcp", "ida_headless"),
            router=_classify_kind,
        ),
        PhaseSpec(
            name="source_audit",
            directive=_SOURCE_AUDIT_DIRECTIVE,
            allowed_servers=("audit_mcp",),
            next=EMIT_STATE,
        ),
        PhaseSpec(
            name="variant_hunt",
            directive=_VARIANT_HUNT_DIRECTIVE,
            allowed_servers=("audit_mcp", "ida_headless"),
            next=EMIT_STATE,
        ),
        PhaseSpec(
            name="binary_audit",
            directive=_BINARY_AUDIT_DIRECTIVE,
            allowed_servers=("ida_headless",),
            next=EMIT_STATE,
        ),
        PhaseSpec(
            name="mobile_audit",
            directive=_MOBILE_AUDIT_DIRECTIVE,
            allowed_servers=("android_mcp", "audit_mcp"),
            next=EMIT_STATE,
        ),
    ),
)


VR_INVESTIGATE_V2 = build_phase_workflow(
    "vr.investigate.v2",
    _GRAPH,
    services_factory=_build_services,
    setup_builder=_setup_builder,
    loop_builder=_loop_builder,
    emit_handler=cast("HandlerFn", state_investigation_emit),
)
