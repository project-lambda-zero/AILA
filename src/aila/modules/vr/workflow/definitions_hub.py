"""VR investigation dispatch-hub graph (opt-in) over the shared substrate.

RFC-13 (#68). Where ``vr.investigate.v2`` wires the audit phases by a
kind router, this graph runs them as a discovery-driven dispatch: setup,
then the hub, then a phase, then back to the hub, until emit. Recon runs
first and posts scoping discoveries; the audit phases activate on those
discoveries (advisory trust, any discovery); poc_development is the gated
phase -- ``trust="confirmed"``, ``capability="exploit-dev"`` -- so it
activates only once the panel has confirmed an exploitable finding by
quorum, never on a raw hunch.

Each phase keeps its V2 per-phase MCP server allowlist, enforced on tool
dispatch. The capability fields scope a phase to a persona once
``_branch_capability`` is threaded (the multi-persona VR case); recon and
the fallback stay open. The definition ships alongside V1 and V2; a seed
binds it per investigation only after an operator smoke.
"""
from __future__ import annotations

from typing import cast

from aila.modules.vr.workflow.definitions import _build_services
from aila.modules.vr.workflow.definitions_v2 import (
    _BINARY_AUDIT_DIRECTIVE,
    _MOBILE_AUDIT_DIRECTIVE,
    _RECON_DIRECTIVE,
    _RECON_MAX_TURNS,
    _SOURCE_AUDIT_DIRECTIVE,
    _VARIANT_HUNT_DIRECTIVE,
    _loop_builder,
    _setup_builder,
)
from aila.modules.vr.workflow.states.investigation_emit import (
    state_investigation_emit,
)
from aila.platform.services.ledger import make_discovery_condition
from aila.platform.workflows.phase_graph import (
    PhaseSpec,
    build_dispatch_workflow,
)
from aila.platform.workflows.types import HandlerFn

__all__ = ["VR_HUB_PHASES", "VR_INVESTIGATE_HUB"]

_POC_DEV_DIRECTIVE = (
    "POC DEVELOPMENT PHASE. Objective: turn a confirmed exploitable "
    "finding into a working proof of concept -- reach the vulnerable "
    "state, control the primitive, and demonstrate impact. Pursue only a "
    "finding the panel has confirmed by quorum. Submit the PoC with the "
    "trigger and the observed effect."
)

VR_HUB_PHASES: tuple[PhaseSpec, ...] = (
    PhaseSpec(
        name="recon",
        directive=_RECON_DIRECTIVE,
        max_turns=_RECON_MAX_TURNS,
        allowed_servers=("audit_mcp", "ida_headless"),
        trust="confirmed",
    ),
    PhaseSpec(
        name="source_audit",
        directive=_SOURCE_AUDIT_DIRECTIVE,
        condition=make_discovery_condition("discovery"),
        capability="source-audit",
        trust="advisory",
        allowed_servers=("audit_mcp",),
    ),
    PhaseSpec(
        name="variant_hunt",
        directive=_VARIANT_HUNT_DIRECTIVE,
        condition=make_discovery_condition("discovery"),
        capability="variant-hunt",
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
    ),
    PhaseSpec(
        name="binary_audit",
        directive=_BINARY_AUDIT_DIRECTIVE,
        condition=make_discovery_condition("discovery"),
        capability="binary-audit",
        trust="advisory",
        allowed_servers=("ida_headless",),
    ),
    PhaseSpec(
        name="mobile_audit",
        directive=_MOBILE_AUDIT_DIRECTIVE,
        condition=make_discovery_condition("discovery"),
        capability="mobile-audit",
        trust="advisory",
        allowed_servers=("android_mcp", "audit_mcp"),
    ),
    PhaseSpec(
        name="poc_development",
        directive=_POC_DEV_DIRECTIVE,
        condition=make_discovery_condition("discovery", confirmed_only=True),
        capability="exploit-dev",
        trust="confirmed",
        allowed_servers=("audit_mcp", "ida_headless"),
    ),
)


VR_INVESTIGATE_HUB = build_dispatch_workflow(
    "vr.investigate.hub",
    VR_HUB_PHASES,
    services_factory=_build_services,
    setup_builder=_setup_builder,
    loop_builder=_loop_builder,
    emit_handler=cast("HandlerFn", state_investigation_emit),
)
