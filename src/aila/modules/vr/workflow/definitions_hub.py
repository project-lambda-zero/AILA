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

from collections.abc import Awaitable, Callable
from typing import Any, cast

from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.index_readiness import vr_index_readiness
from aila.modules.vr.workflow.definitions import _build_services
from aila.modules.vr.workflow.states.investigation_emit import (
    state_investigation_emit,
)
from aila.modules.vr.workflow.states.investigation_loop import _LOOP_BINDINGS
from aila.modules.vr.workflow.states.investigation_setup import (
    _SETUP_BINDINGS,
    _SETUP_HOOKS,
)
from aila.platform.services.ledger import make_discovery_condition
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
    DispatchEscalationModels,
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

# Hub-specific recon directive. The V2 kind-router recon directive tells
# the agent to "submit a scoping outcome" -- correct there because the
# router auto-transitions recon -> source_audit. In the discovery-driven
# hub a terminal submit ENDS the branch, so that directive made the panel
# short-circuit to a draft at recon instead of progressing. Here recon
# advances by POSTING DISCOVERIES: the hub converts recon hypotheses into
# shared ledger discoveries that activate the deep audit phases, so the
# agent must surface hypotheses and must NOT submit a terminal finding yet.
_HUB_RECON_DIRECTIVE = (
    "RECON PHASE. Objective: characterize the target scope and entry "
    "points and surface the most promising audit targets. For each "
    "promising surface, raise a concrete hypothesis naming the entry point "
    "and the sink you suspect -- the hub turns your recon hypotheses into "
    "shared discoveries that route the panel to the deep audit phase. "
    "Name the entry surface that fits this target class. For a web server "
    "or network daemon, that is the request and config parsers, the "
    "protocol state machine, and header, URI, and module-dispatch handling. "
    "For a media or codec library, it is the demuxers, decoders, and "
    "container-format parsers that consume untrusted bytes. For a native "
    "binary or driver, it is the exported functions, the ioctl and "
    "device-IO handlers, and any parse of an externally supplied structure. "
    "For an application framework, it is request routing, deserialization, "
    "template or expression evaluation, and file upload. Do "
    "NOT submit a terminal finding in this phase, and do NOT start a "
    "systematic audit or a PoC yet: recon hands off automatically once you "
    "have surfaced discoveries."
)

_TAINT_ANALYSIS_DIRECTIVE = (
    "TAINT ANALYSIS PHASE. Objective: trace each untrusted-input entry "
    "point to the dangerous sinks it can reach. Follow the data flow across "
    "function boundaries (callers_of, entrypoint paths, and read the "
    "intermediate bodies), and confirm the tainted value reaches the sink "
    "without an effective sanitizer. Record the exact source -- sink path. "
    "Submit confirmed reachable taint paths with evidence."
)
_DEPENDENCY_AUDIT_DIRECTIVE = (
    "DEPENDENCY AUDIT PHASE. Objective: audit the target's declared and "
    "transitive dependencies for known-vulnerable versions and supply-chain "
    "risk. Read the manifests and lockfiles, flag pinned versions with known "
    "CVEs or unmaintained packages, and check whether the vulnerable "
    "dependency code is actually reached from the target. Submit confirmed "
    "vulnerable dependencies with the affected version and the reachable use."
)
_CRYPTO_AUDIT_DIRECTIVE = (
    "CRYPTO AUDIT PHASE. Objective: audit cryptographic usage for misuse -- "
    "weak or broken primitives (MD5, SHA1, DES, RC4, ECB mode), static or "
    "hardcoded keys, IVs, and nonces, weak or predictable randomness, "
    "unauthenticated encryption, and improper certificate or signature "
    "validation. Trace each crypto call to the source of its key, IV, and "
    "nonce. Submit confirmed crypto weaknesses with the responsible code and "
    "the concrete impact."
)
_FUZZ_TARGETING_DIRECTIVE = (
    "FUZZ TARGETING PHASE. Objective: identify the highest-value fuzz targets "
    "-- parsers, decoders, deserializers, and any function that consumes "
    "untrusted bytes -- and specify a harness for each: the entry function, "
    "the input shape, and any required setup. Rank the targets by "
    "attack-surface exposure and reachability from untrusted input. Submit "
    "the ranked fuzz targets with the rationale for each."
)

# Recon only scopes the target, so it is capped tighter than the deep
# phases (which fall back to the module turn-cap reader).
_RECON_MAX_TURNS = 20

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
# Terminal open-ended hunt phase. The scoped audit phases each complete in
# a few turns and exhaust in ~15-25 turns, well under the turn budget. This
# phase is entered ONCE, last, and runs the agent's adaptive loop with its
# max_turns defaulting to the overall turn cap: the loop only exits on a
# finding submission (terminal_submit -> poc_development), a terminal
# branch/investigation state, or the turn cap -- so a single activation
# keeps hunting toward the budget as one workflow step (turns are loop
# iterations inside one state, not state transitions, so this never
# accrues the per-job step count that MAX_STEPS_PER_JOB guards). Its
# retriable per-state timeout resumes it across jobs so the run reaches
# the wall clock. Operator directive: go to the wall, never stop early.
_CONTINUED_HUNT_DIRECTIVE = (
    "CONTINUED HUNT PHASE. The scoped audit phases have run; the turn "
    "budget still holds. Objective: keep hunting for a real, current "
    "vulnerability. Pick angles the prior phases did not close: deepen the "
    "strongest live hypothesis with fresh evidence (read the sink body, "
    "trace the untrusted-input path end to end, check the guards), then "
    "attack a vulnerability class not yet examined. Do not repeat a "
    "completed line of analysis and do not declare the target clean "
    "without exhausting the reachable input-to-sink paths. Submit only a "
    "confirmed finding, with the evidence that proves it."
)
# continued_hunt resumes on each retriable per-state timeout (default
# 9000s == 2.5h). Sized so those resumes span the 144h investigation wall
# clock (144 / 2.5 ~= 58) rather than the phase retry budget ending the
# hunt first; the wall clock and turn budget stay the true terminals.
_CONTINUED_HUNT_MAX_RETRIES = 60

# Audit-phase activation keys off the target's kind (RFC-13 #68 hub
# routing). Gating on shared-ledger discoveries alone stalled the hub
# when recon posted no discoveries, and let a source-repo investigation
# walk into binary_audit / mobile_audit (whose allowed_servers block
# the source path). The kind sets below scope each audit phase to the
# target payloads it can actually operate on; poc_development stays
# discovery-gated because it must only activate on a confirmed finding.
_SOURCE_KINDS = frozenset({"source_repo"})
_BINARY_KINDS = frozenset({
    "native_binary",
    "jar",
    "dotnet_assembly",
    "kernel_image",
    "kernel_module",
    "hypervisor_image",
})
_MOBILE_KINDS = frozenset({"android_apk", "ipa"})
_VARIANT_KINDS = _SOURCE_KINDS | _BINARY_KINDS


def _make_target_kind_condition(
    kinds: frozenset[str],
) -> Callable[[dict[str, Any]], Awaitable[tuple[bool, str]]]:
    """Build a dispatch-hub condition that fires when the investigation's
    primary target has a ``kind`` in *kinds*.

    The returned async predicate matches the phase-graph ``GateFn`` shape
    (``make_discovery_condition``'s ``(bool, reason)`` contract). This
    module is a VR-side file that loads AFTER ``db_models`` is fully
    built (the module task graph imports ``definitions_hub`` at startup
    once ``db_models`` is registered), so the VR db-model + UoW imports
    stay top-level here rather than adopting the deferred-import shape
    ``phase_graph._replan_ratified`` uses for the platform-side cycle.
    """

    async def _cond(state_input: dict[str, Any]) -> tuple[bool, str]:
        investigation_id = state_input.get("investigation_id")
        if not investigation_id:
            return False, "no investigation_id on dispatch input"
        async with UnitOfWork() as uow:
            inv = (await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == investigation_id,
                ),
            )).first()
            if inv is None or not inv.target_id:
                return False, "no target for investigation"
            target = (await uow.session.exec(
                select(VRTargetRecord).where(
                    VRTargetRecord.id == inv.target_id,
                ),
            )).first()
        if target is None:
            return False, "no target for investigation"
        tk = (target.kind or "").strip().lower()
        if tk in kinds:
            return True, f"target kind {tk} matches {sorted(kinds)}"
        return False, f"target kind {tk!r} not in {sorted(kinds)}"

    return _cond


def _setup_builder(next_state: str) -> HandlerFn:
    """Bind the VR setup handler with the graph start transition."""
    return _build_setup_state(_SETUP_BINDINGS, _SETUP_HOOKS, next_state=next_state)


def _loop_builder(phase: PhaseSpec, next_state: str) -> HandlerFn:
    """Bind the VR loop handler with the phase mission, cap, and tool regime."""
    # RFC-12: the read-only knowledge bridge is a universal server, reachable
    # in every phase (workspace-scoped server-side, no write path). Union it
    # into the phase tool gate so agentic knowledge.retrieve is not hard-
    # rejected by a phase whose allowed_servers lists only code-analysis
    # backends. A None gate (no phase restriction) already permits it.
    phase_servers = (
        (*phase.allowed_servers, "knowledge")
        if phase.allowed_servers
        else phase.allowed_servers
    )
    return _build_loop_state(
        _LOOP_BINDINGS,
        InvestigationStateHooks(),
        next_state=next_state,
        phase_directive=phase.directive,
        phase_max_turns=phase.max_turns,
        phase_allowed_servers=phase_servers,
        phase_strategy_family=phase.strategy_family,
    )


VR_HUB_PHASES: tuple[PhaseSpec, ...] = (
    PhaseSpec(
        name="recon",
        directive=_HUB_RECON_DIRECTIVE,
        max_turns=_RECON_MAX_TURNS,
        allowed_servers=("audit_mcp", "ida_headless"),
        trust="confirmed",
    ),
    PhaseSpec(
        name="source_audit",
        directive=_SOURCE_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_SOURCE_KINDS),
        capability="source-audit",
        trust="advisory",
        allowed_servers=("audit_mcp",),
    ),
    PhaseSpec(
        name="taint_analysis",
        directive=_TAINT_ANALYSIS_DIRECTIVE,
        condition=_make_target_kind_condition(_SOURCE_KINDS),
        capability="source-audit",
        trust="advisory",
        allowed_servers=("audit_mcp",),
    ),
    PhaseSpec(
        name="dependency_audit",
        directive=_DEPENDENCY_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_SOURCE_KINDS),
        capability="source-audit",
        trust="advisory",
        allowed_servers=("audit_mcp",),
    ),
    PhaseSpec(
        name="crypto_audit",
        directive=_CRYPTO_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="crypto",
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
    ),
    PhaseSpec(
        name="variant_hunt",
        directive=_VARIANT_HUNT_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="variant-hunt",
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
    ),
    PhaseSpec(
        name="binary_audit",
        directive=_BINARY_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_BINARY_KINDS),
        capability="binary-audit",
        trust="advisory",
        allowed_servers=("ida_headless",),
    ),
    PhaseSpec(
        name="mobile_audit",
        directive=_MOBILE_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_MOBILE_KINDS),
        capability="mobile-audit",
        trust="advisory",
        allowed_servers=("android_mcp", "audit_mcp"),
    ),
    PhaseSpec(
        name="fuzz_targeting",
        directive=_FUZZ_TARGETING_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="fuzz",
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
    ),
    PhaseSpec(
        name="poc_development",
        directive=_POC_DEV_DIRECTIVE,
        condition=make_discovery_condition(
            "discovery",
            payload_exclude={"source": "recon_hypothesis"},
        ),
        capability="exploit-dev",
        trust="confirmed",
        allowed_servers=("audit_mcp", "ida_headless"),
    ),
    # Terminal open-ended hunt. Unconditional (no ``condition``) so it
    # activates for any target kind once every scoped phase above has been
    # visited, and declared LAST so the hub reaches it only after the scoped
    # phases (the hub returns the first eligible unvisited phase). Entered
    # ONCE: its max_turns defaults to the overall turn cap, so one activation
    # runs the agent's loop toward the budget as a single step; the retriable
    # per-state timeout (timeout_retriable) resumes it across jobs, and a
    # high max_retries lets those resumes span the investigation wall clock
    # instead of the phase retry budget capping the run early.
    PhaseSpec(
        name="continued_hunt",
        directive=_CONTINUED_HUNT_DIRECTIVE,
        capability=None,
        allowed_servers=("audit_mcp", "ida_headless"),
        max_retries=_CONTINUED_HUNT_MAX_RETRIES,
        catch_all=True,
    ),
)


VR_INVESTIGATE_HUB = build_dispatch_workflow(
    "vr.investigate.hub",
    VR_HUB_PHASES,
    services_factory=_build_services,
    setup_builder=_setup_builder,
    loop_builder=_loop_builder,
    emit_handler=cast("HandlerFn", state_investigation_emit),
    escalation_models=DispatchEscalationModels(
        message_model=VRInvestigationMessageRecord,
        branch_model=VRInvestigationBranchRecord,
    ),
    index_readiness_fn=vr_index_readiness,
)
