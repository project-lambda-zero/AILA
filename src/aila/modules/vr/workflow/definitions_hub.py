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
from aila.platform.services.ledger import LedgerService, make_discovery_condition
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

# Scoped phase turn caps -- tightly bounded so single phases do not
# monopolize the investigation budget and downstream specialized phases activate.
_RECON_MAX_TURNS = 15
_AUDIT_PHASE_MAX_TURNS = 20
_BINARY_PHASE_MAX_TURNS = 25
_HARDENING_PHASE_MAX_TURNS = 15
_POC_DEV_MAX_TURNS = 20

_POC_DEV_DIRECTIVE = (
    "POC DEVELOPMENT PHASE. Objective: turn a confirmed exploitable "
    "finding into a working proof of concept -- reach the vulnerable "
    "state, control the primitive, and demonstrate impact. Pursue only a "
    "finding the panel has confirmed by quorum or verified taint path. "
    "Submit the PoC script in payload.poc_code with the trigger and observed effect."
)

_HUB_RECON_DIRECTIVE = (
    "RECON PHASE. Objective: characterize the target scope and entry "
    "points and surface the most promising audit targets. For each "
    "promising surface, raise a concrete hypothesis naming the entry point "
    "and the sink you suspect -- the hub turns your recon hypotheses into "
    "shared discoveries that route the panel to the deep audit phases. "
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

_SOURCE_AUDIT_DIRECTIVE = (
    "SOURCE AUDIT PHASE. Objective: systematically audit the source for "
    "exploitable vulnerability classes -- trace untrusted input to "
    "dangerous sinks, read the candidate function bodies, and confirm each "
    "finding with evidence. Submit confirmed findings."
)

_TAINT_ANALYSIS_DIRECTIVE = (
    "TAINT ANALYSIS PHASE. Objective: trace each untrusted-input entry "
    "point to the dangerous sinks it can reach. Follow the data flow across "
    "function boundaries (callers_of, entrypoint paths, and read the "
    "intermediate bodies), and confirm the tainted value reaches the sink "
    "without an effective sanitizer. Record the exact source -- sink path. "
    "Submit confirmed reachable taint paths with evidence."
)

_INJECTION_AUDIT_DIRECTIVE = (
    "INJECTION AUDIT PHASE. Objective: systematically audit for injection "
    "vulnerabilities -- SQL injection (raw query concatenation in DAOs / repositories), "
    "Command Injection (ProcessBuilder, Runtime.exec, os.system, subprocess), "
    "Template Injection / SSTI (Freemarker, Thymeleaf, Jinja2, Velocity), "
    "Dynamic Expression Evaluation (OGNL, SpEL, JXPath, JEXL, MVEL), and XPath / LDAP injection. "
    "Trace untrusted string interpolation and property expansion directly to parser evaluation. "
    "Submit confirmed injection primitives with the reachable trigger payload."
)

_DESERIALIZATION_AUDIT_DIRECTIVE = (
    "DESERIALIZATION AUDIT PHASE. Objective: audit object deserialization and "
    "unsafe parser configurations. Hunt for Java ObjectInputStream.readObject, "
    "XMLDecoder, Jackson / Fastjson polymorphic typing (@JsonTypeInfo, enableDefaultTyping), "
    "SnakeYAML / PyYAML unsafe loaders, Python pickle.loads / yaml.load, .NET BinaryFormatter / "
    "TypeNameHandling, PHP unserialize, and unsafe JNDI lookups (InitialContext.lookup, LDAP/RMI). "
    "Identify reachable gadget chains and remote code execution paths. Submit confirmed deserialization findings."
)

_AUTH_BYPASS_AUDIT_DIRECTIVE = (
    "AUTH BYPASS AUDIT PHASE. Objective: audit authentication, authorization matrices, "
    "and access control boundaries. Analyze JWT signature verification (none algorithm, weak secret, "
    "RS256/HS256 key confusion, jku/jwk header injection), OAuth2 state / redirect manipulation, "
    "Insecure Direct Object References (IDOR), RBAC/ABAC enforcement gaps, SecurityFilterChain order, "
    "and URL dispatcher path traversal (..;, /..;/, %2e%2e). Submit confirmed authentication bypasses."
)

_MEMORY_SAFETY_AUDIT_DIRECTIVE = (
    "MEMORY SAFETY AUDIT PHASE. Objective: audit native code for memory corruption "
    "primitives -- Use-After-Free (UAF), double-free, Out-of-Bounds (OOB) read / write, "
    "heap buffer overflows, stack overflows, type confusion, and integer signedness / wrap flaws "
    "(int32_t to size_t conversion). Trace allocator lifetimes (malloc, free, realloc, custom arenas) "
    "and pointer arithmetic. Submit confirmed memory safety vulnerabilities with crash analysis."
)

_KERNEL_DRIVER_AUDIT_DIRECTIVE = (
    "KERNEL & DRIVER AUDIT PHASE. Objective: audit ring-0 interfaces, kernel drivers, "
    "and system extensions. Analyze IOCTL dispatch tables (DeviceIoControl), METHOD_NEITHER / "
    "METHOD_BUFFERED user pointer validation, ProbeForRead / ProbeForWrite omissions, double-fetch "
    "race conditions from user memory, arbitrary physical memory mapping, and privileged callback registration. "
    "Submit confirmed kernel privilege escalation primitives."
)

_CONCURRENCY_AUDIT_DIRECTIVE = (
    "CONCURRENCY AUDIT PHASE. Objective: audit concurrency, multithreading, and "
    "asynchronous state management. Identify Time-of-Check to Time-of-Use (TOCTOU) file and resource races, "
    "non-atomic database check-and-update patterns, unsafe double-checked locking, mutable shared state without "
    "synchronization primitives, and reentrancy bugs in async event loops and coroutines. "
    "Submit confirmed race condition vulnerabilities with interleaving traces."
)

_PROTOCOL_STATE_AUDIT_DIRECTIVE = (
    "PROTOCOL STATE AUDIT PHASE. Objective: audit network protocols, framing parsers, "
    "and state machines. Hunt for HTTP request smuggling (CL.TE, TE.CL, TE.TE, HTTP/2 desync), "
    "WebSocket framing / masking vulnerabilities, custom binary protocol packet desyncs, and "
    "protocol state machine confusion where privileged commands execute in unauthenticated states. "
    "Submit confirmed protocol desync vulnerabilities."
)

_SIDE_CHANNEL_AUDIT_DIRECTIVE = (
    "SIDE CHANNEL AUDIT PHASE. Objective: audit timing side-channels, cryptographic comparison "
    "oracles, and information leakage. Analyze non-constant-time comparisons (memcmp, string equals on HMACs/tokens), "
    "padding oracle vulnerabilities in CBC ciphers, cache-timing leakages, and differential error responses "
    "that leak internal key material or database state. Submit confirmed side-channel leakage primitives."
)

_COMPILER_HARDENING_AUDIT_DIRECTIVE = (
    "COMPILER HARDENING AUDIT PHASE. Objective: audit binary protections and exploit mitigations: "
    "ASLR/PIE, stack canaries (-fstack-protector-all), Full/Partial RELRO, SafeSEH / Control Flow Guard (CFG), "
    "Clang CFI, ARM PAC/BTI, Fortify Source, and RPATH / RUNPATH security. Identify missing binary protections "
    "that enable exploitation. Submit confirmed hardening gaps with binary metadata."
)

_PATCH_DIFF_AUDIT_DIRECTIVE = (
    "PATCH DIFF AUDIT PHASE. Objective: reverse-engineer security commits, CVE patches, and "
    "bugfix diffs. Analyze previous fixes for incomplete remediation, filter bypasses on patched functions, "
    "regressions introduced during refactoring, and adjacent functions carrying identical unpatched bugs. "
    "Submit confirmed 1-day / variant vulnerabilities with patch diff evidence."
)

_SANDBOX_ESCAPE_AUDIT_DIRECTIVE = (
    "SANDBOX ESCAPE AUDIT PHASE. Objective: audit isolation boundaries, seccomp filters, "
    "and containerization escapes. Analyze seccomp BPF filters, Linux namespace usage (CLONE_NEWUSER, CLONE_NEWNS), "
    "unshare / chroot jailbreaks, mount namespace escapes, and host-guest communication channels in virtualized "
    "environments. Submit confirmed sandbox escape primitives."
)

_FILTER_BYPASS_SYNTHESIS_DIRECTIVE = (
    "FILTER BYPASS SYNTHESIS PHASE. Objective: synthesize WAF and filter evasions when a candidate "
    "exploit payload encounters signature rejection. Mutate payload structure using alternative encodings "
    "(Unicode normalization, double URL encoding, comment injection, whitespace substitution, parameter pollution, "
    "case variation, null-byte truncation) while preserving execution semantics. Submit refined bypass payloads."
)

_EXPLOIT_PRIMITIVE_COMPOSITION_DIRECTIVE = (
    "EXPLOIT PRIMITIVE COMPOSITION PHASE. Objective: compose individual findings into an end-to-end "
    "exploit chain. Chain memory leak / address discovery primitives with write-what-where primitives, "
    "or combine unauthenticated SSRF with internal admin API access to achieve reliable Remote Code Execution. "
    "Submit the integrated end-to-end exploit chain with execution instructions."
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

# Dispatch-hub activation priority tiers (#245). The hub evaluates phases by
# descending PhaseSpec.priority (ties broken by declaration order), so the
# order below is the routing intent, not the tuple position:
#   * recon runs FIRST -- it characterizes the target before any audit or
#     exploit phase (it is unconditional, so only visit-once removes it).
#   * once a finding is confirmed, the exploit-verification phases activate
#     ahead of every audit phase; poc_development (build the PoC) leads,
#     then exploit_primitive_composition (chain primitives), then the
#     situational, advisory-trust filter_bypass_synthesis (it must NOT
#     outrank the confirmed PoC target, so it sits lowest of the three).
#   * a specialized deep-dive whose vulnerability class recon actually named
#     runs ahead of the generic source sweeps.
#   * the generic sweeps and kind-only fallbacks run next.
#   * continued_hunt is the terminal catch-all, last.
_PRIORITY_RECON = 110
_PRIORITY_POC = 100
_PRIORITY_EXPLOIT_COMPOSE = 96
_PRIORITY_FILTER_BYPASS = 92
_PRIORITY_SPECIALIZED = 50
_PRIORITY_BASELINE = 10
_PRIORITY_TERMINAL = 0

# Keyword sets for the discovery-gated specialized audit phases (#245). A
# specialized phase activates only when a shared-ledger discovery names its
# vulnerability class -- any keyword below appears (case-insensitive
# substring) in the discovery's claim, rationale, or kill-criterion -- so
# the panel is routed to the phase that matches what recon surfaced instead
# of walking every kind-eligible audit phase in declaration order.
_INJECTION_KEYWORDS = frozenset({
    "injection", "sql", "cql", "command", "ssti", "eval",
    "ognl", "spel", "xpath", "ldap", "template",
})
_DESERIALIZATION_KEYWORDS = frozenset({
    "deserial", "objectinputstream", "readobject", "pickle", "yaml",
    "fastjson", "jackson", "jndi", "unserialize", "binaryformatter", "gadget",
})
_AUTH_BYPASS_KEYWORDS = frozenset({
    "auth", "jwt", "oauth", "idor", "rbac", "abac",
    "session", "token", "redirect", "bypass",
})
_CONCURRENCY_KEYWORDS = frozenset({
    "race", "toctou", "concurren", "thread", "atomic",
    "deadlock", "reentran", "double-fetch", "lock",
})
_PROTOCOL_STATE_KEYWORDS = frozenset({
    "protocol", "http", "smuggl", "websocket",
    "framing", "desync", "packet", "state machine",
})
_MEMORY_SAFETY_KEYWORDS = frozenset({
    "uaf", "use-after-free", "overflow", "oob", "out-of-bounds",
    "allocator", "free", "heap", "stack", "integer",
    "malloc", "memcpy", "type confusion",
})
_KERNEL_DRIVER_KEYWORDS = frozenset({
    "ioctl", "driver", "kernel", "method_neither", "deviceiocontrol",
    "probeforread", "ring0", "ring-0",
})


async def _resolve_target_kind(investigation_id: str) -> str | None:
    """Return the investigation's primary target ``kind`` (lowercased), or None.

    Shared by :func:`_make_target_kind_condition` and
    :func:`_make_specialized_phase_condition` so the two dispatch conditions
    read the target the same way. The VR db-model + UoW imports stay
    top-level here (this file loads after ``db_models`` is registered).
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            ),
        )).first()
        if inv is None or not inv.target_id:
            return None
        target = (await uow.session.exec(
            select(VRTargetRecord).where(
                VRTargetRecord.id == inv.target_id,
            ),
        )).first()
    if target is None:
        return None
    return (target.kind or "").strip().lower()


def _make_specialized_phase_condition(
    kinds: frozenset[str],
    keywords: frozenset[str],
) -> Callable[[dict[str, Any]], Awaitable[tuple[bool, str]]]:
    """Build a dispatch-hub condition for a discovery-gated specialized phase.

    Fires when the investigation's target kind is in *kinds* AND at least one
    shared-ledger ``discovery`` entry names the phase's vulnerability class --
    any *keyword* appears (case-insensitive substring) in the discovery's
    ``claim``, ``why_plausible``, or ``kill_criterion``. This routes the panel
    to the specialized phase recon actually pointed at, rather than activating
    every kind-eligible audit phase.

    A ratified replan (``_dispatch_replan_relax``) waives the keyword gate: the
    phase then activates on target kind alone, so an operator/panel replan can
    still reach a specialized phase recon did not explicitly name.
    """
    lowered = tuple(kw.lower() for kw in keywords)

    async def _cond(state_input: dict[str, Any]) -> tuple[bool, str]:
        investigation_id = state_input.get("investigation_id")
        if not investigation_id:
            return False, "no investigation_id on dispatch input"
        tk = await _resolve_target_kind(str(investigation_id))
        if tk is None:
            return False, "no target for investigation"
        if tk not in kinds:
            return False, f"target kind {tk!r} not in {sorted(kinds)}"
        if state_input.get("_dispatch_replan_relax"):
            return True, f"replan relax: target kind {tk} (keyword gate waived)"
        discoveries = await LedgerService().read_general(
            str(investigation_id), kinds=["discovery"],
        )
        for row in discoveries:
            payload = row.get("payload") or {}
            haystack = " ".join((
                str(payload.get("claim") or ""),
                str(payload.get("why_plausible") or ""),
                str(payload.get("kill_criterion") or ""),
            )).lower()
            hit = next((kw for kw in lowered if kw in haystack), None)
            if hit is not None:
                return True, f"target kind {tk}; discovery names {hit!r}"
        return False, (
            f"target kind {tk} matches but no discovery names this class"
        )

    return _cond


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
        tk = await _resolve_target_kind(str(investigation_id))
        if tk is None:
            return False, "no target for investigation"
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
        priority=_PRIORITY_RECON,
    ),
    PhaseSpec(
        name="source_audit",
        directive=_SOURCE_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_SOURCE_KINDS),
        capability="source-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp",),
        priority=_PRIORITY_BASELINE,
    ),
    PhaseSpec(
        name="taint_analysis",
        directive=_TAINT_ANALYSIS_DIRECTIVE,
        condition=_make_target_kind_condition(_SOURCE_KINDS),
        capability="source-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp",),
        priority=_PRIORITY_BASELINE,
    ),
    PhaseSpec(
        name="injection_audit",
        directive=_INJECTION_AUDIT_DIRECTIVE,
        condition=_make_specialized_phase_condition(
            _SOURCE_KINDS, _INJECTION_KEYWORDS,
        ),
        capability="source-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp",),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="deserialization_audit",
        directive=_DESERIALIZATION_AUDIT_DIRECTIVE,
        condition=_make_specialized_phase_condition(
            _SOURCE_KINDS, _DESERIALIZATION_KEYWORDS,
        ),
        capability="source-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp",),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="auth_bypass_audit",
        directive=_AUTH_BYPASS_AUDIT_DIRECTIVE,
        condition=_make_specialized_phase_condition(
            _SOURCE_KINDS, _AUTH_BYPASS_KEYWORDS,
        ),
        capability="source-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp",),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="concurrency_audit",
        directive=_CONCURRENCY_AUDIT_DIRECTIVE,
        condition=_make_specialized_phase_condition(
            _SOURCE_KINDS, _CONCURRENCY_KEYWORDS,
        ),
        capability="source-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp",),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="protocol_state_audit",
        directive=_PROTOCOL_STATE_AUDIT_DIRECTIVE,
        condition=_make_specialized_phase_condition(
            _SOURCE_KINDS, _PROTOCOL_STATE_KEYWORDS,
        ),
        capability="source-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp",),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="dependency_audit",
        directive=_DEPENDENCY_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_SOURCE_KINDS),
        capability="source-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp",),
        priority=_PRIORITY_BASELINE,
    ),
    PhaseSpec(
        name="memory_safety_audit",
        directive=_MEMORY_SAFETY_AUDIT_DIRECTIVE,
        condition=_make_specialized_phase_condition(
            _VARIANT_KINDS, _MEMORY_SAFETY_KEYWORDS,
        ),
        capability="binary-audit",
        max_turns=_BINARY_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="kernel_driver_audit",
        directive=_KERNEL_DRIVER_AUDIT_DIRECTIVE,
        condition=_make_specialized_phase_condition(
            _BINARY_KINDS, _KERNEL_DRIVER_KEYWORDS,
        ),
        capability="binary-audit",
        max_turns=_BINARY_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("ida_headless",),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="compiler_hardening_audit",
        directive=_COMPILER_HARDENING_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="binary-audit",
        max_turns=_HARDENING_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="sandbox_escape_audit",
        directive=_SANDBOX_ESCAPE_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="binary-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="crypto_audit",
        directive=_CRYPTO_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="crypto",
        max_turns=_HARDENING_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="side_channel_audit",
        directive=_SIDE_CHANNEL_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="crypto",
        max_turns=_HARDENING_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="variant_hunt",
        directive=_VARIANT_HUNT_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="variant-hunt",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="patch_diff_audit",
        directive=_PATCH_DIFF_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="variant-hunt",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
        priority=_PRIORITY_SPECIALIZED,
    ),
    PhaseSpec(
        name="binary_audit",
        directive=_BINARY_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_BINARY_KINDS),
        capability="binary-audit",
        max_turns=_BINARY_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("ida_headless",),
        priority=_PRIORITY_BASELINE,
    ),
    PhaseSpec(
        name="mobile_audit",
        directive=_MOBILE_AUDIT_DIRECTIVE,
        condition=_make_target_kind_condition(_MOBILE_KINDS),
        capability="mobile-audit",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("android_mcp", "audit_mcp"),
        priority=_PRIORITY_BASELINE,
    ),
    PhaseSpec(
        name="fuzz_targeting",
        directive=_FUZZ_TARGETING_DIRECTIVE,
        condition=_make_target_kind_condition(_VARIANT_KINDS),
        capability="fuzz",
        max_turns=_HARDENING_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless"),
        priority=_PRIORITY_BASELINE,
    ),
    PhaseSpec(
        name="filter_bypass_synthesis",
        directive=_FILTER_BYPASS_SYNTHESIS_DIRECTIVE,
        condition=make_discovery_condition(
            "discovery",
            payload_exclude={"source": "recon_hypothesis"},
        ),
        capability="exploit-dev",
        max_turns=_HARDENING_PHASE_MAX_TURNS,
        trust="advisory",
        allowed_servers=("audit_mcp", "ida_headless", "poc_runner"),
        priority=_PRIORITY_FILTER_BYPASS,
    ),
    PhaseSpec(
        name="exploit_primitive_composition",
        directive=_EXPLOIT_PRIMITIVE_COMPOSITION_DIRECTIVE,
        condition=make_discovery_condition(
            "discovery",
            payload_exclude={"source": "recon_hypothesis"},
        ),
        capability="exploit-dev",
        max_turns=_AUDIT_PHASE_MAX_TURNS,
        trust="confirmed",
        allowed_servers=("audit_mcp", "ida_headless", "poc_runner"),
        priority=_PRIORITY_EXPLOIT_COMPOSE,
    ),
    PhaseSpec(
        name="poc_development",
        directive=_POC_DEV_DIRECTIVE,
        condition=make_discovery_condition(
            "discovery",
            payload_exclude={"source": "recon_hypothesis"},
        ),
        capability="exploit-dev",
        max_turns=_POC_DEV_MAX_TURNS,
        trust="confirmed",
        allowed_servers=("audit_mcp", "ida_headless", "poc_runner"),
        priority=_PRIORITY_POC,
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
        priority=_PRIORITY_TERMINAL,
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
