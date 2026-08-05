"""Phase-graph substrate: a graph of adaptive loops over the durable engine.

A module declares its investigation lifecycle as a :class:`PhaseGraphSpec` --
coarse phases, each a bounded adaptive turn loop with its own prompt family,
tool allowlist, and turn cap -- wired by static edges, routers, and entry
gates. :func:`build_phase_workflow` expands the spec into a
:class:`WorkflowDefinition` the :class:`DurableStateMachine` runs, wrapping
the domain phases with the shared setup (start) and emit (terminal) states.

The turn mechanics stay in the loop factory; this module only assembles the
graph, so every module rides one substrate. A phase's public entry name is
its gate (when it declares an ``entry_gate``) or its loop, so routers and
edges always target ``phase.name`` and gating stays transparent to callers.
The loop and setup handlers are supplied by the module as builders (they own
the record models + factories); the router and gate handlers are pure
control flow and live here.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from aila.platform.workflows.types import (
    HandlerFn,
    StateResult,
    StateSpec,
    WorkflowDefinition,
    WorkflowServices,
)

__all__ = [
    "DISPATCH_STATE",
    "EMIT_STATE",
    "SETUP_STATE",
    "DispatchEscalationModels",
    "GateFn",
    "LoopBuilder",
    "PhaseGraphSpec",
    "PhaseSpec",
    "RouterFn",
    "SetupBuilder",
    "build_dispatch_workflow",
    "build_phase_workflow",
    "make_dispatch_router",
    "make_gate_state",
    "make_router_state",
]

_log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class DispatchEscalationModels:
    """Module-specific SQLModel record types the dispatch-hub escalation posts against.

    RFC-13 #68 stall escalation writes an operator-steering message using
    the module's own ``<Module>InvestigationMessageRecord`` and
    ``<Module>InvestigationBranchRecord`` tables, so the message lands in
    the same view the module's UI and its agent-side broadcast reader
    consume from. The dispatch handler is platform-generic and cannot
    reach into a module's ``db_models`` on its own; a module opts into
    live escalation by threading this tuple into
    :func:`build_dispatch_workflow` at graph-registration time.

    When omitted, the hub still emits ``hub_stalled_timeout`` and the
    emit-state ``resolve_final_status`` still flips the investigation
    to STALLED -- only the operator-facing message post is skipped, and
    one info line records the skip so the miss is observable.
    """

    message_model: type[Any]
    branch_model: type[Any]


# Module-level cached ConfigRegistry so per-stall reads share its TTL
# cache instead of building a fresh registry (and losing every prior
# cache hit) on every hub tick. Mirrors ``sse_gate._get_registry``.
_CONFIG_REGISTRY: Any = None
_CONFIG_REGISTRY_LOCK = threading.Lock()


def _get_registry() -> Any:
    """Return the module-cached ConfigRegistry, building it on first call."""
    global _CONFIG_REGISTRY
    if _CONFIG_REGISTRY is not None:
        return _CONFIG_REGISTRY
    with _CONFIG_REGISTRY_LOCK:
        if _CONFIG_REGISTRY is None:
            # Lazy import: aila.storage.registry pulls in db_models and
            # this module is imported early on module-loading; deferring
            # to first-call is the safe (already-established) pattern.
            from aila.storage.registry import ConfigRegistry

            _CONFIG_REGISTRY = ConfigRegistry()
    return _CONFIG_REGISTRY


def _resolve_replan_timeout_s() -> float:
    """Read ``platform.dispatch_replan_timeout_s`` via ConfigRegistry.

    Fall back to the schema default (imported lazily so bootstrap
    ordering never chokes) on any registry failure -- a broken
    registry never turns every stall into a runtime crash. A value
    <= 0 disables the escalation entirely (documented on the schema
    field).
    """
    # Lazy import: config module pulls storage which pulls db_models;
    # keeping this at first-call keeps import order matching sse_gate.
    from aila.platform.config import PlatformConfigSchema

    default_val = float(PlatformConfigSchema().dispatch_replan_timeout_s)
    registry = _get_registry()
    try:
        raw = registry.get_sync("platform", "dispatch_replan_timeout_s")
    except (OSError, RuntimeError, TimeoutError, ValueError, TypeError) as exc:
        _log.debug(
            "dispatch_replan_timeout_s registry read failed: %s -- "
            "falling back to schema default %.0f",
            exc, default_val,
        )
        return default_val
    if raw is None:
        return default_val
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default_val

SETUP_STATE = "investigation_setup"
EMIT_STATE = "investigation_emit"
# The dispatch hub state of a discovery-driven graph (build_dispatch_workflow).
DISPATCH_STATE = "dispatch"

# A router reads the state input (carrying the prior phase's output) and
# returns the name of the next phase to enter.
RouterFn = Callable[[dict[str, Any]], Awaitable[str]]
# A gate reads the state input and returns (allowed, reason). A denied gate
# routes to the phase fallback instead of its loop.
GateFn = Callable[[dict[str, Any]], Awaitable[tuple[bool, str]]]
# A module maps the resolved next-state name to its setup handler, which
# binds the record models and spawns the initial persona branch.
SetupBuilder = Callable[[str], HandlerFn]
# A module maps a phase and its next-state name to that phase's loop
# handler, applying the phase prompt family and tool allowlist.
LoopBuilder = Callable[["PhaseSpec", str], HandlerFn]


@dataclass(frozen=True)
class PhaseSpec:
    """One coarse phase: a bounded adaptive loop with its own regime.

    ``strategy_family``, when set, overrides the prompt family for this
    phase (the turn runner selects the phase's family instead of the
    investigation-level one); None falls back to the investigation's
    ``strategy_family``. ``allowed_servers`` is the phase tool allowlist;
    ``max_turns`` caps the phase; ``directive`` is the phase mission
    surfaced to the agent as a ``_directive.phase_mission`` observable. Exactly one of ``next`` (static
    edge) or ``router`` (dynamic edge) sets the exit; omit both to fall
    through to the terminal emit. ``entry_gate`` guards the phase (readiness
    / approval / custody); a denied gate routes to ``on_fallback`` (default
    emit).

    Dispatch-graph fields (``build_dispatch_workflow``): ``condition`` is
    the activation predicate the hub evaluates (the module-supplied evidence
    reader, which honors ``trust`` itself); ``capability`` is the persona
    specialty that owns the phase (None means any branch may walk it);
    ``trust`` is ``"confirmed"`` (activate only on quorum-confirmed
    discoveries) or ``"advisory"`` (any discovery). These are unused by
    ``build_phase_workflow`` and ``next`` / ``router`` / ``entry_gate`` are
    unused by ``build_dispatch_workflow``.
    """

    name: str
    strategy_family: str | None = None
    allowed_servers: tuple[str, ...] | None = None
    max_turns: int | None = None
    directive: str | None = None
    next: str | None = None
    router: RouterFn | None = None
    entry_gate: GateFn | None = None
    on_fallback: str | None = None
    condition: GateFn | None = None
    capability: str | None = None
    trust: str = "confirmed"
    timeout_s: float = 3600.0
    on_failure: str | None = None
    max_retries: int = 0

    def __post_init__(self) -> None:
        if self.next is not None and self.router is not None:
            raise ValueError(
                f"PhaseSpec {self.name!r} sets both next and router; pick one",
            )
        if self.trust not in ("confirmed", "advisory"):
            raise ValueError(
                f"PhaseSpec {self.name!r} trust must be 'confirmed' or 'advisory'",
            )


@dataclass(frozen=True)
class PhaseGraphSpec:
    """A module lifecycle as a start phase plus its phases."""

    start: str
    phases: tuple[PhaseSpec, ...]

    def __post_init__(self) -> None:
        names = [p.name for p in self.phases]
        if len(names) != len(set(names)):
            raise ValueError("PhaseGraphSpec has duplicate phase names")
        if self.start not in names:
            raise ValueError(
                f"PhaseGraphSpec.start={self.start!r} names no declared phase",
            )


def make_router_state(router: RouterFn) -> HandlerFn:
    """Wrap a module routing function as a state handler."""

    async def _handler(state_input: dict[str, Any], services: Any) -> StateResult:
        del services
        nxt = await router(state_input)
        return StateResult(next_state=nxt, output={**state_input})

    return _handler


def make_gate_state(gate: GateFn, *, on_pass: str, on_fail: str) -> HandlerFn:
    """Wrap a module gate predicate as a state handler.

    Records the decision on the output so a denied entry is visible to the
    operator (and to the fallback phase) rather than a silent skip.
    """

    async def _handler(state_input: dict[str, Any], services: Any) -> StateResult:
        del services
        allowed, reason = await gate(state_input)
        return StateResult(
            next_state=on_pass if allowed else on_fail,
            output={**state_input, "gate_allowed": allowed, "gate_reason": reason},
        )

    return _handler


def build_phase_workflow(
    definition_id: str,
    spec: PhaseGraphSpec,
    *,
    services_factory: Callable[[str], Awaitable[WorkflowServices]],
    setup_builder: SetupBuilder,
    loop_builder: LoopBuilder,
    emit_handler: HandlerFn,
) -> WorkflowDefinition:
    """Expand a phase graph into an engine WorkflowDefinition.

    The shape is setup, then ``spec.start`` and onward through the phases,
    then emit, then the reserved success terminal. Each phase becomes a loop
    state built by the module for its regime and next transition, a
    preceding gate state when it declares an ``entry_gate``, and a following
    router state when it declares a ``router``. Phase public names are stable
    edge targets; the gate and loop split is internal.
    """
    states: dict[str, StateSpec] = {
        SETUP_STATE: StateSpec(
            handler=setup_builder(spec.start),
            timeout_s=60.0,
            max_retries=1,
        ),
    }
    for phase in spec.phases:
        if phase.router is not None:
            route_name = f"{phase.name}__route"
            states[route_name] = StateSpec(
                handler=make_router_state(phase.router), timeout_s=30.0,
            )
            loop_next = route_name
        else:
            loop_next = phase.next or EMIT_STATE
        loop_name = f"{phase.name}__loop" if phase.entry_gate else phase.name
        states[loop_name] = StateSpec(
            handler=loop_builder(phase, loop_next),
            timeout_s=phase.timeout_s,
            on_failure=phase.on_failure,
            max_retries=phase.max_retries,
        )
        if phase.entry_gate is not None:
            states[phase.name] = StateSpec(
                handler=make_gate_state(
                    phase.entry_gate,
                    on_pass=loop_name,
                    on_fail=phase.on_fallback or EMIT_STATE,
                ),
                timeout_s=30.0,
            )
    states[EMIT_STATE] = StateSpec(handler=emit_handler, timeout_s=120.0)
    return WorkflowDefinition(
        definition_id=definition_id,
        start_state=SETUP_STATE,
        states=states,
        services_factory=services_factory,
    )


def make_dispatch_router(
    phases: tuple[PhaseSpec, ...],
    *,
    escalation_models: DispatchEscalationModels | None = None,
) -> HandlerFn:
    """Build the dispatch-hub handler over *phases* (activation, not decision).

    The hub is the per-branch control loop of a discovery-driven graph. On
    each visit it reads the durable ``_dispatch_visited`` set and, in
    declared order, transitions to the first unvisited phase for which all
    hold:

    * the phase ``condition`` is satisfied (None means unconditional); the
      condition is the module-supplied evidence reader and honors the phase
      ``trust`` tier itself;
    * the phase ``capability`` is None (shared) or equals the branch
      capability threaded on the input as ``_branch_capability`` (None on
      the input disables capability filtering, the single-agent shape);
    * the overall budget is not exhausted (``_budget_exhausted`` on the
      input; the platform loop sets it from the investigation turn cap).

    When no unvisited phase qualifies it transitions to ``EMIT_STATE``;
    when the budget is exhausted it emits with a ``budget_truncated``
    marker. The chosen phase is marked visited so it runs at most once per
    branch; ``MAX_STEPS_PER_JOB`` bounds the whole walk. A phase loops back
    to the hub, so a discovery written during one phase can enable a later
    phase on the next visit.

    RFC-13 #68 stall escalation: when the hub stalls (no phase qualifies)
    it raises one ``replan`` request per distinct visited-set. If the
    replan stays unratified longer than ``platform.dispatch_replan_timeout_s``,
    the hub emits the distinct ``hub_stalled_timeout`` exit_reason (the
    emit state flips the investigation to STALLED via
    ``resolve_final_status``) and -- when ``escalation_models`` is
    provided -- posts an operator-steering escalation via
    :func:`aila.platform.agents.auto_steering.post_dispatch_stall_escalation`.
    Within-window stalls continue to emit ``hub_stalled`` (COMPLETED)
    unchanged; ratified replans continue to relax trust for one pass
    unchanged.
    """

    async def _pick(
        state_input: dict[str, Any], visited: set[str], branch_capability: Any,
    ) -> tuple[PhaseSpec | None, str]:
        for phase in phases:
            if phase.name in visited:
                continue
            if (
                phase.capability is not None
                and branch_capability is not None
                and phase.capability != branch_capability
            ):
                continue
            if phase.condition is None:
                return phase, "unconditional"
            # Thread the phase trust so the condition resolves confirmed-vs-
            # advisory from the declared tier (single source of truth), not a
            # value baked into the condition (RFC-13 #68).
            enabled, reason = await phase.condition(
                {**state_input, "_dispatch_phase_trust": phase.trust},
            )
            if enabled:
                return phase, reason
        return None, ""

    def _activate(
        state_input: dict[str, Any], visited: set[str], phase: PhaseSpec, reason: str,
    ) -> StateResult:
        return StateResult(
            next_state=phase.name,
            output={
                **state_input,
                "_dispatch_visited": sorted(visited | {phase.name}),
                "_dispatch_last": phase.name,
                "_dispatch_reason": reason,
            },
        )

    async def _read_replan_rows(investigation_id: str) -> list[dict[str, Any]]:
        # Shared ledger fetch for ratified-check + oldest-replan-age.
        # Lazy import: phase_graph is imported while db_models is still
        # loading (tasks -> workflows -> phase_graph), so importing the
        # services package at module scope would re-enter a half-built
        # db_models. Deferring to call time breaks that cycle.
        from aila.platform.services.ledger import LedgerService
        return await LedgerService().read_general(investigation_id)

    def _replan_ratified_from_rows(rows: list[dict[str, Any]]) -> bool:
        replan_ids = {
            int(r["id"]) for r in rows
            if r["kind"] == "request"
            and (r.get("payload") or {}).get("intent") == "replan"
        }
        for row in rows:
            if row["kind"] != "decision":
                continue
            payload = row.get("payload") or {}
            if payload.get("approved") and int(payload.get("target", -1)) in replan_ids:
                return True
        return False

    def _oldest_unratified_replan_created_at(
        rows: list[dict[str, Any]],
    ) -> datetime | None:
        replan_ids = [
            int(r["id"]) for r in rows
            if r["kind"] == "request"
            and (r.get("payload") or {}).get("intent") == "replan"
        ]
        if not replan_ids:
            return None
        ratified_targets = {
            int((row.get("payload") or {}).get("target", -1))
            for row in rows
            if row["kind"] == "decision"
            and (row.get("payload") or {}).get("approved")
        }
        unratified = [
            row for row in rows
            if row["kind"] == "request"
            and (row.get("payload") or {}).get("intent") == "replan"
            and int(row["id"]) not in ratified_targets
        ]
        if not unratified:
            return None
        # ``rows`` come back oldest-first (LedgerService orders by id), so
        # the first hit is already the earliest. Guard with an explicit
        # min() anyway -- id order tracks created_at monotonically today
        # but I would rather anchor on the timestamp we actually care
        # about than on an incidental ordering.
        oldest_dt: datetime | None = None
        for row in unratified:
            created_at = row.get("created_at")
            if not isinstance(created_at, datetime):
                continue
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=UTC)
            if oldest_dt is None or created_at < oldest_dt:
                oldest_dt = created_at
        return oldest_dt

    async def _post_stall_escalation(
        investigation_id: str, blocked: list[str], replan_age_s: float,
    ) -> None:
        # RFC-13 #68: post one operator-steering escalation for a stall
        # that has aged past the configured window. Best-effort -- the
        # escalation function swallows every error internally, but we
        # log the skip when the module has not bound its record models
        # so the miss is observable during rollout.
        if escalation_models is None:
            _log.info(
                "dispatch stall escalation skipped: no escalation_models "
                "bound for investigation=%s (blocked=%s replan_age_s=%.0f)",
                investigation_id, blocked, replan_age_s,
            )
            return
        # Lazy import matches every other cross-package import in this
        # module -- avoids the db_models load-time cycle.
        from aila.platform.agents.auto_steering import post_dispatch_stall_escalation

        await post_dispatch_stall_escalation(
            investigation_id=investigation_id,
            blocked_phases=blocked,
            replan_age_s=replan_age_s,
            message_model=escalation_models.message_model,
            branch_model=escalation_models.branch_model,
        )

    async def _handle_stall(
        investigation_id: str,
        visited: set[str],
        blocked: list[str],
        state_input: dict[str, Any],
        branch_capability: Any,
    ) -> StateResult | None:
        # Raise one replan request per distinct visited-set (idempotent), then
        # relax confirmed trust for one pass if a replan is already ratified.
        # Lazy import breaks the db_models load-time cycle (see
        # _read_replan_rows).
        from aila.platform.services.ledger import LedgerService
        from aila.platform.uow import UnitOfWork
        service = LedgerService()
        async with UnitOfWork() as uow:
            await service.append_general(
                investigation_id, "__hub__", "request",
                {"intent": "replan", "reason": "no activatable phase",
                 "blocked": blocked},
                idempotency_key=f"replan:{','.join(sorted(visited))}",
                session=uow.session,
            )
            await uow.session.commit()
        rows = await _read_replan_rows(investigation_id)
        if _replan_ratified_from_rows(rows):
            relaxed = {**state_input, "_dispatch_replan_relax": True}
            phase, reason = await _pick(relaxed, visited, branch_capability)
            if phase is not None:
                return _activate(
                    state_input, visited, phase, f"replan-relaxed: {reason}",
                )
        return None

    async def _resolve_stall_timeout(
        investigation_id: str,
    ) -> tuple[bool, float]:
        # Return (timed_out, replan_age_s). A value <= 0 on the window
        # disables escalation and we always return (False, 0.0). Called
        # AFTER _handle_stall's relaxation attempt failed, so the ledger
        # already contains the replan request row we just wrote.
        window_s = _resolve_replan_timeout_s()
        if window_s <= 0:
            return False, 0.0
        rows = await _read_replan_rows(investigation_id)
        earliest = _oldest_unratified_replan_created_at(rows)
        if earliest is None:
            return False, 0.0
        # ``utc_now`` lives in platform.contracts; lazy-import for the
        # same db_models cycle reason as the ledger.
        from aila.platform.contracts import utc_now

        replan_age_s = (utc_now() - earliest).total_seconds()
        return replan_age_s > window_s, replan_age_s

    async def _apply_ratified_requests(investigation_id: str) -> None:
        # Apply every ratified, not-yet-applied ledger request before the hub
        # re-decides, so a panel-approved request (a confirmed discovery, an
        # opened objective) takes effect this visit. The oracle's apply is
        # idempotent. Lazy import breaks the db_models load-time cycle (see
        # _replan_ratified).
        from aila.platform.services.oracle import Oracle
        from aila.platform.uow import UnitOfWork
        async with UnitOfWork() as uow:
            applied = await Oracle().apply_all_ratified(
                investigation_id, session=uow.session,
            )
            if applied:
                await uow.session.commit()

    async def _handler(state_input: dict[str, Any], services: Any) -> StateResult:
        del services
        # ``_budget_exhausted`` is set by the phase loop on its max_turns
        # exit once the branch's cumulative turns reach the overall
        # investigation cap (investigation_loop_base). The hub then emits
        # instead of activating another phase inside this task, enforcing
        # the overall cap within a single hub walk (not only across
        # re-enqueues).
        if state_input.get("_budget_exhausted"):
            return StateResult(
                next_state=EMIT_STATE,
                # Explicit non-continue exit_reason so emit._should_auto_continue
                # does NOT re-enqueue this branch after a hub-level halt --
                # forwarding {**state_input} alone inherited the prior phase
                # loop's stale ``exit_reason='max_turns'`` and produced the
                # 563-task runaway diagnosed on RFC-13.
                output={
                    **state_input,
                    "budget_truncated": True,
                    "exit_reason": "hub_budget_exhausted",
                },
            )
        visited = set(state_input.get("_dispatch_visited") or [])
        branch_capability = state_input.get("_branch_capability")
        investigation_id = state_input.get("investigation_id")
        if investigation_id:
            await _apply_ratified_requests(str(investigation_id))
        phase, reason = await _pick(state_input, visited, branch_capability)
        if phase is not None:
            return _activate(state_input, visited, phase, reason)
        blocked = [
            p.name for p in phases
            if p.name not in visited and p.condition is not None
        ]
        if blocked and investigation_id and not state_input.get(
            "_dispatch_replan_relax"
        ):
            inv_id_str = str(investigation_id)
            relaxed = await _handle_stall(
                inv_id_str, visited, blocked, state_input,
                branch_capability,
            )
            if relaxed is not None:
                return relaxed
            # RFC-13 #68: within-window unratified stall keeps emitting
            # ``hub_stalled`` (COMPLETED via resolve_final_status);
            # timed-out unratified stall emits ``hub_stalled_timeout``
            # and fires the operator escalation, and the emit state
            # flips the investigation to STALLED. Ratified replans
            # never reach here (relaxed is not None).
            timed_out, replan_age_s = await _resolve_stall_timeout(inv_id_str)
            if timed_out:
                await _post_stall_escalation(
                    inv_id_str, blocked, replan_age_s,
                )
                return StateResult(
                    next_state=EMIT_STATE,
                    output={
                        **state_input,
                        "stalled": True,
                        "blocked_phases": blocked,
                        "replan_age_s": replan_age_s,
                        "exit_reason": "hub_stalled_timeout",
                    },
                )
            return StateResult(
                next_state=EMIT_STATE,
                # See the ``hub_budget_exhausted`` branch above -- explicit
                # non-continue exit_reason so emit does not auto_continue on
                # a hub-level stall.
                output={
                    **state_input,
                    "stalled": True,
                    "blocked_phases": blocked,
                    "exit_reason": "hub_stalled",
                },
            )
        # Clean hub completion: no unvisited phase qualified, no stall. Same
        # explicit non-continue exit_reason so emit does not auto_continue.
        return StateResult(
            next_state=EMIT_STATE,
            output={**state_input, "exit_reason": "hub_complete"},
        )

    return _handler


def build_dispatch_workflow(
    definition_id: str,
    phases: tuple[PhaseSpec, ...],
    *,
    services_factory: Callable[[str], Awaitable[WorkflowServices]],
    setup_builder: SetupBuilder,
    loop_builder: LoopBuilder,
    emit_handler: HandlerFn,
    allow_phase_handoff: bool = False,
    escalation_models: DispatchEscalationModels | None = None,
) -> WorkflowDefinition:
    """Expand a discovery-driven phase graph into an engine WorkflowDefinition.

    The shape is setup, then the dispatch hub, then a phase, then back to the
    hub, and so on until emit. Every phase loops back to the hub (unlike
    ``build_phase_workflow``, which wires static edges), so the hub
    re-decides after each phase and the traversal grows with the agents'
    discoveries. The module supplies the setup and per-phase loop handlers;
    the hub handler is the substrate's.

    Set ``allow_phase_handoff=True`` when this graph runs as the inner
    definition of a two-phase dispatcher (``is_dispatcher`` + ``dispatches_to``):
    the inner run shares the dispatcher's run_id, so the cursor must reset from
    the dispatcher's terminal state to this graph's start_state. A graph bound
    directly to a task (VR, malware) runs under its own fresh run_id and leaves
    this at the default.

    ``escalation_models`` opts the module in to live RFC-13 #68 stall
    escalation: when the hub emits ``hub_stalled_timeout``, the substrate
    calls :func:`aila.platform.agents.auto_steering.post_dispatch_stall_escalation`
    with the module's own message + branch record types so the operator
    steering message lands in the module's own investigation-messages
    surface. When None, the exit_reason and STALLED flip still fire
    (never gated on the models) but no message is posted; the miss is
    logged so rollout is observable.
    """
    if not phases:
        raise ValueError(
            f"{definition_id}: build_dispatch_workflow needs at least one phase",
        )
    states: dict[str, StateSpec] = {
        SETUP_STATE: StateSpec(
            handler=setup_builder(DISPATCH_STATE),
            timeout_s=60.0,
            max_retries=1,
        ),
        DISPATCH_STATE: StateSpec(
            handler=make_dispatch_router(
                phases, escalation_models=escalation_models,
            ),
            timeout_s=30.0,
        ),
    }
    for phase in phases:
        states[phase.name] = StateSpec(
            handler=loop_builder(phase, DISPATCH_STATE),
            timeout_s=phase.timeout_s,
            on_failure=phase.on_failure,
            max_retries=phase.max_retries,
        )
    states[EMIT_STATE] = StateSpec(handler=emit_handler, timeout_s=120.0)
    return WorkflowDefinition(
        definition_id=definition_id,
        start_state=SETUP_STATE,
        states=states,
        services_factory=services_factory,
        allow_phase_handoff=allow_phase_handoff,
    )
