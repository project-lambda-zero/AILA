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

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from aila.platform.workflows.types import (
    HandlerFn,
    StateResult,
    StateSpec,
    WorkflowDefinition,
    WorkflowServices,
)

__all__ = [
    "EMIT_STATE",
    "SETUP_STATE",
    "GateFn",
    "LoopBuilder",
    "PhaseGraphSpec",
    "PhaseSpec",
    "RouterFn",
    "SetupBuilder",
    "build_phase_workflow",
    "make_gate_state",
    "make_router_state",
]

SETUP_STATE = "investigation_setup"
EMIT_STATE = "investigation_emit"

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

    ``strategy_family`` selects the phase prompt via the version store;
    ``allowed_servers`` is the phase tool allowlist; ``max_turns`` caps the
    phase; ``directive`` is the phase mission surfaced to the agent as a
    ``_directive.phase_mission`` observable. Exactly one of ``next`` (static
    edge) or ``router`` (dynamic edge) sets the exit; omit both to fall
    through to the terminal emit. ``entry_gate`` guards the phase (readiness
    / approval / custody); a denied gate routes to ``on_fallback`` (default
    emit).
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
    timeout_s: float = 3600.0
    on_failure: str | None = None
    max_retries: int = 0

    def __post_init__(self) -> None:
        if self.next is not None and self.router is not None:
            raise ValueError(
                f"PhaseSpec {self.name!r} sets both next and router; pick one",
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
