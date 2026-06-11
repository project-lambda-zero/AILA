"""Public types for the durable workflows engine.

Defines the contracts that every state handler, workflow definition, and
services factory must honour. Nothing here performs I/O; this module is
safe to import from any layer.

See CONTEXT.md decisions:
  - D-03: type definitions live here
  - D-09, D-10: handler signature + output shape
  - D-11, D-45: WorkflowServices.build() contract
  - D-35: handlers mutate DB state via async_session_scope
  - D-36: StateResult validates JSON-serializability at return time
  - D-37: reserved terminal states auto-registered
  - D-39: retriable_on must be a tuple of BaseException subclasses
"""
from __future__ import annotations

import dataclasses
import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, model_validator

# ---- Reserved terminal state names (D-37) ----------------------------------

RESERVED_SUCCEEDED: Final[str] = "__succeeded__"
RESERVED_FAILED: Final[str] = "__failed__"
RESERVED_CANCELLED: Final[str] = "__cancelled__"
RESERVED_CRASHED: Final[str] = "__crashed__"

# Phase B (cutover): non-terminal pause state. The cursor sits here when
# the operator pauses an investigation. Distinct from terminals — paused
# cursors are resumable via :func:`pause_investigation` /
# :func:`resume_investigation` tasks (see vr.workflow.tasks.pause_resume).
# The prior ``current_state`` is preserved on ``archived_state`` so resume
# can restore it.
RESERVED_PAUSED: Final[str] = "__paused__"

RESERVED_TERMINAL_STATES: Final[frozenset[str]] = frozenset(
    {
        RESERVED_SUCCEEDED,
        RESERVED_FAILED,
        RESERVED_CANCELLED,
        RESERVED_CRASHED,
    }
)

# ---- Engine limits (Phase 178 fix pass) -----------------------------------

# Upper bound on transitions per single ``execute`` call. Protects against a
# malformed definition whose handlers loop indefinitely (e.g., A -> B -> A)
# without reaching a terminal state. Breaching this cap raises
# ``WorkflowStepLimitExceeded`` and the engine transitions to ``__crashed__``.
MAX_STEPS_PER_JOB: Final[int] = 1000

# Matches the DB column bound enforced by migration 023/024
# (``String(128)`` on state identifiers). Enforced at ``WorkflowDefinition``
# construction time so crafted state names never reach the audit writer.
STATE_NAME_MAX_LEN: Final[int] = 128


# ---- WorkflowServices Protocol (D-11, D-45) --------------------------------


@runtime_checkable
class WorkflowServices(Protocol):
    """Per-workflow service bundle. Built fresh per attempt (D-11).

    Handlers receive an instance via ``handler(state_input, services)``. The
    engine calls ``services_factory(run_id)`` once at the start of every
    state execution; the instance is never passed across state boundaries.

    IMPORTANT (D-35 cancellation semantics):
        Handlers invoked under ``asyncio.wait_for`` may receive
        ``asyncio.CancelledError`` when the per-state timeout fires. DB
        writes performed via ``async_session_scope()`` roll back
        automatically because its ``__aexit__`` closes the session on
        ``CancelledError``. Handler authors that mutate external
        (non-DB) state -- filesystem, remote APIs, process control --
        are responsible for making those effects idempotent. The engine
        cannot reason about external side-effects.

    Build failures (D-45):
        If ``build(run_id)`` raises, the engine wraps the exception in
        ``ServiceBuildError`` and writes an ``exited:failed`` transition
        with ``error_class="ServiceBuildError"``, then follows the
        failure-handler path (``spec.on_failure`` or ``__crashed__``).
    """

    @classmethod
    async def build(cls, run_id: str) -> WorkflowServices:
        """Construct a fresh services bundle for the given run."""
        ...


# ---- StateResult (D-10, D-36) ----------------------------------------------


class StateResult(BaseModel):
    """Handler return value. Pydantic model so construction validates shape.

    ``next_state`` is the name of the next state to transition to (may be
    a reserved terminal such as ``__succeeded__``). ``output`` must be
    JSON-serializable (D-36); validation runs at construction time via a
    ``model_validator(mode="after")`` that performs a trial ``json.dumps``.

    A handler that returns non-serializable content raises
    ``pydantic.ValidationError`` at the ``return`` line; the engine treats
    this as a non-retriable exception.
    """

    next_state: str
    output: dict[str, Any]

    model_config = ConfigDict(frozen=True)

    @model_validator(mode="after")
    def _validate_output_json_serializable(self) -> StateResult:
        # Strict JSON-serializability check (D-36). Bare json.dumps raises
        # TypeError on non-native types; this is deliberate so the
        # must_have "rejects non-JSON-serializable output" test passes.
        # Handlers that need to return datetimes/UUIDs must convert them
        # to strings before constructing the StateResult.
        try:
            json.dumps(self.output)
        except TypeError as exc:
            raise ValueError(
                f"StateResult.output must be JSON-serializable: {exc}"
            ) from exc
        return self


# ---- StateSpec (frozen dataclass) ------------------------------------------

HandlerFn = Callable[[dict[str, Any], WorkflowServices], Awaitable[StateResult]]


@dataclass(frozen=True, slots=True)
class StateSpec:
    """Specification for a single state in a workflow.

    ``handler`` is the async function invoked by the engine for this state.
    ``timeout_s`` wraps the handler in ``asyncio.wait_for``; on timeout the
    engine records ``exited:timeout`` and treats the state as non-retriable
    (D-16).

    ``retriable_on`` must be a ``tuple`` of ``BaseException`` subclasses
    (D-39). The engine uses ``isinstance(exc, retriable_on)`` so subclass
    matching is automatic.

    ``max_retries`` is the per-state retry budget. When exceeded, the
    engine transitions to ``on_failure`` (or ``__crashed__`` if unset).

    ``terminal=True`` marks this state as an explicit terminator; the
    engine loop exits before calling the handler (D-37). Reserved terminal
    states (``__succeeded__`` etc.) are auto-registered as terminal by
    ``WorkflowDefinition.__post_init__`` and do not need to be declared.

    ``backoff`` overrides ``default_backoff`` for retry defer calculation.

    ``output_schema`` is an optional Pydantic ``BaseModel`` subclass. When
    set, the engine validates the handler's output dict against it
    (``model_validate``) before advancing the cursor. Validation failure
    transitions to ``on_failure`` with ``error="output_validation_failed"``.
    Terminal states must not declare ``output_schema`` (they do not advance).
    Phase 183 Plan 06 (output validation).
    """

    handler: HandlerFn
    timeout_s: float = 300.0
    max_retries: int = 0
    retriable_on: tuple[type[BaseException], ...] = ()
    on_failure: str | None = None
    on_success: str | None = None
    terminal: bool = False
    backoff: Callable[[int], float] | None = None
    output_schema: type[BaseModel] | None = None

    def __post_init__(self) -> None:
        # D-39: retriable_on must be a tuple of BaseException subclasses.
        if not isinstance(self.retriable_on, tuple):
            raise TypeError(
                f"retriable_on must be a tuple[type[BaseException], ...], "
                f"got {type(self.retriable_on).__name__}"
            )
        for exc_type in self.retriable_on:
            if not isinstance(exc_type, type) or not issubclass(exc_type, BaseException):
                raise TypeError(
                    f"retriable_on entries must be BaseException subclasses; "
                    f"got {exc_type!r}"
                )
        # Phase 183 Plan 06: output_schema validation.
        if self.output_schema is not None and not (
            isinstance(self.output_schema, type)
            and issubclass(self.output_schema, BaseModel)
        ):
            raise TypeError(
                "output_schema must be a BaseModel subclass; "
                f"got {self.output_schema!r}"
            )


# ---- State (frozen dataclass, engine-internal) -----------------------------


@dataclass(frozen=True, slots=True)
class State:
    """In-memory snapshot of a workflow run's cursor row.

    ``version`` is the optimistic lock value; the engine's cursor UPDATE
    guards ``WHERE version = :loaded_version`` and raises
    ``WorkflowConflictError`` if the UPDATE affects 0 rows.
    """

    current: str
    input: dict[str, Any]
    retries_in_state: int = 0
    version: int = 0


# ---- Reserved-terminal noop handler ----------------------------------------


async def _noop_terminal_handler(
    state_input: dict[str, Any], services: WorkflowServices
) -> StateResult:
    """Placeholder handler for auto-registered reserved terminal states.

    Never actually invoked: the engine loop checks ``spec.terminal`` before
    calling any handler, so auto-registered terminals short-circuit. This
    body raises loud to catch regressions in the termination check
    (minor-flag #5).
    """
    del state_input, services
    raise RuntimeError(
        "reserved terminal handler should never be invoked; "
        "engine termination check regressed"
    )


# ---- Static DAG validation -------------------------------------------------


def _validate_static_graph(
    definition_id: str,
    start_state: str,
    states: dict[str, StateSpec],
) -> None:
    """Validate the state graph's structural properties at construction time.

    Two tiers:

    Tier 1 (always runs): every ``on_success`` and ``on_failure`` target
    must reference a state that exists in the definition. Catches typos
    and stale references immediately.

    Tier 2 (runs when the graph is fully annotated — every non-terminal
    user state declares ``on_success``): builds the forward-edge adjacency
    list from ``on_success`` + ``on_failure`` edges and verifies:

    - **Reachability**: every non-terminal state is reachable from
      ``start_state`` via forward edges. Unreachable states are dead code
      that will never execute.
    - **Terminal reachability**: at least one reserved terminal state
      (``__succeeded__``, ``__failed__``, etc.) is reachable from
      ``start_state``. A graph that can never terminate is a bug.

    Tier 2 is skipped when any non-terminal state lacks ``on_success``
    (e.g., minimal test definitions). This keeps backward-compatible with
    existing test fixtures while enforcing correctness on production
    workflow definitions that declare full edge metadata.
    """
    user_states: dict[str, StateSpec] = {
        name: spec for name, spec in states.items()
        if name not in RESERVED_TERMINAL_STATES
    }
    all_names = set(states.keys())

    # -- Tier 1: edge-target existence ----------------------------------------
    for name, spec in user_states.items():
        if spec.on_success is not None and spec.on_success not in all_names:
            raise ValueError(
                f"[{definition_id}] state {name!r} declares "
                f"on_success={spec.on_success!r} which does not exist in "
                f"states (available: {sorted(all_names)})"
            )
        if spec.on_failure is not None and spec.on_failure not in all_names:
            raise ValueError(
                f"[{definition_id}] state {name!r} declares "
                f"on_failure={spec.on_failure!r} which does not exist in "
                f"states (available: {sorted(all_names)})"
            )

    # -- Tier 2: full graph analysis (only when fully annotated) ---------------
    fully_annotated = all(
        spec.on_success is not None or spec.terminal
        for spec in user_states.values()
    )
    if not fully_annotated:
        return

    adjacency: dict[str, set[str]] = {name: set() for name in all_names}
    for name, spec in user_states.items():
        if spec.on_success is not None:
            adjacency[name].add(spec.on_success)
        if spec.on_failure is not None:
            adjacency[name].add(spec.on_failure)

    # BFS from start_state
    reachable: set[str] = set()
    queue = [start_state]
    while queue:
        current = queue.pop()
        if current in reachable:
            continue
        reachable.add(current)
        for neighbor in adjacency.get(current, ()):
            if neighbor not in reachable:
                queue.append(neighbor)

    # Check: at least one terminal reachable
    terminal_reachable = reachable & RESERVED_TERMINAL_STATES
    if not terminal_reachable:
        raise ValueError(
            f"[{definition_id}] no reserved terminal state is reachable "
            f"from start_state={start_state!r} via on_success/on_failure "
            f"edges. Reachable states: {sorted(reachable)}"
        )

    # Check: no dead (unreachable) non-terminal states
    unreachable_user = set(user_states.keys()) - reachable
    if unreachable_user:
        raise ValueError(
            f"[{definition_id}] unreachable states detected: "
            f"{sorted(unreachable_user)}. These states can never execute "
            f"because they are not reachable from start_state={start_state!r} "
            f"via on_success/on_failure edges."
        )


# ---- WorkflowDefinition (frozen dataclass) ---------------------------------


@dataclass(frozen=True, slots=True)
class WorkflowDefinition:
    """Immutable specification of a workflow's state graph.

    ``definition_id`` is a stable identifier (e.g.
    ``"vulnerability.analyze_fleet.v1"``). Change the version suffix when
    the state graph changes in a way that would break in-flight runs.

    ``states`` is a mapping from state name to ``StateSpec``. Reserved
    terminal states (``__succeeded__``, ``__failed__``, ``__cancelled__``,
    ``__crashed__``) are auto-registered in ``__post_init__`` and do not
    need to be provided by the caller (D-37).

    ``services_factory`` is a coroutine callable taking ``run_id`` and
    returning a fresh ``WorkflowServices`` instance (D-11).
    """

    definition_id: str
    start_state: str
    states: Mapping[str, StateSpec]
    services_factory: Callable[[str], Awaitable[WorkflowServices]]
    # Phase 178 amendment (authorized 2026-04-13): two-level dispatch
    # handoff. When True, an execute() call whose ``run_id`` already has a
    # reserved-terminal cursor with a DIFFERENT ``definition_id`` is
    # treated as a fresh phase start: cursor is atomically reset to this
    # definition's ``start_state`` with the supplied ``initial_input``,
    # and a synthetic ``exited:phase_handoff`` transition row is written
    # in the same transaction. Same-definition re-execute on a terminal
    # cursor is still a no-op (preserves ARQ-retry-after-terminal
    # behaviour). See Phase 180 CONTEXT D-10.
    allow_phase_handoff: bool = False
    # Phase 183 amendment: platform dispatch primitive. When True,
    # ``@platform_task`` owns the full two-phase execution: run_record
    # creation, both plan_json writes, dispatcher execution, inner
    # definition resolution via ``dispatches_to``, and inner execution.
    # Modules set is_dispatcher=True and supply dispatches_to; they never
    # call DurableStateMachine.execute directly. (Golden Rule 3/4 / v5.0).
    is_dispatcher: bool = False
    dispatches_to: dict[str, WorkflowDefinition] = dataclasses.field(
        default_factory=dict
    )

    def __post_init__(self) -> None:
        # Phase 178 security fix: validate state-name length BEFORE the
        # dict is frozen and persisted. Matches the DB-level bound on
        # ``workflow_state_cursor.current_state`` / ``definition_id`` and
        # ``workflow_state_transitions.from_state`` / ``to_state``.
        # Reserved terminals are auto-injected (fixed short names) so they
        # are always within bounds.
        if len(self.definition_id) > STATE_NAME_MAX_LEN:
            raise ValueError(
                f"definition_id length {len(self.definition_id)} exceeds "
                f"STATE_NAME_MAX_LEN={STATE_NAME_MAX_LEN}"
            )
        for name in self.states:
            if len(name) > STATE_NAME_MAX_LEN:
                raise ValueError(
                    f"state name {name!r} exceeds "
                    f"STATE_NAME_MAX_LEN={STATE_NAME_MAX_LEN} "
                    f"(actual length {len(name)})"
                )

        # Phase 183 Bug 10 fix: start_state must not be a reserved terminal.
        # A definition whose start_state is e.g. "__succeeded__" would exit
        # immediately without calling any handler — silent no-op behaviour
        # that is always a programming error.
        if self.start_state in RESERVED_TERMINAL_STATES:
            raise ValueError(
                f"start_state={self.start_state!r} is a reserved terminal state; "
                "workflow definitions must start in a real handler state"
            )

        # Phase 183 dispatcher invariants.
        if self.is_dispatcher and not self.dispatches_to:
            raise ValueError(
                "is_dispatcher=True requires non-empty dispatches_to"
            )
        if not self.is_dispatcher and self.dispatches_to:
            raise ValueError(
                "dispatches_to only valid when is_dispatcher=True"
            )

        # Phase 183 Plan 06: terminal states cannot declare output_schema.
        # Terminal states never advance so validation would be a no-op, and
        # declaring it almost certainly indicates a programming error.
        for state_name, state_spec in self.states.items():
            if (
                state_name in RESERVED_TERMINAL_STATES
                and state_spec.output_schema is not None
            ):
                raise ValueError(
                    f"State {state_name!r} is a reserved terminal state; "
                    "terminal states cannot declare output_schema"
                )

        # Build a new dict with reserved terminals injected, then freeze
        # the attribute (minor-flag #6: no object.__setattr__ on frozen
        # dataclasses when we can construct the dict once).
        merged: dict[str, StateSpec] = dict(self.states)
        for reserved in RESERVED_TERMINAL_STATES:
            if reserved not in merged:
                merged[reserved] = StateSpec(
                    handler=_noop_terminal_handler,
                    terminal=True,
                )
        # Using object.__setattr__ here is the documented escape hatch for
        # frozen dataclasses in __post_init__; it replaces the field once.
        object.__setattr__(self, "states", merged)

        if self.start_state not in merged:
            raise ValueError(
                f"start_state={self.start_state!r} not in states "
                f"(available: {sorted(merged.keys())})"
            )

        # Static DAG validation: validate all declared edge targets exist
        # and, when the graph is fully annotated, verify structural
        # properties (reachability, terminal reachability, dead states).
        _validate_static_graph(self.definition_id, self.start_state, merged)


# Re-export list for external consumers / __init__.py.
__all__ = [
    "HandlerFn",
    "MAX_STEPS_PER_JOB",
    "RESERVED_CANCELLED",
    "RESERVED_CRASHED",
    "RESERVED_FAILED",
    "RESERVED_SUCCEEDED",
    "RESERVED_TERMINAL_STATES",
    "STATE_NAME_MAX_LEN",
    "State",
    "StateResult",
    "StateSpec",
    "WorkflowDefinition",
    "WorkflowServices",
]
