# DurableStateMachine — design as it actually exists

This document describes `src/aila/platform/workflows/engine.py` and the
public contracts in `src/aila/platform/workflows/types.py` exactly as
they are coded today. No proposals. No "could be improved". Every
sentence corresponds to a line range you can open and re-read.

The reader of this file should be able to integrate new behaviour
into the workflow layer without re-deriving any of these guarantees
from the source.

---

## 1. What the durable state machine is for

Every multi-step backend action in AILA — a vulnerability
investigation turn loop, a MASVS audit dispatch, a target ingestion,
a forensics replay — runs as a state machine with **named states**
and an **append-only audit trail**. The engine is responsible for
moving the cursor from one state to the next, and for the database
writes that make that move recoverable on crash.

The engine is **stateless**. All durable data lives in two Postgres
tables:

  - `workflow_state_cursor` — one row per `run_id`. Carries
    `current_state`, `state_input` (the dict the current state
    handler will receive), `retries_in_state`, `definition_id`, and
    `version`. The whole row is the live state of the run.
  - `workflow_state_transitions` — append-only event log. Two event
    kinds: `entered` (the engine has begun executing a state) and
    `exited:*` (the handler returned, raised, timed out, or was
    structurally short-circuited). Each row carries `from_state`,
    `to_state`, the redacted exception class name, the duration, an
    output hash, and a monotonically increasing `seq`.

A workflow run is **the cursor row plus its audit log**. Anything
the engine does has a deterministic mapping to writes against those
two tables.

---

## 2. Reserved terminal states (`types.py:28-40`)

Four terminals are reserved and auto-registered by every
`WorkflowDefinition`:

  - `__succeeded__` — handler-emitted clean exit. Reached by a state
    whose handler returned `StateResult(next_state="__succeeded__", …)`.
  - `__failed__` — non-retriable failure path. Reached when a state
    raised an exception not listed in `retriable_on`, or when the
    retry budget was exhausted, or when output validation failed.
  - `__cancelled__` — operator-initiated stop. Never reached by the
    engine itself; reached only when an external actor (the operator
    or a cancel endpoint) writes `__cancelled__` directly to the
    cursor.
  - `__crashed__` — engine-detected fatal condition. Reached on
    `MAX_STEPS_PER_JOB` breach, on `ServiceBuildError`, on a
    `failed_in_failure_handler` chain, or on any path where the
    engine cannot continue.

These four names are members of the frozenset
`RESERVED_TERMINAL_STATES`. The terminal-check in
`engine.py:152-156` (`_is_terminal`) returns True if the state name
is in this set OR if a user-defined state declares `terminal=True`
on its `StateSpec`.

User code does not need to declare these states. `WorkflowDefinition.
__post_init__` (`types.py:436-445`) injects them with a no-op handler
into the definition's states dict. Even if the workflow author tried
to override one, the engine treats it as terminal anyway because of
the reserved-set check in `_is_terminal`.

---

## 3. `StateSpec` — the per-state contract (`types.py:132-194`)

Every non-reserved state in a workflow is one `StateSpec` instance.
The fields:

  - `handler: HandlerFn` — async callable taking `(state_input,
    services)` and returning `StateResult`. This is the state's
    business logic.
  - `timeout_s: float = 300.0` — wall-clock cap. The engine wraps
    every handler call in `asyncio.wait_for(handler(...),
    timeout=spec.timeout_s)`.
  - `max_retries: int = 0` — per-state retry budget. Independent
    from ARQ's job-level retry count.
  - `retriable_on: tuple[type[BaseException], ...] = ()` — exception
    types that should trigger a retry instead of a failure
    transition. Must be a tuple (D-39, enforced in
    `__post_init__`).
  - `on_failure: str | None = None` — name of the state to transition
    to when the handler raises a non-retriable exception or exhausts
    retries. When unset, failure transitions to `__crashed__`.
  - `on_success: str | None = None` — declarative success edge. Used
    only by the static DAG validator (`_validate_static_graph`); the
    engine itself reads `next_state` from the handler's
    `StateResult`.
  - `terminal: bool = False` — explicit terminator. The engine's
    `_is_terminal` check exits the loop before invoking the handler.
  - `backoff: Callable[[int], float] | None = None` — overrides
    `default_backoff` for retry defer calculation.
  - `output_schema: type[BaseModel] | None = None` — optional
    Pydantic model validated against `result.output` before the
    cursor advances. Validation failure routes to `on_failure` (or
    `__failed__`).

`StateSpec` is a `frozen` dataclass with `slots`. It cannot be
mutated after construction. `__post_init__` enforces:

  - `retriable_on` is a tuple of `BaseException` subclasses.
  - `output_schema` is a `BaseModel` subclass when provided.

---

## 4. `WorkflowDefinition` — the full graph (`types.py:338-456`)

A workflow definition is the immutable plan the engine executes
against. Fields:

  - `definition_id: str` — stable identifier (max 128 chars,
    `STATE_NAME_MAX_LEN`). Conventional shape is
    `"<domain>.<flow>.v<n>"`; bump the version suffix on
    incompatible state-graph changes.
  - `start_state: str` — name of the state the engine enters first
    when no cursor exists yet for the `run_id`.
  - `states: Mapping[str, StateSpec]` — every non-terminal state in
    the graph. Reserved terminals are merged in by `__post_init__`
    so the user code never has to declare them.
  - `services_factory: Callable[[str], Awaitable[WorkflowServices]]`
    — coroutine called once per state execution to build a fresh
    services bundle. Per D-11, services are never reused across
    state boundaries.
  - `allow_phase_handoff: bool = False` — opt-in for two-level
    dispatch. When True, an `execute()` call whose cursor is on a
    reserved terminal but whose `definition_id` differs from the
    cursor's resets the cursor atomically to the new definition's
    start.
  - `is_dispatcher: bool = False` — opt-in for the platform's
    two-phase dispatch primitive (`@platform_task`). Dispatchers
    own run-record creation, both plan-json writes, dispatcher
    execution, inner definition resolution, and inner execution.
  - `dispatches_to: dict[str, WorkflowDefinition] = {}` — required
    when `is_dispatcher=True`. Maps dispatcher decisions to the
    inner definitions they hand off to.

`__post_init__` validates:

  - `definition_id` and every state name fit in 128 chars (matches
    the `VARCHAR(128)` column bounds in migration 023/024).
  - `start_state` is not a reserved terminal (a workflow that
    starts at `__succeeded__` would silently no-op).
  - `is_dispatcher` and `dispatches_to` are consistent (both set or
    both unset).
  - Terminal states do not declare `output_schema`.
  - The reserved terminals are injected with the no-op handler.
  - The static DAG validator runs over the merged graph
    (reachability + terminal-reachability + no dead states), when
    every non-terminal state declares an `on_success` edge.

The static validator (`_validate_static_graph`,
`types.py:238-332`) runs in two tiers. Tier 1 always runs and
catches dangling `on_success`/`on_failure` targets. Tier 2 runs
only when the graph is "fully annotated" (every user state declares
either `on_success` or `terminal=True`) and verifies the BFS
adjacency:

  - every non-terminal state is reachable from `start_state`;
  - at least one reserved terminal is reachable from `start_state`;
  - no dead (unreachable) non-terminal states.

---

## 5. The main loop — `DurableStateMachine.execute` (`engine.py:94-147`)

`execute(run_id, definition, initial_input) -> dict[str, Any]` is
the only public entry point. The contract:

  1. The caller has already created a `WorkflowRunRecord` row (the
     parent run record) and the corresponding `TaskRecord` row. The
     engine does not create those — it operates on a `run_id` that
     already exists in the parent tables.
  2. `initial_input` MUST be JSON-serializable. The engine runs a
     trial `json.dumps(initial_input, default=None)` at line 112
     before doing anything; non-serializable input raises `TypeError`
     immediately with a clear "Pydantic models must be
     `.model_dump(mode='json')` before passing as task kwargs"
     message. This is the documented contract — Pydantic models,
     dataclasses, arbitrary objects WILL NOT be silently coerced.
  3. The engine loads the cursor (creates a fresh one if absent),
     enters the `while not _is_terminal(...)` loop, calls
     `_step_once` for each transition, counts steps against
     `MAX_STEPS_PER_JOB=1000`, and returns the terminal state's
     `state_input` dict when the loop exits.

Step counting (`engine.py:128-145`):

  - `steps` starts at 0 before the loop.
  - Each iteration increments `steps`.
  - When `steps >= MAX_STEPS_PER_JOB`, the engine constructs a
    `WorkflowStepLimitExceeded`, calls `_force_crashed`, and breaks
    out of the loop. The state machine is now at `__crashed__` and
    the audit row carries the redacted exception metadata.

Previous-state tracking (`engine.py:120-124`, `engine.py:140-145`):

  - The variable `previous_state` is held across iterations. Initial
    entry has `previous_state=None`; the first `_log_entered` call
    documents the entry as a self-reference. From the second
    iteration onward, the cross-state arrow `previous_state ->
    state.current` is recorded.

The return value is `state.input` of the terminal state. For a
clean success this is the last handler's `output`. For a failure
this is typically `{"error_class": ..., "error_message": ...,
"failed_state": ...}` or, for the failure-in-failure-handler path,
`{"origin_state": ..., "origin_error_class": ...,
"origin_error_message": ..., "failure_handler_error": ...}`.

---

## 6. Cursor load / init (`engine.py:160-260`)

`_load_or_init_cursor` returns a `State` snapshot of the cursor. It
implements four branches:

  - **Cursor exists, normal path**: read the row, return a `State`
    populated with `current_state`, `state_input`, `retries_in_state`,
    `version`.
  - **Cursor at terminal + foreign definition_id + allow_phase_handoff
    on the new definition**: call `_execute_phase_handoff` to reset
    the cursor atomically (see §7).
  - **Cursor mid-inner-run + caller is a dispatcher with a foreign
    definition_id**: call `_handle_mid_inner_run` to return a
    synthetic `__succeeded__` (see §8). This is the ARQ
    retry-safety path for two-phase dispatch.
  - **Cursor does not exist (fresh run)**: INSERT a new row at
    `definition.start_state` with `state_input=initial_input` and
    `version=0`. On `IntegrityError` (another worker inserted
    first), roll back, open a fresh session, re-read the row, and
    return it. Phase 178 fix 3 resolves the TOCTOU window between
    "get returns None" and the INSERT — both racing workers serialise
    on the PK constraint and the loser returns the winner's row
    without re-trying.

If the post-rollback re-read finds no row, the engine raises a
`RuntimeError` naming the FK violation hypothesis (the
`workflowrunrecord` row is missing). This is the documented
guidance: ensure `WorkflowRunRecord` exists before calling
`execute()`.

---

## 7. Phase handoff (`engine.py:264-410`)

Two-level dispatch: a parent definition's terminal cursor can be
"handed off" to a different child definition's start state in one
atomic operation. Used by the platform's two-phase dispatch
primitive.

Trigger conditions (all three must hold):

  - `definition.allow_phase_handoff` is True.
  - The cursor's `current_state` is a member of
    `RESERVED_TERMINAL_STATES`.
  - The cursor's `definition_id` differs from `definition.
    definition_id`.

The implementation:

  1. Open a fresh `async_session_scope`.
  2. `SELECT ... FOR UPDATE` the cursor row, lock-stable read.
  3. Re-verify the three trigger conditions inside the lock. (Two
     concurrent handoffs serialise on the lock; the loser observes
     the winner's already-reset cursor.)
  4. Write a synthetic `exited:phase_handoff` audit row with the
     previous terminal as `from_state` and the new start as
     `to_state`. `output_hash` fingerprints the new `initial_input`.
  5. UPDATE the cursor: `current_state=definition.start_state`,
     `state_input=initial_input`, `retries_in_state=0`,
     `definition_id=definition.definition_id`, `version=version+1`.
  6. Commit. Both the audit row and the cursor reset land in the
     same transaction.

No `entered` row is written here. The engine's main loop logs
`entered` on the first step under the new definition.

---

## 8. Mid-inner-run dispatcher re-entry (`engine.py:414-524`)

This is the ARQ retry-safety path for the two-phase dispatch
primitive. Scenario: the dispatcher task gets retried by ARQ; on
attempt N (>= 2), its `execute()` call finds that the cursor has
already advanced to a non-terminal state under a different
(inner) definition.

Without this branch, the engine would raise `UnknownNextStateError`
(the cursor's current state is not in the dispatcher's
`definition.states`) and the dispatcher task would crash.

The branch:

  1. Open a fresh session — the lockless outer session must NOT be
     reused (GA1).
  2. `SELECT ... FOR UPDATE` the cursor row as the FIRST statement.
  3. If the cursor vanished (workflow completed under us), log
     `mid_inner_run_cursor_vanished` and return a synthetic
     `State(current=__succeeded__, input={}, ...)`. Raising here
     would trigger ARQ retry and risk a duplicate run.
  4. If the locked row has advanced to a terminal state under the
     dispatcher's own definition (another worker finished), return
     it directly.
  5. Otherwise, the cursor is still mid-inner-run under a foreign
     definition. Log `mid_inner_run_skip` and return a synthetic
     `State(current=__succeeded__, input={"selected_definition_id":
     inner_def_id, ...}, ...)`. The dispatch layer is responsible
     for idempotency.

Both concurrent retries WILL return `__succeeded__` — `FOR UPDATE`
serialises reads but does not prevent both from succeeding. The
dispatch layer's `@platform_task` wrapper is responsible for
idempotency of dual-success injection.

---

## 9. Per-step execution — `_step_once` (`engine.py:528-684`)

This is the heart of the engine. Exactly five subphases.

**Step 1 — `entered` audit row in its own transaction**
(`engine.py:544-549`).

The engine writes the `entered` row through `_log_entered`
(`engine.py:1113-1143`) inside its own `async_session_scope`. This
is intentional. D-41 specifies: an orphan `entered` row with no
matching `exited:*` row in the audit log IS the crash signal. If we
bundled the `entered` write with the handler call, a SIGKILL between
"handler started" and "engine committed" would lose that signal.

The `entered` row carries `from_state=previous_state` (or
`state.current` self-reference on initial entry per Phase 178 fix
11), `to_state=state.current`, and the full `state_input` snapshot.
After commit, an SSE event is fanned out for the live UI.

**Step 2 — services build** (`engine.py:551-566`).

`services = await definition.services_factory(run_id)`. Per D-45,
build failure is non-retriable — the engine wraps the exception as
`ServiceBuildError(type(build_exc).__name__)` and routes to
`_handle_failure` immediately, with `duration_ms=0`.

The wrapped `ServiceBuildError` carries the class name of the real
exception verbatim. The audit row will say
`error_class="ServiceBuildError"` and the `error_message` will be
the original exception's class name string.

**Step 3 — handler under timeout** (`engine.py:568-605`).

`result = await asyncio.wait_for(spec.handler(state.input,
services), timeout=spec.timeout_s)`. Three outcomes:

  - **`TimeoutError`** — Per D-16, timeout is non-retriable even if
    `TimeoutError` appears in `spec.retriable_on`. The engine short-
    circuits to `_handle_timeout` BEFORE the `retriable_on` check.
    The audit event is `exited:timeout`.
  - **Any other `BaseException`** — The engine writes a structured
    log line with the full traceback (encoded as
    `errors="backslashreplace"` ASCII so log shipping cannot fail
    on Unicode). Then checks `retriable_on` and `retries_in_state <
    max_retries`. Retry path goes to `_handle_retry` (which always
    raises). Non-retriable or exhausted-budget path goes to
    `_handle_failure`. The audit event is either `exited:retry` or
    `exited:failed`.
  - **Clean return** — Continue to step 4.

`BaseException` is caught, not `Exception`. This includes
`SystemExit`, `KeyboardInterrupt`, and `GeneratorExit`. The engine
treats these the same as any other handler exception for audit
purposes — the operator sees the class name in the audit log and
the engine decides retry vs failure by the exception's
relationship to `retriable_on`.

**Step 4 — next-state validation** (`engine.py:607-620`).

`result.next_state` must be a state in `definition.states` OR a
reserved terminal. If not, the engine constructs
`UnknownNextStateError` and routes through `_handle_failure`. This
catches handlers that return typo'd state names.

**Step 4b — output validation** (`engine.py:622-662`, Phase 183
Plan 06).

Two layers:

  - Layer 1: a non-terminal handler must not return `output={}`.
    Empty-dict return signals the handler couldn't decide what to
    pass to the next state. Engine logs `workflow.empty_output` and
    transitions through `_transition_to_failure` with
    `error_code="output_validation_failed"`.
  - Layer 2: optional `spec.output_schema`. If set, the engine runs
    `spec.output_schema.model_validate(result.output)`. Validation
    failure transitions through `_transition_to_failure` with the
    Pydantic errors recorded in the audit row.

Both layers go to `_transition_to_failure`, which routes to
`spec.on_failure` (or `__failed__`). The cursor never advances to
`__succeeded__` on a validation failure.

**Step 5 — atomic commit** (`engine.py:664-684`).

The engine calls `_commit_transition` with `audit_event="exited:ok"`
and the new state's `current=result.next_state`, `input=result.
output`. See §11 for the commit primitive.

---

## 10. Outcome handlers (`engine.py:688-928`)

Four exit shapes, each implemented as its own method that routes
through `_commit_transition`.

  - `_handle_retry` (`engine.py:688-724`) — writes `exited:retry`
    with the redacted exception class + message, advances the
    cursor with `retries_in_state += 1` (the cursor stays on the
    same state), then RAISES `arq.Retry(defer=backoff_fn(...))`.
    Returns `NoReturn` so the type system catches accidental
    fall-through. The backoff defer is `spec.backoff` if set,
    else `default_backoff`.
  - `_handle_timeout` (`engine.py:726-760`) — writes
    `exited:timeout`, transitions to `spec.on_failure` (or
    `__crashed__`), carries
    `state_input={"error_class": "TimeoutError", "failed_state":
    state.current}`.
  - `_handle_failure` (`engine.py:762-830`) — non-retriable or
    exhausted-retries. Walks the definition for "is any other state
    naming the current state as its `on_failure` target?". If yes
    AND the current state raised, the audit event becomes
    `exited:failed_in_failure_handler`, the transition forces
    `__crashed__`, and `state_input` carries the origin error +
    the failure handler's own error. Otherwise the audit event is
    `exited:failed`, transition goes to `spec.on_failure` (or
    `__crashed__`), and `state_input` carries `error_class`,
    `error_message`, `failed_state`.
  - `_transition_to_failure` (`engine.py:832-879`) — Phase 183
    Plan 06's output-validation failure path. Same shape as
    `_handle_failure` but the error metadata is structured
    (`error`, `error_detail`, `previous_state`) instead of
    `error_class`/`error_message`.

`_force_crashed` (`engine.py:881-928`) is a specialised variant for
engine-internal fatals (step-limit breach). It writes the full
exception to the worker log via `_log.exception` (so the operator
has the traceback in the private log) and stores ONLY the redacted
class name + safe-message in the audit row.

All exception text in the audit log goes through `safe_exc_message`
(`log.py`). Per Phase 178 fix 7, the default is class-name redaction;
handlers that need the full message must raise exceptions inheriting
from `WorkflowSafeMessage`.

---

## 11. The atomic commit primitive — `_commit_transition` (`engine.py:932-1061`)

Phase 178 fix 1, the load-bearing guarantee of the engine.

In ONE transaction:

  1. `SELECT version FROM workflow_state_cursor WHERE run_id = ?
     FOR UPDATE`. Serialises concurrent workers on the same
     `run_id`. The loser blocks; the winner proceeds.
  2. Verify `current_version == loaded_state.version`. If mismatch,
     raise `WorkflowConflictError`. The caller (ARQ) retries the
     whole job; the next attempt reloads the cursor and discovers
     the new version (D-32 — no split-brain).
  3. Write the `exited:*` audit row via `write_exited`. The audit
     row carries `from_state`, `to_state`, `event`, `output`,
     `duration_ms`, `error_class`, `error_message`. The `seq` is
     computed inside the same INSERT as `COALESCE(MAX(seq), -1) +
     1` (Phase 178 fix 2 — race-safe). PK collisions retry under a
     SAVEPOINT.
  4. UPDATE the cursor: `current_state=new_state.current`,
     `state_input=new_state.input`,
     `retries_in_state=new_state.retries_in_state`,
     `definition_id=definition.definition_id`,
     `version=loaded_version + 1`. The UPDATE uses
     `.returning(run_id)`; if `result.first() is None`, the cursor
     vanished between the FOR UPDATE lock and the UPDATE, and the
     engine raises `WorkflowConflictError`. (Phase 178 fix 12 —
     `.returning()` instead of driver-specific `rowcount`.)
  5. Best-effort heartbeat: UPDATE
     `taskrecord SET heartbeat_at = NOW() WHERE id = run_id`. This
     is the only place the engine writes `heartbeat_at`. The reaper
     uses this to distinguish actively-progressing jobs from
     zombies. A missing TaskRecord (e.g. in tests) UPDATEs zero rows
     — harmless. Per-task heartbeats are EXCLUSIVELY emitted here;
     no parallel heartbeat thread, no liveness key in Redis.
  6. Commit.
  7. After commit, fan out an SSE event with the
     `from_state`/`to_state`/`event`/`duration_ms`/error metadata so
     the live UI sees the transition without polling. Best-effort —
     if the SSE bus is down, the engine does not roll back the
     commit.

The contract — audit row + cursor advance commit together — is the
property that makes the system crash-safe. A SIGKILL between the
two writes is impossible; either both land or neither does.

---

## 12. The standalone cursor save — `_save_state` (`engine.py:1063-1109`)

Same optimistic-lock semantics as `_commit_transition` but without
the audit-write side. Retained for tests and for callers that need
to advance the cursor without a paired audit row (uncommon outside
test fixtures).

The engine's own transition path never uses `_save_state`. All
production cursor advances go through `_commit_transition` so the
audit row and the cursor land atomically.

---

## 13. Heartbeats and the reaper

The engine writes `heartbeat_at` to `TaskRecord` exactly once per
successful state commit (inside `_commit_transition`, step 5).
There is no parallel heartbeat thread. There is no Redis liveness
key. There is no other heartbeat path.

The reaper (operator-facing component, NOT inside the engine) uses
`heartbeat_at` to distinguish:

  - active job: `taskrecord.status='running' AND heartbeat_at >
    NOW() - <freshness window>`
  - zombie job: `taskrecord.status='running' AND heartbeat_at <
    NOW() - <freshness window>`

A handler that runs longer than the freshness window without
producing any state transitions will eventually be flagged as a
zombie because no commits → no heartbeat updates. The engine's
position is: a state that takes longer than the freshness window
to produce a single transition is a state that should be split, OR
the handler should be returning intermediate states so the audit
trail and the heartbeat reflect real progress.

The engine does NOT write `heartbeat_at` on the `entered` row
commit. Per §9 step 1, the `entered` write is intentionally NOT
bundled with downstream writes. The first heartbeat update lands
on the FIRST `exited:*` commit. A state that hangs forever in its
handler will have an `entered` row in the audit log but no
heartbeat update beyond the cursor's last commit.

---

## 14. SSE fan-out (`engine.py:1049-1060`, `engine.py:1132-1143`)

After every audit commit, the engine calls `emit_transition_event`
to push the transition through the SSE bus. The live UI subscribes
and renders cursor moves without polling.

Failures in SSE fan-out are logged but do not roll back the commit.
SSE is a UX nicety on top of the durable state, not the durable
state itself.

---

## 15. The contracts an external caller must honour

Anything calling `DurableStateMachine.execute` MUST:

  1. Create the `WorkflowRunRecord` row before calling. The engine
     does not create it. A missing parent row causes the
     `_load_or_init_cursor` IntegrityError-rollback-re-read path to
     fail with the documented `RuntimeError`.
  2. Create the `TaskRecord` row before calling. The engine writes
     `heartbeat_at` to it during commit; a missing row makes the
     heartbeat a no-op (acceptable but observable).
  3. Pass JSON-serializable `initial_input`. Pydantic models,
     dataclasses, datetimes — all rejected at line 112 with a clear
     message. The contract is `dict[str, JSON-primitive]`.
  4. Treat `arq.Retry` as the only retry signal. `WorkflowConflictError`
     bubbling out means "another worker beat us"; ARQ retries the
     outer job; the next attempt reloads the cursor and sees the
     new version. Catching `WorkflowConflictError` and resuming is
     a bug — the engine has already moved on under a different
     worker.

Anything NOT calling `DurableStateMachine.execute` MUST NOT:

  1. Write to `workflow_state_cursor` directly. The cursor is the
     engine's source of truth; outside writes break the optimistic-
     lock contract.
  2. Write to `workflow_state_transitions` directly. The audit log
     is append-only AND seq-allocated; outside writes break the
     `MAX(seq) + 1` race-safety.
  3. Set `taskrecord.heartbeat_at` outside the engine's commit
     path. Heartbeats from outside the engine make the reaper unable
     to tell a real progressing run from a fake-heartbeat scribble.
  4. Force-flip the cursor from a terminal state back to a non-
     terminal state. The engine treats terminals as absorbing.
     Reopening a "completed" workflow is a phase-handoff operation
     and goes through `allow_phase_handoff=True` on the new
     definition — NOT a direct UPDATE on the cursor.
  5. Delete cursor or transition rows outside the engine's own
     paths. The engine has no logic to recover from a vanished
     cursor mid-run — that's the `RuntimeError` path.

---

## 16. What the engine does not do

The engine does NOT:

  - Manage ARQ jobs. ARQ is the outer scheduler; the engine is the
    inner state machine.
  - Manage the task queue. `taskrecord` is owned by the platform
    task layer.
  - Manage business-domain rows. The VR module's branches, outcomes,
    messages, hypotheses live in their own tables; the engine has no
    knowledge of them.
  - Reap zombies. The reaper is a separate component that reads
    `taskrecord.heartbeat_at`.
  - Pause workflows. There is no "paused" terminal in the reserved
    set. Pause is implemented at the domain layer (the VR
    investigation's `pause_reason` column is a domain-owned signal,
    not a workflow-engine signal).
  - Cancel workflows. `__cancelled__` exists as a terminal but the
    engine never writes it. External cancel paths write it directly
    to the cursor.
  - Re-enqueue work. ARQ owns enqueueing; the engine produces the
    cursor state ARQ reads.

---

## 17. The minimum integration shape for a new workflow

Anything that wants to be a state machine in this codebase:

  1. Define one `WorkflowDefinition` with a stable `definition_id`.
  2. Define one or more `StateSpec` entries — handler, timeout,
     `on_success`/`on_failure` edges, `retriable_on` if applicable.
  3. Define a `services_factory` that constructs the per-attempt
     services bundle.
  4. Make the handler signature `async def handler(state_input,
     services) -> StateResult`.
  5. Return `StateResult(next_state=<state-name>, output=<json-
     serializable dict>)`. The `output` becomes the next state's
     `state_input`.
  6. Persist domain side-effects (DB writes, file ops, network
     calls) through the services bundle. The services factory
     receives `run_id` and can scope its DB session to it.
  7. Let ARQ (via `@platform_task`) call `DurableStateMachine.
     execute(run_id, definition, initial_input)`. Don't call the
     engine yourself from request handlers; that's a direct call
     and bypasses the task layer.

Any state-machine-like behaviour in the codebase that is NOT
expressed this way is a violation of Golden Rule 4 ("Explicit state
machines over implicit flow") and should be rewritten through this
contract.
