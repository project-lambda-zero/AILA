"""Durable state-machine engine for AILA workflows.

Entry point: ``DurableStateMachine.execute(run_id, definition, initial_input)``.

Guarantees:
    - Crash-safe: the audit-exit row and the cursor advance commit in a
      SINGLE transaction (Phase 178 fix 1). SIGKILL between them cannot
      leave the audit saying "moved" while the cursor says "still here"
      -- they move together.
    - Append-only audit: every ``entered`` event is its own transaction
      (D-41 preserves crash signal via orphan entered rows). Every
      ``exited:*`` event is bundled with the cursor UPDATE so the two
      writes are atomic.
    - Race-safe seq allocation: audit writes compute
      ``COALESCE(MAX(seq), -1) + 1`` inside the INSERT's own snapshot;
      concurrent workers for the same ``run_id`` cannot read the same
      max then both INSERT (Phase 178 fix 2). PK collisions retry with
      a SAVEPOINT.
    - ARQ-native retries: retriable exceptions raise ``arq.Retry`` after
      persisting the cursor (D-13). No parallel heartbeat or custom
      liveness keys.
    - Optimistic locking: stale UPDATE (0 rows) raises
      ``WorkflowConflictError``; ARQ retries the job; next attempt
      reloads the cursor and discovers the new version (D-32 -- no
      split-brain).
    - Exception redaction: by default, audit rows carry the exception
      CLASS NAME only. Handlers that need the full message preserved
      must raise exceptions inheriting from ``WorkflowSafeMessage``
      (Phase 178 fix 7).
    - Step limit: ``MAX_STEPS_PER_JOB`` caps transitions per single
      ``execute`` call to protect against malformed definitions that
      loop (Phase 178 fix 6).

The engine runs inside an ARQ job; Phase 179's ``@platform_task`` wrapper
will instantiate this engine per attempt. Phase 178 does NOT touch the
worker or the task-system code.
"""
from __future__ import annotations

import asyncio
import json
import time
from datetime import UTC, datetime
from typing import Any, NoReturn

import pydantic
import sqlalchemy as sa
import structlog
from arq.worker import Retry
from sqlalchemy.exc import IntegrityError

from aila.platform.tasks.models import TaskRecord
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor

from .backoff import default_backoff
from .errors import (
    ServiceBuildError,
    UnknownNextStateError,
    WorkflowConflictError,
    WorkflowStepLimitExceeded,
)
from .log import emit_transition_event, safe_exc_message, write_entered, write_exited
from .types import (
    MAX_STEPS_PER_JOB,
    RESERVED_CRASHED,
    RESERVED_FAILED,
    RESERVED_SUCCEEDED,
    RESERVED_TERMINAL_STATES,
    State,
    StateSpec,
    WorkflowDefinition,
)

_log = structlog.get_logger(__name__)


class DurableStateMachine:
    """Stateless engine; all durable data lives in Postgres.

    Usage::

        out = await DurableStateMachine.execute(run_id, definition, {"n": 0})

    The engine loops through states until it reaches a terminal one
    (reserved ``__succeeded__`` / ``__failed__`` / ``__cancelled__`` /
    ``__crashed__`` or any ``StateSpec(terminal=True)``). On retriable
    exceptions it raises ``arq.Retry`` after persisting the cursor so
    that ARQ can reschedule the outer job.
    """

    # ---- Public entry point ------------------------------------------------

    @classmethod
    async def execute(
        cls,
        run_id: str,
        definition: WorkflowDefinition,
        initial_input: dict[str, Any],
    ) -> dict[str, Any]:
        """Drive the state machine until a terminal state.

        Returns the terminal state's ``state_input``. For a clean success
        path, this is the last handler's ``output``. For a failure path,
        it is typically ``{"error": ..., "failed_state": ...}`` or the
        platform-reserved ``{"origin_state": ..., ...}`` payload.
        """
        # Guard: initial_input must be JSON-serializable. Pydantic models,
        # dataclasses, and other non-primitive objects cause silent JSONB
        # INSERT failures downstream. Fail fast with a clear message.
        try:
            json.dumps(initial_input, default=None)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"initial_input for run_id={run_id!r} is not JSON-serializable. "
                f"Pydantic models must be .model_dump(mode='json') before passing "
                f"as task kwargs. Offending value: {exc}"
            ) from exc
        state = await cls._load_or_init_cursor(run_id, definition, initial_input)
        # Phase 178 fix 11: track the previous state so ``entered`` rows
        # carry a real ``from_state`` on cross-state transitions. Initial
        # entry uses None and falls back to state.current (documented
        # self-reference).
        previous_state: str | None = None

        # Phase 178 fix 6: hard cap to avoid infinite loops on malformed
        # definitions. Breach -> non-retriable crash with typed origin.
        steps = 0
        while not cls._is_terminal(state.current, definition):
            if steps >= MAX_STEPS_PER_JOB:
                exc = WorkflowStepLimitExceeded(
                    f"exceeded MAX_STEPS_PER_JOB={MAX_STEPS_PER_JOB} "
                    f"(definition_id={definition.definition_id!r}, "
                    f"current_state={state.current!r})"
                )
                state = await cls._force_crashed(
                    run_id, definition, state, exc
                )
                break
            new_state = await cls._step_once(
                run_id, definition, state, previous_state
            )
            previous_state = state.current
            state = new_state
            steps += 1

        return state.input

    # ---- Termination check -------------------------------------------------

    @staticmethod
    def _is_terminal(state_name: str, definition: WorkflowDefinition) -> bool:
        if state_name in RESERVED_TERMINAL_STATES:
            return True
        spec = definition.states.get(state_name)
        return bool(spec and spec.terminal)

    # ---- Cursor load / init -----------------------------------------------

    @classmethod
    async def _load_or_init_cursor(
        cls,
        run_id: str,
        definition: WorkflowDefinition,
        initial_input: dict[str, Any],
    ) -> State:
        """Return the persisted cursor as a ``State``, or create a fresh one.

        Fresh run -> INSERT a row at ``definition.start_state`` with
        ``state_input=initial_input``, ``version=0``.

        Resume after crash / ARQ retry -> the row exists; we reload and
        ignore ``initial_input`` (the persisted ``state_input`` is the
        truth).

        Phase 178 fix 3: TOCTOU resolved -- if two workers both see a
        missing row and both INSERT, the PK constraint raises
        ``IntegrityError`` on the loser. The loser catches, rolls back,
        reloads the winner's row, and returns it.
        """
        async with async_session_scope() as session:
            row = await session.get(WorkflowStateCursor, run_id)
            if row is not None:
                # Phase 178 amendment (authorized 2026-04-13): two-level
                # dispatch handoff. If the existing cursor is at a reserved
                # terminal state AND the caller presents a different
                # definition_id AND that definition opts in to handoff,
                # atomically reset the cursor to the new definition's
                # start_state and write a synthetic exited:phase_handoff
                # audit row in the SAME transaction. Same-definition
                # re-execute on a terminal cursor remains a no-op
                # (preserves ARQ-retry-after-terminal behaviour).
                if (
                    definition.allow_phase_handoff
                    and row.current_state in RESERVED_TERMINAL_STATES
                    and row.definition_id != definition.definition_id
                ):
                    return await cls._execute_phase_handoff(
                        run_id=run_id,
                        definition=definition,
                        initial_input=initial_input,
                    )
                # Phase 183 Plan 01: fourth branch — dispatcher re-entry while
                # cursor is mid-inner-run (non-terminal, foreign definition_id).
                # Guard uses getattr so this branch is dormant until Plan 02
                # adds is_dispatcher to WorkflowDefinition.
                if (
                    getattr(definition, "is_dispatcher", False)
                    and row.definition_id != definition.definition_id
                    and row.current_state not in RESERVED_TERMINAL_STATES
                ):
                    return await cls._handle_mid_inner_run(
                        run_id=run_id,
                        definition=definition,
                    )
                return State(
                    current=row.current_state,
                    input=row.state_input,
                    retries_in_state=row.retries_in_state,
                    version=row.version,
                )

            new_row = WorkflowStateCursor(
                run_id=run_id,
                current_state=definition.start_state,
                state_input=initial_input,
                retries_in_state=0,
                definition_id=definition.definition_id,
                version=0,
            )
            session.add(new_row)
            try:
                await session.commit()
                return State(
                    current=new_row.current_state,
                    input=new_row.state_input,
                    retries_in_state=new_row.retries_in_state,
                    version=new_row.version,
                )
            except IntegrityError:
                # Another worker inserted first; rebuild a clean session
                # and reload the winner's row.
                await session.rollback()

        async with async_session_scope() as session:
            existing = await session.get(WorkflowStateCursor, run_id)
            if existing is None:  # pragma: no cover -- genuine DB error
                raise RuntimeError(
                    f"workflow_state_cursor row for run_id={run_id!r} "
                    "vanished after IntegrityError rollback — likely an FK "
                    "violation (workflowrunrecord row missing) rather than a "
                    "concurrent insert race. Ensure WorkflowRunRecord exists "
                    "before calling DurableStateMachine.execute()."
                )
            return State(
                current=existing.current_state,
                input=existing.state_input,
                retries_in_state=existing.retries_in_state,
                version=existing.version,
            )

    # ---- Phase-handoff primitive (Phase 178 amendment 2026-04-13) ---------

    @classmethod
    async def _execute_phase_handoff(
        cls,
        *,
        run_id: str,
        definition: WorkflowDefinition,
        initial_input: dict[str, Any],
    ) -> State:
        """Atomically reset a terminal cursor to the new definition's start.

        Writes one synthetic ``exited:phase_handoff`` transition row and
        UPDATEs the cursor in the same transaction. Two concurrent callers
        serialize on ``FOR UPDATE`` of the cursor row; the loser observes
        the winner's already-handed-off cursor (non-terminal, new
        ``definition_id``) and the regular load path returns it.

        Invariants:
            - Only reached when the caller's ``definition.allow_phase_handoff``
              is True AND the stored cursor sits on a ``RESERVED_TERMINAL_STATES``
              member AND ``definition_id`` differs from the cursor's.
            - No optimistic ``version`` check against a caller-loaded State:
              handoff is a one-shot reset, not an in-flight advance. The
              FOR UPDATE lock prevents concurrent handoffs from colliding.
            - The synthetic audit event is ``exited:phase_handoff`` with
              ``from_state`` = previous terminal, ``to_state`` =
              ``definition.start_state``; ``output_hash`` fingerprints the
              new ``initial_input``. No ``entered`` row is written here --
              the engine's main loop logs ``entered`` on the first step.
        """
        async with async_session_scope() as session:
            cursor_table = WorkflowStateCursor.__table__  # type: ignore[attr-defined]
            lock_stmt = (
                sa.select(
                    cursor_table.c.current_state,
                    cursor_table.c.definition_id,
                    cursor_table.c.version,
                )
                .where(cursor_table.c.run_id == run_id)
                .with_for_update()
            )
            lock_result = await session.execute(lock_stmt)
            locked = lock_result.first()
            if locked is None:
                # Cursor vanished between the initial get() and FOR UPDATE.
                # Fall back to a fresh INSERT under the new definition.
                new_row = WorkflowStateCursor(
                    run_id=run_id,
                    current_state=definition.start_state,
                    state_input=initial_input,
                    retries_in_state=0,
                    definition_id=definition.definition_id,
                    version=0,
                )
                session.add(new_row)
                await session.commit()
                return State(
                    current=definition.start_state,
                    input=initial_input,
                    retries_in_state=0,
                    version=0,
                )

            current_state = str(locked[0])
            current_def_id = str(locked[1])
            current_version = int(locked[2])

            # Post-lock re-check: another worker may have won the race and
            # already performed the handoff. In that case the cursor is
            # non-terminal under the new definition -- just return it.
            if (
                current_state not in RESERVED_TERMINAL_STATES
                or current_def_id == definition.definition_id
            ):
                # Reload the full row to return consistent State.
                full = await session.get(WorkflowStateCursor, run_id)
                if full is None:
                    _log.error("workflow.cursor_vanished_under_lock", run_id=run_id)
                    raise WorkflowConflictError(
                        f"Cursor row vanished for run_id={run_id} under FOR UPDATE lock"
                    )
                return State(
                    current=full.current_state,
                    input=full.state_input,
                    retries_in_state=full.retries_in_state,
                    version=full.version,
                )

            # Write the synthetic handoff audit row within the same txn.
            _handoff_now = datetime.now(UTC)
            _handoff_seq = await write_exited(
                session,
                run_id=run_id,
                from_state=current_state,
                to_state=definition.start_state,
                event="exited:phase_handoff",
                output=initial_input,
                duration_ms=0,
                error_class=None,
                error_message=None,
            )

            # Reset the cursor to the new definition's start.
            new_version = current_version + 1
            upd_stmt = (
                sa.update(WorkflowStateCursor)
                .where(WorkflowStateCursor.run_id == run_id)  # type: ignore[arg-type]
                .where(WorkflowStateCursor.version == current_version)  # type: ignore[arg-type]
                .values(
                    current_state=definition.start_state,
                    state_input=initial_input,
                    retries_in_state=0,
                    definition_id=definition.definition_id,
                    version=new_version,
                )
                .returning(WorkflowStateCursor.__table__.c.run_id)  # type: ignore[attr-defined]
            )
            upd_result = await session.execute(upd_stmt)
            if upd_result.first() is None:  # pragma: no cover -- FOR UPDATE holds
                _log.warning(
                    "workflow.phase_handoff_update_zero_rows",
                    run_id=run_id,
                    loaded_version=current_version,
                )
                raise WorkflowConflictError(
                    "Concurrent workflow modification detected"
                )

            await session.commit()

        # Phase 181 D-02: best-effort SSE fan-out after commit.
        await emit_transition_event(
            run_id=run_id,
            seq=_handoff_seq,
            from_state=current_state,
            to_state=definition.start_state,
            event="exited:phase_handoff",
            duration_ms=0,
            error_class=None,
            error_message=None,
            happened_at=_handoff_now,
        )
        return State(
            current=definition.start_state,
            input=initial_input,
            retries_in_state=0,
            version=new_version,
        )

    # ---- Mid-inner-run dispatcher re-entry (Phase 183 Plan 01) -----------

    @classmethod
    async def _handle_mid_inner_run(
        cls,
        *,
        run_id: str,
        definition: WorkflowDefinition,
    ) -> State:
        """Return a synthetic ``__succeeded__`` when a dispatcher retries while
        the cursor is mid-inner-run under a different definition_id.

        This is the ARQ retry-safety path for two-phase dispatch. On retry
        attempt N (N >= 2), the dispatcher definition's ``execute()`` call
        reaches ``_load_or_init_cursor`` and finds a cursor that belongs to an
        inner definition that is still running. Rather than crashing with
        ``UnknownNextStateError``, the engine returns a synthetic terminal
        so the dispatch layer can resume the inner run.

        Lock protocol (GA1 — lock timing is critical):
            1. Open a FRESH ``async_session_scope()`` — the outer
               ``_load_or_init_cursor`` session was lock-free and must NOT be
               reused here.
            2. The FIRST statement inside this session is ``SELECT ... FOR UPDATE``
               on the cursor row. This serialises concurrent ARQ retries that
               both entered the fourth branch.
            3. All column reads use named mapping access (``locked_row.current_state``
               etc.) — never positional index — so column-order changes cannot
               silently read wrong values.

        Vanished row (T-183-01-01):
            If the row is gone between the outer ``get()`` and the FOR UPDATE,
            the workflow completed under us. Return a synthetic
            ``State(current=RESERVED_SUCCEEDED, input={}, ...)`` so the
            dispatcher exits cleanly. Raising here would trigger ARQ retry
            which would INSERT a duplicate run.

        Post-lock re-check:
            If the locked row has advanced to a terminal state under the
            dispatcher definition, return it directly — another worker already
            finished.

        Idempotency note:
            Both concurrent retries WILL return synthetic ``__succeeded__``
            (FOR UPDATE serialises reads but does NOT prevent both from
            succeeding). The dispatch layer (Plan 02) is responsible for
            idempotency of dual ``__succeeded__`` injection.
        """
        async with async_session_scope() as session:
            # GA1: FOR UPDATE is the FIRST DB operation in this session scope.
            cursor_table = WorkflowStateCursor.__table__  # type: ignore[attr-defined]
            lock_stmt = (
                sa.select(
                    cursor_table.c.current_state.label("current_state"),
                    cursor_table.c.definition_id.label("definition_id"),
                    cursor_table.c.state_input.label("state_input"),
                    cursor_table.c.version.label("version"),
                )
                .where(cursor_table.c.run_id == run_id)
                .with_for_update()
            )
            lock_result = await session.execute(lock_stmt)
            locked_row = lock_result.mappings().first()

            if locked_row is None:
                # Cursor vanished between outer get() and FOR UPDATE lock
                # acquisition — workflow completed concurrently.
                _log.warning(
                    "workflow.mid_inner_run_cursor_vanished",
                    run_id=run_id,
                    dispatcher_def_id=definition.definition_id,
                )
                return State(
                    current=RESERVED_SUCCEEDED,
                    input={},
                    retries_in_state=0,
                    version=0,
                )

            current_state: str = locked_row["current_state"]
            current_def_id: str = locked_row["definition_id"]
            state_input: dict[str, Any] = locked_row["state_input"]
            locked_version: int = locked_row["version"]

            # Post-lock re-check: another worker already advanced the cursor to
            # a terminal state under the dispatcher definition.
            if (
                current_state in RESERVED_TERMINAL_STATES
                and current_def_id == definition.definition_id
            ):
                return State(
                    current=current_state,
                    input=state_input,
                    retries_in_state=0,
                    version=locked_version,
                )

            # Cursor is still mid-inner-run (non-terminal, foreign def).
            # Return synthetic __succeeded__ carrying the inner definition_id
            # so the dispatch layer can resume/continue the inner run.
            _log.info(
                "workflow.mid_inner_run_skip",
                run_id=run_id,
                inner_def_id=current_def_id,
                inner_state=current_state,
                dispatcher_def_id=definition.definition_id,
            )
            return State(
                current=RESERVED_SUCCEEDED,
                input={"selected_definition_id": current_def_id, **state_input},
                retries_in_state=0,
                version=locked_version,
            )

    # ---- Per-iteration step -----------------------------------------------

    @classmethod
    async def _step_once(
        cls,
        run_id: str,
        definition: WorkflowDefinition,
        state: State,
        previous_state: str | None,
    ) -> State:
        """Execute exactly one state transition. Returns the new State."""
        spec = definition.states.get(state.current)
        if spec is None:
            raise UnknownNextStateError(
                f"State {state.current!r} not in definition "
                f"{definition.definition_id!r}"
            )

        # Step 1: log `entered` in its own transaction. D-41 preserves the
        # crash signal (orphan entered rows with no matching exited:*).
        # Phase 178 fix 11: from_state carries the previous state so the
        # audit trail shows real arrows on cross-state transitions.
        from_state = previous_state if previous_state is not None else state.current
        await cls._log_entered(run_id, state, from_state)

        # Step 2: build services (D-45 -- build failure is non-retriable).
        try:
            services = await definition.services_factory(run_id)
        except Exception as build_exc:
            # Preserve the original exception's class name in the audit
            # row (already the default via safe_exc_message). The wrapped
            # ServiceBuildError carries the class name verbatim.
            wrapped = ServiceBuildError(type(build_exc).__name__)
            return await cls._handle_failure(
                run_id,
                definition,
                state,
                spec,
                wrapped,
                duration_ms=0,
            )

        # Step 3: run handler under timeout.
        start = time.monotonic()
        try:
            result = await asyncio.wait_for(
                spec.handler(state.input, services),
                timeout=spec.timeout_s,
            )
        except TimeoutError as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            # D-16: timeout is non-retriable EVEN IF TimeoutError is
            # listed in retriable_on. Short-circuit before the
            # retriable_on check.
            return await cls._handle_timeout(
                run_id, definition, state, spec, exc, duration_ms
            )
        except BaseException as exc:
            import traceback as _tb
            duration_ms = int((time.monotonic() - start) * 1000)
            _tb_str = _tb.format_exc().encode("ascii", errors="backslashreplace").decode("ascii")
            _log.error(
                "workflow.handler_exception",
                run_id=run_id,
                state=state.current,
                error_class=type(exc).__name__,
                traceback=_tb_str,
            )
            if (
                spec.retriable_on
                and isinstance(exc, spec.retriable_on)
                and state.retries_in_state < spec.max_retries
            ):
                # _handle_retry always raises (Retry / conflict / etc.)
                await cls._handle_retry(
                    run_id, definition, state, spec, exc, duration_ms
                )
            return await cls._handle_failure(
                run_id, definition, state, spec, exc, duration_ms
            )

        # Step 4: success. Validate the returned next_state exists.
        duration_ms = int((time.monotonic() - start) * 1000)
        if (
            result.next_state not in definition.states
            and result.next_state not in RESERVED_TERMINAL_STATES
        ):
            unknown = UnknownNextStateError(
                f"Handler for {state.current!r} returned "
                f"next_state={result.next_state!r} which is not in "
                f"definition.states and not a reserved terminal"
            )
            return await cls._handle_failure(
                run_id, definition, state, spec, unknown, duration_ms
            )

        # Step 4b (Phase 183 Plan 06): output validation.
        # Layer 1 — non-terminal handlers must not return empty dict.
        if result.output == {} and state.current not in RESERVED_TERMINAL_STATES:
            _log.warning(
                "workflow.empty_output",
                run_id=run_id,
                state=state.current,
            )
            return await cls._transition_to_failure(
                run_id=run_id,
                definition=definition,
                state=state,
                spec=spec,
                duration_ms=duration_ms,
                error_code="output_validation_failed",
                error_detail="Handler returned empty dict for non-terminal state",
            )

        # Layer 2 — optional per-state Pydantic schema validation.
        if spec.output_schema is not None:
            try:
                spec.output_schema.model_validate(result.output)
            except pydantic.ValidationError as exc:
                _log.warning(
                    "workflow.output_schema_failed",
                    run_id=run_id,
                    state=state.current,
                    errors=[
                        {"loc": e["loc"], "msg": e["msg"]}
                        for e in exc.errors()
                    ],
                )
                return await cls._transition_to_failure(
                    run_id=run_id,
                    definition=definition,
                    state=state,
                    spec=spec,
                    duration_ms=duration_ms,
                    error_code="output_validation_failed",
                    error_detail=str(exc),
                )

        # Step 5 (Phase 178 fix 1): write exit + advance cursor in ONE
        # transaction. Either both land or neither does -- SIGKILL
        # between cannot create split-brain.
        return await cls._commit_transition(
            run_id=run_id,
            definition=definition,
            loaded_state=state,
            new_state=State(
                current=result.next_state,
                input=result.output,
                retries_in_state=0,
                version=state.version + 1,
            ),
            audit_from=state.current,
            audit_to=result.next_state,
            audit_event="exited:ok",
            audit_output=result.output,
            audit_duration_ms=duration_ms,
            audit_error_class=None,
            audit_error_message=None,
        )

    # ---- Outcome handlers --------------------------------------------------

    @classmethod
    async def _handle_retry(
        cls,
        run_id: str,
        definition: WorkflowDefinition,
        state: State,
        spec: StateSpec,
        exc: BaseException,
        duration_ms: int,
    ) -> NoReturn:
        """Persist the retry transition, then raise ``arq.Retry``.

        Always raises (Phase 178 fix 5): either ``WorkflowConflictError``
        from the cursor save, or ``arq.Retry`` with the backoff defer.
        The return annotation is ``NoReturn`` so ``_step_once`` cannot
        accidentally treat a dropped return value as a new State.
        """
        saved = await cls._commit_transition(
            run_id=run_id,
            definition=definition,
            loaded_state=state,
            new_state=State(
                current=state.current,
                input=state.input,
                retries_in_state=state.retries_in_state + 1,
                version=state.version + 1,
            ),
            audit_from=state.current,
            audit_to=state.current,
            audit_event="exited:retry",
            audit_output=None,
            audit_duration_ms=duration_ms,
            audit_error_class=type(exc).__name__,
            audit_error_message=safe_exc_message(exc),
        )
        backoff_fn = spec.backoff or default_backoff
        raise Retry(defer=backoff_fn(saved.retries_in_state))

    @classmethod
    async def _handle_timeout(
        cls,
        run_id: str,
        definition: WorkflowDefinition,
        state: State,
        spec: StateSpec,
        exc: asyncio.TimeoutError,
        duration_ms: int,
    ) -> State:
        """Timeout path (D-16): write ``exited:timeout`` and transition to
        failure in one atomic commit."""
        next_state = spec.on_failure or RESERVED_CRASHED
        error_class = type(exc).__name__
        return await cls._commit_transition(
            run_id=run_id,
            definition=definition,
            loaded_state=state,
            new_state=State(
                current=next_state,
                input={
                    "error_class": error_class,
                    "failed_state": state.current,
                },
                retries_in_state=0,
                version=state.version + 1,
            ),
            audit_from=state.current,
            audit_to=next_state,
            audit_event="exited:timeout",
            audit_output=None,
            audit_duration_ms=duration_ms,
            audit_error_class=error_class,
            audit_error_message="handler exceeded spec.timeout_s",
        )

    @classmethod
    async def _handle_failure(
        cls,
        run_id: str,
        definition: WorkflowDefinition,
        state: State,
        spec: StateSpec,
        exc: BaseException,
        duration_ms: int,
    ) -> State:
        """Non-retriable or exhausted-retries path.

        Distinguishes the "failure handler itself raised" case (D-33):
        if any OTHER state named the current state as its ``on_failure``
        target AND the current state raised, record
        ``exited:failed_in_failure_handler`` and force ``__crashed__``
        with rich origin metadata. No second retry.

        All audit writes + cursor advance commit atomically (Phase 178
        fix 1). Exception text is redacted via ``safe_exc_message``.
        """
        is_failure_handler = any(
            other_spec.on_failure == state.current and other_spec is not spec
            for other_spec in definition.states.values()
        )

        error_class = type(exc).__name__
        error_message = safe_exc_message(exc)
        _log.exception(
            "workflow handler crash: run_id=%s state=%s error_class=%s message=%r",
            run_id, state.current, error_class, str(exc),
        )

        if is_failure_handler:
            event = "exited:failed_in_failure_handler"
            to_state = RESERVED_CRASHED
            new_input: dict[str, Any] = {
                "origin_state": state.current,
                "origin_error_class": error_class,
                "origin_error_message": error_message,
                "failure_handler_error": error_class,
            }
        else:
            event = "exited:failed"
            to_state = spec.on_failure or RESERVED_CRASHED
            new_input = {
                "error_class": error_class,
                "error_message": error_message,
                "failed_state": state.current,
            }

        return await cls._commit_transition(
            run_id=run_id,
            definition=definition,
            loaded_state=state,
            new_state=State(
                current=to_state,
                input=new_input,
                retries_in_state=0,
                version=state.version + 1,
            ),
            audit_from=state.current,
            audit_to=to_state,
            audit_event=event,
            audit_output=None,
            audit_duration_ms=duration_ms,
            audit_error_class=error_class,
            audit_error_message=error_message,
        )

    @classmethod
    async def _transition_to_failure(
        cls,
        *,
        run_id: str,
        definition: WorkflowDefinition,
        state: State,
        spec: StateSpec,
        duration_ms: int,
        error_code: str,
        error_detail: str,
    ) -> State:
        """Phase 183 Plan 06: route output-validation failures to on_failure.

        Transitions to ``spec.on_failure`` if configured, otherwise to
        ``RESERVED_FAILED``. Writes a structured ``exited:failed`` audit row
        so the failure appears in the transition timeline. The cursor carries
        ``{"error": error_code, "error_detail": error_detail,
        "previous_state": state.current}`` so downstream failure handlers
        have the context they need.

        This path is never a silent success: the cursor advances to a
        failure state (on_failure or __failed__), never to __succeeded__.
        """
        to_state = spec.on_failure or RESERVED_FAILED
        new_input: dict[str, Any] = {
            "error": error_code,
            "error_detail": error_detail,
            "previous_state": state.current,
        }
        return await cls._commit_transition(
            run_id=run_id,
            definition=definition,
            loaded_state=state,
            new_state=State(
                current=to_state,
                input=new_input,
                retries_in_state=0,
                version=state.version + 1,
            ),
            audit_from=state.current,
            audit_to=to_state,
            audit_event="exited:failed",
            audit_output=None,
            audit_duration_ms=duration_ms,
            audit_error_class=error_code,
            audit_error_message=error_detail,
        )

    @classmethod
    async def _force_crashed(
        cls,
        run_id: str,
        definition: WorkflowDefinition,
        state: State,
        exc: BaseException,
    ) -> State:
        """Phase 178 fix 6: transition directly to ``__crashed__`` with
        the exception's redacted metadata. Used when the engine itself
        detects a fatal condition (e.g., step-limit exceeded) that does
        NOT originate from a handler.

        Also writes the FULL exception (with traceback + str(exc)) to
        the worker log via _log.exception so the operator can debug.
        The cursor row only stores the redacted class name per the
        Phase 178 security policy; the operator-private log gets the
        real message.
        """
        error_class = type(exc).__name__
        error_message = safe_exc_message(exc)
        _log.exception(
            "workflow._force_crashed: run_id=%s failed_state=%s "
            "error_class=%s message=%r",
            run_id, state.current, error_class, str(exc),
        )
        return await cls._commit_transition(
            run_id=run_id,
            definition=definition,
            loaded_state=state,
            new_state=State(
                current=RESERVED_CRASHED,
                input={
                    "error_class": error_class,
                    "error_message": error_message,
                    "failed_state": state.current,
                },
                retries_in_state=0,
                version=state.version + 1,
            ),
            audit_from=state.current,
            audit_to=RESERVED_CRASHED,
            audit_event="exited:failed",
            audit_output=None,
            audit_duration_ms=0,
            audit_error_class=error_class,
            audit_error_message=error_message,
        )

    # ---- Persistence primitives -------------------------------------------

    @classmethod
    async def _commit_transition(
        cls,
        *,
        run_id: str,
        definition: WorkflowDefinition,
        loaded_state: State,
        new_state: State,
        audit_from: str,
        audit_to: str,
        audit_event: str,
        audit_output: dict[str, Any] | None,
        audit_duration_ms: int,
        audit_error_class: str | None,
        audit_error_message: str | None,
    ) -> State:
        """Phase 178 fix 1: write ``exited:*`` + advance cursor in ONE
        transaction. Either both land or neither does.

        Phase 178 fix 12: cursor UPDATE uses ``.returning(run_id)`` and
        checks ``result.first()`` rather than relying on driver-specific
        ``rowcount`` semantics.

        Raises ``WorkflowConflictError`` when the optimistic version
        check fails (concurrent worker beat us to it). The caller (ARQ)
        retries the whole job.
        """
        async with async_session_scope() as session:
            # Serialize audit writes per run_id by locking the cursor
            # row FOR UPDATE first. Two concurrent workers cannot both
            # advance past this point with the same loaded_version;
            # exactly one wins.
            cursor_table = WorkflowStateCursor.__table__  # type: ignore[attr-defined]
            lock_stmt = (
                sa.select(cursor_table.c.version)
                .where(cursor_table.c.run_id == run_id)
                .with_for_update()
            )
            lock_result = await session.execute(lock_stmt)
            current_version_row = lock_result.first()
            if current_version_row is None:
                # Cursor vanished -- treat as conflict so ARQ retries.
                _log.warning(
                    "workflow.cursor_missing_during_commit",
                    run_id=run_id,
                    loaded_version=loaded_state.version,
                )
                raise WorkflowConflictError(
                    "Concurrent workflow modification detected"
                )
            current_version = int(current_version_row[0])
            if current_version != loaded_state.version:
                _log.warning(
                    "workflow.cursor_version_mismatch",
                    run_id=run_id,
                    loaded_version=loaded_state.version,
                    current_version=current_version,
                )
                raise WorkflowConflictError(
                    "Concurrent workflow modification detected"
                )

            # Audit write within the same transaction.
            _emit_now = datetime.now(UTC)
            _emit_seq = await write_exited(
                session,
                run_id=run_id,
                from_state=audit_from,
                to_state=audit_to,
                event=audit_event,
                output=audit_output,
                duration_ms=audit_duration_ms,
                error_class=audit_error_class,
                error_message=audit_error_message,
            )

            # Cursor UPDATE with RETURNING (fix 12).
            upd_stmt = (
                sa.update(WorkflowStateCursor)
                .where(WorkflowStateCursor.run_id == run_id)  # type: ignore[arg-type]
                .where(WorkflowStateCursor.version == loaded_state.version)  # type: ignore[arg-type]
                .values(
                    current_state=new_state.current,
                    state_input=new_state.input,
                    retries_in_state=new_state.retries_in_state,
                    definition_id=definition.definition_id,
                    version=loaded_state.version + 1,
                )
                .returning(WorkflowStateCursor.__table__.c.run_id)  # type: ignore[attr-defined]
            )
            upd_result = await session.execute(upd_stmt)
            if upd_result.first() is None:
                # Should not happen given FOR UPDATE lock above, but
                # defend anyway.
                _log.warning(
                    "workflow.cursor_update_affected_zero_rows",
                    run_id=run_id,
                    loaded_version=loaded_state.version,
                )
                raise WorkflowConflictError(
                    "Concurrent workflow modification detected"
                )

            # Best-effort heartbeat: update TaskRecord.heartbeat_at so the
            # reaper can distinguish actively-progressing jobs from zombies.
            # run_id == task_id for @platform_task workflow jobs (see
            # template.py: DurableStateMachine.execute(task_context.task_id)).
            # We do this inside the same transaction so it commits atomically
            # with the cursor advance. A missing TaskRecord (e.g. during
            # tests) produces 0 rows updated — that is fine.
            await session.execute(
                sa.update(TaskRecord)
                .where(TaskRecord.id == run_id)  # type: ignore[arg-type]
                .values(heartbeat_at=_emit_now)
            )

            await session.commit()
        # Phase 181 D-02: best-effort SSE fan-out after commit.
        await emit_transition_event(
            run_id=run_id,
            seq=_emit_seq,
            from_state=audit_from,
            to_state=audit_to,
            event=audit_event,
            duration_ms=audit_duration_ms,
            error_class=audit_error_class,
            error_message=audit_error_message,
            happened_at=_emit_now,
        )
        return new_state

    @classmethod
    async def _save_state(
        cls,
        *,
        run_id: str,
        loaded_version: int,
        new_state: State,
        definition_id: str,
    ) -> State:
        """Standalone cursor UPDATE with optimistic lock.

        Retained for use by tests and callers that advance the cursor
        without a paired audit write. Engine's own transition path uses
        ``_commit_transition`` so audit + cursor land atomically.

        Phase 178 fix 12: uses ``.returning(run_id)`` instead of
        ``rowcount`` for cross-driver reliability.
        Phase 178 fix 9: conflict message is generic; details go to
        structlog at warning level.
        """
        async with async_session_scope() as session:
            stmt = (
                sa.update(WorkflowStateCursor)
                .where(WorkflowStateCursor.run_id == run_id)  # type: ignore[arg-type]
                .where(WorkflowStateCursor.version == loaded_version)  # type: ignore[arg-type]
                .values(
                    current_state=new_state.current,
                    state_input=new_state.input,
                    retries_in_state=new_state.retries_in_state,
                    definition_id=definition_id,
                    version=loaded_version + 1,
                )
                .returning(WorkflowStateCursor.__table__.c.run_id)  # type: ignore[attr-defined]
            )
            result = await session.execute(stmt)
            winner = result.first()
            await session.commit()
            if winner is None:
                _log.warning(
                    "workflow.cursor_version_mismatch",
                    run_id=run_id,
                    loaded_version=loaded_version,
                )
                raise WorkflowConflictError(
                    "Concurrent workflow modification detected"
                )
        return new_state

    # ---- Log helpers (entered row: one session per write, D-41) -----------

    @classmethod
    async def _log_entered(
        cls, run_id: str, state: State, from_state: str
    ) -> None:
        """Write the ``entered`` audit row in its own transaction.

        Intentionally NOT bundled with subsequent writes: if the process
        dies between this commit and the handler's return, the orphan
        ``entered`` row is the documented crash signal (D-41).
        """
        async with async_session_scope() as session:
            seq = await write_entered(
                session,
                run_id=run_id,
                from_state=from_state,
                to_state=state.current,
                state_input=state.input,
            )
            await session.commit()
        # Phase 181 D-02: best-effort SSE fan-out after commit.
        await emit_transition_event(
            run_id=run_id,
            seq=seq,
            from_state=from_state,
            to_state=state.current,
            event="entered",
            duration_ms=None,
            error_class=None,
            error_message=None,
            happened_at=datetime.now(UTC),
        )


__all__ = ["DurableStateMachine"]
