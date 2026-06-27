"""@platform_task decorator + PlatformTask registry (Phase 179).

The single, canonical way to register an async callable as an AILA platform
task. The decorator:

1. Wraps the function in an ARQ-compatible coroutine ``(ctx: dict, **kwargs)``
   that constructs a :class:`~aila.platform.tasks.context.TaskContext` and
   hands it to either the wrapped body (single-stage task) or
   ``DurableStateMachine.execute`` (workflow-engine task, D-05/D-06).
2. Stashes outcome info keyed by ``(job_id, job_try)`` into the
   :mod:`aila.platform.tasks.hooks` outcome stash so
   :func:`aila.platform.tasks.hooks._on_job_end` can drive TaskRecord
   terminal state without introspecting the exception directly.
3. Converts ``WorkflowConflictError`` into ``arq.worker.Retry(defer=...)``
   inside the wrapper (D-09). ARQ only honours ``Retry`` when raised from
   the job body, not from ``on_job_end`` -- the planner's clarification in
   the Phase 179 brief.
4. Registers a :class:`PlatformTask` record keyed by the wrapped function's
   qualified name into the module-level ``_REGISTRY``. ``WorkerSettings``
   reads ``_REGISTRY.all_functions()`` at import time, so module authors
   never touch a hand-maintained function list.

Authorization is enforced upstream by the FastAPI route layer
(require_user_or_api_key). The wrapper does not re-validate caller identity.
"""
from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any, cast

import sqlalchemy as sa
import structlog
from arq.worker import Retry
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlmodel import select

from aila.platform.tasks.context import TaskContext
from aila.platform.workflows import (
    DurableStateMachine,
    WorkflowConflictError,
    WorkflowDefinition,
    default_backoff,
)

__all__ = [
    "PlatformTask",
    "platform_task",
]

# ``_REGISTRY`` and the ``_ensure_run_record`` / ``_run_two_phase_dispatch`` /
# ``_update_plan_json`` helpers are sibling-internal: imported directly by
# ``aila.platform.tasks.hooks`` and ``aila.platform.tasks.worker``. They are
# intentionally absent from ``__all__`` because they are not part of the
# package's public surface.

_dispatch_log = structlog.get_logger(__name__)


# Type alias for the wrapped coroutine shape ARQ invokes.
# ``ctx`` is ARQ's own context dict (job_id, job_try, redis, ...). ``kwargs``
# is the user payload from ``TaskQueue.submit``.
_ArqJob = Callable[..., Awaitable[dict[str, Any]]]


@dataclass(frozen=True, slots=True)
class PlatformTask:
    """Immutable record describing a registered platform task.

    Attributes:
        fn: The ARQ-callable wrapper (the coroutine ARQ invokes). Not the
            original handler -- the wrapper knows how to build TaskContext
            and delegate to the workflow engine when ``definition`` is set.
        name: Qualified dotted name used as the registry key.
        track: ARQ queue suffix (e.g. ``"vulnerability"``).
        module_id: Logical module owner (e.g. ``"vulnerability"``).
        max_tries: Per-task retry cap; overrides ``WorkerSettings.max_tries``
            when the wrapper observes it via ARQ's ``max_tries`` kwarg on
            ``enqueue_job``.
        timeout_s: Per-task job timeout applied by the wrapper.
        retriable_on: Tuple of exception classes that should be converted
            to ``arq.Retry`` instead of bubbling. Currently unused on
            PlatformTask; retry policy is owned by StateSpec.retriable_on
            in the workflow engine.
        definition: Frozen workflow definition. ``None`` means the wrapped
            body runs directly (D-06). Otherwise the wrapper invokes
            :meth:`DurableStateMachine.execute` (D-05).
    """

    fn: _ArqJob
    name: str
    track: str
    module_id: str
    max_tries: int
    timeout_s: float
    retriable_on: tuple[type[BaseException], ...]
    definition: WorkflowDefinition | None


class _Registry:
    """In-process PlatformTask registry.

    The registry is populated at import time as module code executes the
    ``@platform_task`` decorator. ``WorkerSettings.functions`` reads
    :meth:`all_functions` so the ARQ functions list is never hand-maintained
    (D-02).

    Duplicate registration raises ``ValueError`` to prevent one module
    silently shadowing another's handler with the same qualified name.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, PlatformTask] = {}

    def register(self, task: PlatformTask) -> None:
        if task.name in self._tasks:
            raise ValueError(
                f"PlatformTask {task.name!r} already registered; "
                "double-registration is refused to prevent silent override.",
            )
        self._tasks[task.name] = task

    def get_task(self, name: str) -> PlatformTask | None:
        return self._tasks.get(name)

    def all_functions(self) -> list[_ArqJob]:
        # Return wrapped coroutines in a stable insertion order so ARQ's
        # function-name -> function map is deterministic across restarts.
        return [t.fn for t in self._tasks.values()]

    @property
    def tasks(self) -> list[PlatformTask]:
        """Snapshot of registered tasks in registration order."""
        return list(self._tasks.values())

    def clear(self) -> None:
        """Test helper -- clear the registry. Not called by production code."""
        self._tasks.clear()


# Module-level registry instance. Populated at ARQ worker startup by
# tasks/worker.py:_bootstrap_platform_tasks().
_REGISTRY: _Registry = _Registry()


async def _ensure_run_record(run_id: str, query_text: str) -> None:
    """Insert a WorkflowRunRecord for ``run_id`` if one does not exist.

    The scan submission endpoint creates a TaskRecord but no WorkflowRunRecord.
    ``workflow_state_cursor`` has an FK → ``workflowrunrecord.id``, so the
    cursor INSERT fails with an IntegrityError (FK violation) when the run
    record is absent. This helper ensures the record exists before the engine
    starts. Concurrent retries are safe -- INSERT ON CONFLICT DO NOTHING.
    """
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import WorkflowRunRecord

    tbl = WorkflowRunRecord.__table__  # type: ignore[attr-defined]
    async with async_session_scope() as session:
        await session.execute(
            pg_insert(tbl)
            .values(id=run_id, query_text=query_text, status="running")
            .on_conflict_do_nothing(index_elements=["id"])
        )
        await session.commit()


async def _update_plan_json(run_id: str, plan: dict[str, Any]) -> None:
    """Persist ``plan_json`` for ``run_id`` (D-13).

    Uses ``.returning(WorkflowRunRecord.run_id)`` so that asyncpg returns the
    matched row rather than the rowcount (asyncpg returns rowcount=-1 for DML
    without RETURNING, making a rowcount==0 check a permanent no-op).

    If the returned row is None the ``WorkflowRunRecord`` is missing and
    ``plan_json`` was never written -- that is a data-integrity violation, not a
    silent success. Raises ``WorkflowConflictError`` in that case.
    """
    from aila.storage.database import async_session_scope
    from aila.storage.db_models import WorkflowRunRecord

    run_id_col = WorkflowRunRecord.__table__.c.id  # type: ignore[attr-defined]
    async with async_session_scope() as session:
        result = await session.execute(
            sa.update(WorkflowRunRecord)
            .where(run_id_col == run_id)
            .values(plan_json=plan)
            .returning(run_id_col)
        )
        row = result.fetchone()
        if row is None:
            _dispatch_log.warning(
                "workflow.plan_json_update.row_missing",
                run_id=run_id,
            )
            raise WorkflowConflictError(
                f"WorkflowRunRecord missing for run_id={run_id!r} "
                "-- plan_json not persisted"
            )
        await session.commit()


def _hash_initial_input(kwargs: dict[str, Any]) -> str:
    """Stable 16-hex-char hash of the initial task kwargs (moved from modules)."""
    blob = json.dumps(kwargs, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


async def _run_two_phase_dispatch(
    task_context: TaskContext,
    definition: WorkflowDefinition,
    kwargs: dict[str, Any],
) -> dict[str, Any]:
    """Platform-owned two-phase dispatch execution.

    Called by ``@platform_task`` when ``definition.is_dispatcher=True``.
    Owns:
      1. WorkflowRunRecord row creation (idempotent upsert)
      2. First plan_json write (dispatcher definition + input hash)
      3. Dispatcher DurableStateMachine.execute call
      4. Inner definition resolution from ``definition.dispatches_to``
      5. Second plan_json write (inner definition + operation_mode)
      6. Inner DurableStateMachine.execute call
      7. Terminal output forwarding

    Args:
        task_context: Task context built by the @platform_task wrapper.
        definition: The dispatcher WorkflowDefinition (is_dispatcher=True).
        kwargs: Raw ARQ job kwargs (the caller payload).

    Returns:
        ``{"response": <payload>}`` on success, or
        ``{"response": None, "error": "<reason>"}`` on graceful failure.

    Raises:
        WorkflowConflictError: On missing plan_json row or unknown
            selected_definition_id (both are integrity violations).
    """
    run_id = task_context.task_id
    # Key verified from modules/vulnerability/workflow/task.py: kwargs["query"]
    query_text: str = str(kwargs.get("query") or "")
    initial_hash = _hash_initial_input(kwargs)

    # Step 1: ensure WorkflowRunRecord exists before the engine touches
    # workflow_state_cursor (FK → workflowrunrecord.id).
    await _ensure_run_record(run_id, query_text)

    # Step 2: first plan_json write -- dispatcher definition + input hash.
    await _update_plan_json(
        run_id,
        {
            "definition_id": definition.definition_id,
            "operation_mode": None,
            "initial_input_hash": initial_hash,
        },
    )

    # Step 3: run dispatcher.
    dispatcher_output = await DurableStateMachine.execute(
        run_id=run_id,
        definition=definition,
        initial_input=dict(kwargs),
    )

    # Graceful failure: dispatcher did not emit selected_definition_id.
    # DurableStateMachine.execute() returns state.input directly -- the terminal
    # handler's output dict. A successful dispatcher run carries
    # "selected_definition_id"; a crashed/failed run carries "error_class" /
    # "failed_state" instead.
    selected_id: str | None = dispatcher_output.get("selected_definition_id")
    if not isinstance(selected_id, str) or not selected_id:
        _dispatch_log.warning(
            "workflow.dispatch.dispatcher_failed",
            run_id=run_id,
            definition_id=definition.definition_id,
            dispatcher_error_class=dispatcher_output.get("error_class"),
            dispatcher_failed_state=dispatcher_output.get("failed_state"),
        )
        return {
            "response": None,
            "error": "dispatcher_failed",
            "dispatcher_output": dispatcher_output,
        }

    # Step 4: output_payload IS dispatcher_output -- engine returns state.input
    # directly (no "output" wrapper key exists).
    output_payload = dispatcher_output
    if not isinstance(selected_id, str) or not selected_id:
        _dispatch_log.warning(
            "workflow.dispatch.no_selected_definition_id",
            run_id=run_id,
            definition_id=definition.definition_id,
            output_keys=sorted(output_payload.keys()),
        )
        return {
            "response": None,
            "error": "dispatcher_produced_no_selected_definition_id",
        }

    if selected_id not in definition.dispatches_to:
        raise WorkflowConflictError(
            f"selected_definition_id {selected_id!r} not in dispatches_to "
            f"(run_id={run_id!r}, available={sorted(definition.dispatches_to.keys())})"
        )

    inner_definition = definition.dispatches_to[selected_id]

    # Derive operation_mode from the snapshot if the dispatcher left it.
    operation_mode: str | None = None
    snapshot_dict = output_payload.get("snapshot")
    if isinstance(snapshot_dict, dict):
        mode_val = snapshot_dict.get("operation_mode")
        if isinstance(mode_val, str) and mode_val:
            operation_mode = mode_val

    # Step 5: second plan_json write -- inner definition + mode.
    await _update_plan_json(
        run_id,
        {
            "definition_id": inner_definition.definition_id,
            "operation_mode": operation_mode,
            "initial_input_hash": initial_hash,
        },
    )

    # Step 6: run inner definition under the same run_id.
    # allow_phase_handoff=True on the inner definition atomically resets the
    # cursor from the dispatcher's terminal to the inner's start_state.
    inner_input = {
        k: v for k, v in output_payload.items() if k != "selected_definition_id"
    }
    terminal_output = await DurableStateMachine.execute(
        run_id=run_id,
        definition=inner_definition,
        initial_input=inner_input,
    )

    # Step 7: extract and forward response.
    # terminal_output is state.input from the inner engine run -- the last
    # handler's output dict. state_response_emit places {"response": ...} at
    # the top level (no "output" wrapper key exists).
    response = terminal_output.get("response") if isinstance(terminal_output, dict) else None
    if response is None:
        _dispatch_log.warning(
            "workflow.dispatch.no_response",
            run_id=run_id,
            inner_definition_id=inner_definition.definition_id,
            terminal_keys=sorted(terminal_output.keys()),
        )
        return {"response": None, "error": "inner_workflow_returned_no_response"}

    return {"response": response}


async def _load_task_identity(task_id: str) -> tuple[str, str | None]:
    """Load ``(user_id, team_id)`` from TaskRecord for TaskContext construction.

    Returns ``("__unknown__", None)`` when the record is missing. Callers
    log-and-continue; an absent TaskRecord for a running ARQ job means
    submit raced with a hard delete, which we surface in the hook (not
    the wrapper) so the exception path is consistent with the rest of
    the matrix.
    """
    # Imports deferred so template.py is safe to import at ARQ worker boot
    # before the DB is reachable (registry population must not hit Postgres).
    from aila.platform.tasks.models import TaskRecord
    from aila.storage.database import async_session_scope

    async with async_session_scope() as session:
        record: TaskRecord | None = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == task_id))
        ).first()
    if record is None:
        return "__unknown__", None
    return record.user_id, getattr(record, "team_id", None)


def platform_task(
    *,
    track: str,
    module_id: str,
    max_tries: int = 3,
    timeout_s: float = 3600.0,
    retriable_on: tuple[type[BaseException], ...] = (),
    definition: WorkflowDefinition | None = None,
) -> Callable[[Callable[..., Awaitable[dict[str, Any]]]], _ArqJob]:
    """Register an async callable as an ARQ-callable platform task.

    Usage::

        @platform_task(track="vulnerability", module_id="vulnerability")
        async def my_task(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
            return {"result_path": "/tmp/x"}

    With a workflow definition the wrapper delegates to the engine; the
    body never runs directly (D-05)::

        @platform_task(
            track="vulnerability",
            module_id="vulnerability",
            definition=VULNERABILITY_ANALYZE_FLEET,
        )
        async def analyze_fleet(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
            # Wrapper delegates to DurableStateMachine.execute.
            ...

    Raises:
        TypeError: If the decorated callable is not ``async def``.
        ValueError: If a task with the same qualified name is already
            registered (set via ``_REGISTRY.register``).
    """

    def _decorator(fn: Callable[..., Awaitable[dict[str, Any]]]) -> _ArqJob:
        if not inspect.iscoroutinefunction(fn):
            raise TypeError(
                f"@platform_task requires an `async def` function; "
                f"got {type(fn).__name__} for {fn!r}",
            )

        registry_name = f"{fn.__module__}.{fn.__qualname__}"

        @functools.wraps(fn)
        async def _wrapper(ctx: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
            # Deferred import: hooks.py imports template.py indirectly via
            # worker.py at boot, so a top-level import would form a cycle
            # during `aila.platform.tasks` package init.
            from aila.platform.tasks.hooks import _JobOutcome, _stash_outcome

            job_id = str(ctx.get("job_id", ""))
            job_try = int(ctx.get("job_try", 1))

            user_id, team_id = await _load_task_identity(job_id)
            task_context = TaskContext(
                task_id=job_id,
                job_try=job_try,
                user_id=user_id,
                team_id=team_id,
            )

            try:
                if definition is not None:
                    if definition.is_dispatcher:
                        # Phase 183: platform-owned two-phase dispatch. The
                        # helper owns run_record, both plan_json writes,
                        # dispatcher execution, inner resolution, and inner
                        # execution. The body (fn) never runs.
                        result = await _run_two_phase_dispatch(
                            task_context, definition, dict(kwargs)
                        )
                    else:
                        # D-05: workflow-engine task. Pass kwargs as initial_input.
                        # The engine inserts workflow_state_cursor with an FK
                        # to workflowrunrecord.id, so the run record MUST
                        # exist before execute() touches the cursor -- same
                        # invariant the two-phase path enforces. Without
                        # this the cursor INSERT raises IntegrityError, the
                        # transaction rolls back, and the engine reports the
                        # row 'vanished'. Synthesize a query_text from
                        # kwargs['query'] when present, else a deterministic
                        # workflow:<definition_id> tag so the row is auditable.
                        query_text = str(
                            kwargs.get("query")
                            or f"workflow:{definition.definition_id}",
                        )
                        await _ensure_run_record(
                            task_context.task_id, query_text,
                        )
                        result = await DurableStateMachine.execute(
                            task_context.task_id,
                            definition,
                            initial_input=dict(kwargs),
                        )
                else:
                    # D-06: direct single-stage execution. The body owns
                    # its return shape; we only require it be a dict.
                    result = await fn(task_context, **kwargs)

                _stash_outcome(
                    job_id,
                    job_try,
                    _JobOutcome(kind="success", result=result),
                )
                return result

            except WorkflowConflictError as conflict:
                # D-09/D-14 last row: engine optimistic-lock conflict -- let
                # ARQ reschedule via its native Retry exception. The hook
                # sees ``kind="retry_signalled"`` and leaves TaskRecord
                # RUNNING (Branch 2).
                _stash_outcome(
                    job_id,
                    job_try,
                    _JobOutcome(
                        kind="retry_signalled",
                        exception=conflict,
                        exception_class=type(conflict).__name__,
                    ),
                )
                raise Retry(defer=default_backoff(job_try)) from conflict

            except Retry as retry_exc:
                # The handler (or a nested wrapper) already chose to retry.
                _stash_outcome(
                    job_id,
                    job_try,
                    _JobOutcome(
                        kind="retry_signalled",
                        exception=retry_exc,
                        exception_class=type(retry_exc).__name__,
                    ),
                )
                raise

            except asyncio.CancelledError as cancel_exc:
                _stash_outcome(
                    job_id,
                    job_try,
                    _JobOutcome(
                        kind="cancelled",
                        exception=cancel_exc,
                        exception_class=type(cancel_exc).__name__,
                    ),
                )
                raise

            except TimeoutError as timeout_exc:
                _stash_outcome(
                    job_id,
                    job_try,
                    _JobOutcome(
                        kind="timeout",
                        exception=timeout_exc,
                        exception_class=type(timeout_exc).__name__,
                    ),
                )
                raise

            except BaseException as exc:
                _stash_outcome(
                    job_id,
                    job_try,
                    _JobOutcome(
                        kind="exception",
                        exception=exc,
                        exception_class=type(exc).__name__,
                    ),
                )
                raise

        # Ensure ARQ's function-name resolution (ARQ builds a name->func map
        # keyed by ``func.__qualname__``/``func.__name__``) points at the
        # wrapper and not at the unwrapped original.
        _wrapper.__name__ = fn.__name__
        _wrapper.__qualname__ = fn.__qualname__
        _wrapper.__module__ = fn.__module__

        task = PlatformTask(
            fn=cast(_ArqJob, _wrapper),
            name=registry_name,
            track=track,
            module_id=module_id,
            max_tries=max_tries,
            timeout_s=timeout_s,
            retriable_on=retriable_on,
            definition=definition,
        )
        _REGISTRY.register(task)
        return cast(_ArqJob, _wrapper)

    return _decorator
