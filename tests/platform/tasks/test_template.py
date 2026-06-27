"""Phase 179 Task 1 -- @platform_task + _REGISTRY + TaskContext contracts.

Runs against real Postgres via the shared ``test_db`` fixture; no mocks for
the engine or the DB. The engine invocation is exercised through the same
toy 3-state definition used by ``tests/platform/workflows/test_engine.py``.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import pytest
import pytest_asyncio

from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.hooks import _OUTCOME_STASH, _pop_outcome
from aila.platform.tasks.template import (
    _REGISTRY,
    PlatformTask,
    platform_task,
)
from aila.platform.workflows import (
    StateResult,
    StateSpec,
    WorkflowDefinition,
    WorkflowServices,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord

# --- TaskContext shape -----------------------------------------------------


def test_task_context_is_frozen_and_hashable() -> None:
    ctx = TaskContext(task_id="abc", job_try=2, user_id="u", team_id=None)
    # Hashable -- frozen dataclass with slots.
    assert hash(ctx) == hash(ctx)
    with pytest.raises(FrozenInstanceError):
        ctx.job_try = 99  # type: ignore[misc]


def test_task_context_exposes_exactly_four_fields() -> None:
    ctx = TaskContext(task_id="a", job_try=1, user_id="u", team_id="t")
    assert ctx.task_id == "a"
    assert ctx.job_try == 1
    assert ctx.user_id == "u"
    assert ctx.team_id == "t"


# --- Registry invariants ---------------------------------------------------


@pytest.fixture(autouse=True)
def _isolate_registry() -> Any:
    """Snapshot and restore the module-level registry around each test."""
    # pylint: disable=protected-access
    snapshot = dict(_REGISTRY._tasks)  # noqa: SLF001
    stash_snapshot = dict(_OUTCOME_STASH)
    _REGISTRY.clear()
    _OUTCOME_STASH.clear()
    try:
        yield
    finally:
        _REGISTRY.clear()
        _OUTCOME_STASH.clear()
        _REGISTRY._tasks.update(snapshot)  # noqa: SLF001
        _OUTCOME_STASH.update(stash_snapshot)


def test_decorator_registers_non_definition_task() -> None:
    @platform_task(track="vulnerability", module_id="vulnerability")
    async def simple_task(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        return {"ok": True}

    entry = _REGISTRY.get_task(f"{simple_task.__module__}.{simple_task.__qualname__}")
    assert entry is not None
    assert isinstance(entry, PlatformTask)
    assert entry.definition is None
    assert entry.track == "vulnerability"
    assert entry.module_id == "vulnerability"
    assert entry.max_tries == 3
    assert entry.timeout_s == 3600.0


def test_decorator_registers_definition_task() -> None:
    async def noop_handler(
        _state_input: dict[str, Any], _services: object
    ) -> StateResult:
        return StateResult(next_state="__succeeded__", output={})

    async def services_factory(_run_id: str) -> WorkflowServices:
        class _Stub:
            async def build(self) -> object:  # pragma: no cover
                return self
        return _Stub()  # type: ignore[return-value]

    definition = WorkflowDefinition(
        definition_id="test.toy_defn.v1",
        start_state="start",
        states={"start": StateSpec(handler=noop_handler)},
        services_factory=services_factory,
    )

    @platform_task(
        track="vulnerability",
        module_id="vulnerability",
        definition=definition,
    )
    async def engine_task(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        # Wrapper never calls this body when definition is set; still must
        # be defined for the decorator to accept the signature.
        return {}

    entry = _REGISTRY.get_task(f"{engine_task.__module__}.{engine_task.__qualname__}")
    assert entry is not None
    assert entry.definition is definition


def test_double_registration_raises_value_error() -> None:
    @platform_task(track="vulnerability", module_id="vulnerability")
    async def first(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        return {}

    # Re-decorate the same function -- re-execution of the decorator must
    # refuse to silently shadow the existing entry.
    with pytest.raises(ValueError, match="already registered"):
        platform_task(track="vulnerability", module_id="vulnerability")(first)


def test_sync_function_rejected() -> None:
    with pytest.raises(TypeError, match="async def"):
        @platform_task(track="vulnerability", module_id="vulnerability")
        def sync_task(ctx: TaskContext) -> dict[str, Any]:  # type: ignore[misc]
            return {}


def test_all_functions_returns_wrapped_coroutines() -> None:
    @platform_task(track="vulnerability", module_id="vulnerability")
    async def wrapped_task(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        return {}

    # ``wrapped_task`` is the wrapper returned by the decorator, not the
    # original body; ``all_functions()`` must return exactly that object.
    fns = _REGISTRY.all_functions()
    assert len(fns) == 1
    assert fns[0] is wrapped_task


# --- Wrapper execution -----------------------------------------------------


@pytest_asyncio.fixture
async def seeded_task(test_db: None) -> str:  # noqa: ARG001
    """Insert a TaskRecord so the wrapper's TaskContext loader finds it."""
    import uuid

    from aila.platform.tasks.models import TaskRecord, TaskStatus

    tid = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=tid,
                track="vulnerability",
                fn_path="tests.fake.fn",
                fn_module="tests",
                status=TaskStatus.QUEUED,
                user_id="user-42",
                group_id="operator",
                kwargs_json="{}",
                team_id="team-alpha",
            ),
        )
        await session.commit()
    return tid


@pytest.mark.asyncio
async def test_wrapper_invokes_body_when_definition_is_none(
    seeded_task: str,
) -> None:
    calls: list[TaskContext] = []

    @platform_task(track="vulnerability", module_id="vulnerability")
    async def body(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        calls.append(ctx)
        return {"echo": kwargs.get("x", None), "result_path": None}

    arq_ctx = {"job_id": seeded_task, "job_try": 1}
    result = await body(arq_ctx, x=42)  # type: ignore[arg-type]

    assert result == {"echo": 42, "result_path": None}
    assert len(calls) == 1
    assert calls[0].task_id == seeded_task
    assert calls[0].job_try == 1
    assert calls[0].user_id == "user-42"
    assert calls[0].team_id == "team-alpha"


@pytest.mark.asyncio
async def test_wrapper_delegates_to_engine_when_definition_is_set(
    seeded_task: str,
) -> None:
    # Seed a WorkflowRunRecord so the engine has a cursor anchor; we use
    # the same 3-state toy layout the Phase 178 engine tests use.
    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(
                id=seeded_task,
                query_text="test",
                action_id="test",
                module_id="test",
            ),
        )
        await session.commit()

    async def _start_handler(
        state_input: dict[str, Any], _services: object
    ) -> StateResult:
        n = int(state_input.get("n", 0)) + 1
        return StateResult(next_state="work", output={"n": n})

    async def _work_handler(
        state_input: dict[str, Any], _services: object
    ) -> StateResult:
        n = int(state_input.get("n", 0)) + 1
        return StateResult(
            next_state="__succeeded__",
            output={"n": n, "done": True},
        )

    class _ToyServices:
        pass

    async def _services_factory(_run_id: str) -> WorkflowServices:
        return _ToyServices()  # type: ignore[return-value]

    definition = WorkflowDefinition(
        definition_id="test.wrapper_engine.v1",
        start_state="start",
        states={
            "start": StateSpec(handler=_start_handler),
            "work": StateSpec(handler=_work_handler),
        },
        services_factory=_services_factory,
    )

    @platform_task(
        track="vulnerability",
        module_id="vulnerability",
        definition=definition,
    )
    async def engine_task(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        # Body must not be invoked when definition is set.
        raise AssertionError("body should not run when definition is provided")

    arq_ctx = {"job_id": seeded_task, "job_try": 1}
    result = await engine_task(arq_ctx, n=0)  # type: ignore[arg-type]

    # Engine ran the 2-state chain; terminal payload carries n=2, done=True.
    assert result["n"] == 2
    assert result["done"] is True


@pytest.mark.asyncio
async def test_wrapper_stashes_success_outcome(seeded_task: str) -> None:
    @platform_task(track="vulnerability", module_id="vulnerability")
    async def ok(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        return {"result_path": "/tmp/out"}

    arq_ctx = {"job_id": seeded_task, "job_try": 1}
    await ok(arq_ctx)  # type: ignore[arg-type]

    outcome = _pop_outcome(seeded_task, 1)
    assert outcome is not None
    assert outcome.kind == "success"
    assert outcome.result == {"result_path": "/tmp/out"}


@pytest.mark.asyncio
async def test_wrapper_stashes_exception_outcome_and_reraises(
    seeded_task: str,
) -> None:
    @platform_task(track="vulnerability", module_id="vulnerability")
    async def boom(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        raise RuntimeError("boom!")

    arq_ctx = {"job_id": seeded_task, "job_try": 1}
    with pytest.raises(RuntimeError, match="boom"):
        await boom(arq_ctx)  # type: ignore[arg-type]

    outcome = _pop_outcome(seeded_task, 1)
    assert outcome is not None
    assert outcome.kind == "exception"
    assert outcome.exception_class == "RuntimeError"
    assert isinstance(outcome.exception, RuntimeError)


@pytest.mark.asyncio
async def test_wrapper_converts_workflow_conflict_to_arq_retry(
    seeded_task: str,
) -> None:
    """WorkflowConflictError raised from the body is converted to arq.Retry.

    Exercises the ``definition is None`` path because the engine's public
    contract is to surface ``WorkflowConflictError`` only from its cursor
    UPDATE (not from user handlers). Phase 180's module wrappers will hit
    the same wrapper-catch code path when the engine's cursor layer raises.
    """
    from arq.worker import Retry

    from aila.platform.workflows import WorkflowConflictError

    @platform_task(track="vulnerability", module_id="vulnerability")
    async def conflict_task(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        raise WorkflowConflictError("cursor moved under us")

    arq_ctx = {"job_id": seeded_task, "job_try": 2}
    with pytest.raises(Retry):
        await conflict_task(arq_ctx)  # type: ignore[arg-type]

    outcome = _pop_outcome(seeded_task, 2)
    assert outcome is not None
    assert outcome.kind == "retry_signalled"
