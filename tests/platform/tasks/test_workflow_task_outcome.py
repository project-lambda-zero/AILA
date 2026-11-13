"""Issue #442: a workflow-engine task's TaskRecord follows the run's terminal.

``DurableStateMachine.execute`` returns normally for every terminal cursor,
including ``__crashed__`` and ``__failed__``. The ``@platform_task`` wrapper
and the ``on_job_end`` hook together must record a failed run as FAILED (and
keep its WAITING dependents parked), a cancelled run as CANCELLED, and only a
succeeded run as DONE. A cancelled run is one the state reconciler closed
(cursor ``__cancelled__``, run row ``cancelled``) before the attempt started.

Runs the real wrapper, engine, and hook against the test Postgres; the ARQ
pool is patched so a wrongly released dependent never reaches Redis.
"""
from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlmodel import select

from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.hooks import _OUTCOME_STASH, _on_job_end
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.template import _REGISTRY, platform_task
from aila.platform.workflows import (
    StateResult,
    StateSpec,
    WorkflowDefinition,
    WorkflowServices,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateCursor

Handler = Callable[[dict[str, Any], object], Awaitable[StateResult]]


@pytest.fixture(autouse=True)
def _isolate_registry() -> Any:
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


@pytest_asyncio.fixture
async def task_and_dependent(test_db: None) -> tuple[str, str]:  # noqa: ARG001
    """A RUNNING workflow task and a WAITING dependent of it."""
    task_id = str(uuid.uuid4())
    dep_id = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=task_id,
                track="vulnerability",
                fn_path=f"tests.workflow_outcome.parent_{task_id[:8]}",
                fn_module="tests",
                status=TaskStatus.RUNNING,
                user_id="user-442",
                group_id="operator",
                kwargs_json="{}",
            ),
        )
        session.add(
            TaskRecord(
                id=dep_id,
                track="vulnerability",
                fn_path=f"tests.workflow_outcome.dependent_{dep_id[:8]}",
                fn_module="tests",
                status=TaskStatus.WAITING,
                user_id="user-442",
                group_id="operator",
                kwargs_json="{}",
                depends_on_json=f'["{task_id}"]',
            ),
        )
        await session.commit()
    return task_id, dep_id


async def _succeed(_state_input: dict[str, Any], _services: object) -> StateResult:
    return StateResult(next_state="__succeeded__", output={"done": True})


async def _raise(_state_input: dict[str, Any], _services: object) -> StateResult:
    raise RuntimeError("handler blew up")


async def _fail(_state_input: dict[str, Any], _services: object) -> StateResult:
    return StateResult(next_state="__failed__", output={"reason": "no evidence"})


async def _run_workflow_task(
    task_id: str, handler: Handler, definition_id: str | None = None,
) -> None:
    """Drive one attempt through the real wrapper, engine, and end hook."""

    async def _services_factory(_run_id: str) -> WorkflowServices:
        return object()  # type: ignore[return-value]

    definition = WorkflowDefinition(
        definition_id=definition_id or f"test.workflow_outcome.{uuid.uuid4().hex[:8]}",
        start_state="start",
        states={"start": StateSpec(handler=handler, max_retries=0)},
        services_factory=_services_factory,
    )

    @platform_task(track="vulnerability", module_id="vulnerability", definition=definition)
    async def workflow_task(ctx: TaskContext, **kwargs: Any) -> dict[str, Any]:
        raise AssertionError("the engine runs the definition, not this body")

    pool = MagicMock()
    pool.enqueue_job = AsyncMock()
    pool.aclose = AsyncMock()
    arq_ctx = {"job_id": task_id, "job_try": 1}
    with patch("aila.platform.tasks.hooks._create_pool", new=AsyncMock(return_value=pool)):
        await workflow_task(arq_ctx)  # type: ignore[arg-type]
        await _on_job_end(arq_ctx)


async def _task(task_id: str) -> TaskRecord:
    async with async_session_scope() as session:
        rec = (await session.exec(select(TaskRecord).where(TaskRecord.id == task_id))).first()
    assert rec is not None
    return rec


async def _cursor_state(run_id: str) -> str:
    async with async_session_scope() as session:
        cursor = (
            await session.exec(
                select(WorkflowStateCursor).where(WorkflowStateCursor.run_id == run_id)
            )
        ).first()
    assert cursor is not None
    return cursor.current_state


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "cursor", "error_parts"),
    [
        (_raise, "__crashed__", ["code=WORKFLOW_FAILED", "failed_state=start", "error_class=RuntimeError"]),
        (_fail, "__failed__", ["code=WORKFLOW_FAILED"]),
    ],
    ids=["handler_raises", "handler_fails"],
)
async def test_failed_workflow_run_marks_the_task_failed(
    task_and_dependent: tuple[str, str],
    handler: Handler,
    cursor: str,
    error_parts: list[str],
) -> None:
    task_id, dep_id = task_and_dependent

    await _run_workflow_task(task_id, handler)

    assert await _cursor_state(task_id) == cursor
    rec = await _task(task_id)
    assert rec.status == TaskStatus.FAILED
    assert rec.completed_at is not None
    for part in error_parts:
        assert part in (rec.error or "")
    # A failed parent never releases the work that depends on it.
    assert (await _task(dep_id)).status == TaskStatus.WAITING


@pytest.mark.asyncio
async def test_cancelled_workflow_run_marks_the_task_cancelled(
    task_and_dependent: tuple[str, str],
) -> None:
    task_id, dep_id = task_and_dependent
    definition_id = f"test.workflow_outcome.{uuid.uuid4().hex[:8]}"
    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(id=task_id, query_text="test", status="cancelled"),
        )
        await session.flush()
        session.add(
            WorkflowStateCursor(
                run_id=task_id,
                current_state="__cancelled__",
                state_input={},
                definition_id=definition_id,
            ),
        )
        await session.commit()

    await _run_workflow_task(task_id, _succeed, definition_id)

    assert await _cursor_state(task_id) == "__cancelled__"
    assert (await _task(task_id)).status == TaskStatus.CANCELLED
    assert (await _task(dep_id)).status == TaskStatus.WAITING


@pytest.mark.asyncio
async def test_succeeded_workflow_run_marks_the_task_done_and_releases_dependents(
    task_and_dependent: tuple[str, str],
) -> None:
    task_id, dep_id = task_and_dependent

    await _run_workflow_task(task_id, _succeed)

    assert await _cursor_state(task_id) == "__succeeded__"
    rec = await _task(task_id)
    assert rec.status == TaskStatus.DONE
    assert rec.error is None
    assert (await _task(dep_id)).status == TaskStatus.QUEUED
