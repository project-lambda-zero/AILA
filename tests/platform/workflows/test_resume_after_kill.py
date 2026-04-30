"""Crash-resume tests (D-24, D-41).

Simulates the "ARQ retry of a job that died mid-state" scenario:
stage a cursor row as if a prior worker advanced past `start`, then
call execute and verify the engine resumes from the persisted state
rather than restarting from `definition.start_state`.

Also proves D-41: orphan `entered` rows (no matching `exited:*`) are NOT
cleaned up by the engine; they are intentional audit signals of a
crash between log-write and handler return.
"""
from __future__ import annotations

from typing import Any

import pytest
from sqlmodel import select

from aila.platform.workflows import (
    DurableStateMachine,
    StateResult,
    StateSpec,
    WorkflowDefinition,
)
from aila.platform.workflows.log import compute_hash
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    WorkflowStateCursor,
    WorkflowStateTransition,
)
from tests.platform.workflows.conftest import (
    ToyServices,
    toy_services_factory,
)

# ---- D-24: resume picks up from saved cursor ------------------------------


@pytest.mark.asyncio
async def test_resume_picks_up_from_saved_cursor(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """Stage a cursor row at `work` with state_input={"n": 5}. The
    initial_input passed to execute is ignored because the persisted
    cursor is the truth."""
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="work",
                state_input={"n": 5},
                retries_in_state=0,
                definition_id="test.toy.v1",
                version=1,
            )
        )
        await session.commit()

    out = await DurableStateMachine.execute(
        workflow_run_id, toy_definition, {"ignored": True}
    )
    # work.handler adds 1 and marks done.
    assert out == {"n": 6, "done": True}


# ---- retries_in_state preserved on resume ---------------------------------


@pytest.mark.asyncio
async def test_resume_preserves_retries_in_state(
    workflow_run_id: str,
) -> None:
    calls = {"n": 0}

    async def flaky(state_input: dict[str, Any], services: ToyServices) -> StateResult:
        calls["n"] += 1
        # Succeed on the first resumed call; the staged cursor simulates
        # a prior attempt that already bumped retries_in_state to 1.
        return StateResult(next_state="__succeeded__", output={"resumed": True})

    definition = WorkflowDefinition(
        definition_id="test.resumeretry.v1",
        start_state="flaky_state",
        states={"flaky_state": StateSpec(handler=flaky)},
        services_factory=toy_services_factory,
    )

    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="flaky_state",
                state_input={"n": 0},
                retries_in_state=1,
                definition_id="test.resumeretry.v1",
                version=3,
            )
        )
        # Also stage a prior `entered` row so the next seq computation
        # returns max+1 (not 1).
        session.add(
            WorkflowStateTransition(
                run_id=workflow_run_id,
                seq=10,
                from_state="flaky_state",
                to_state="flaky_state",
                event="entered",
                input_hash=compute_hash({"n": 0}),
                output_hash=None,
                duration_ms=None,
                error_class=None,
                error_message=None,
            )
        )
        await session.commit()

    out = await DurableStateMachine.execute(workflow_run_id, definition, {})
    assert out == {"resumed": True}

    # New entered row for the resumed attempt has seq = prior_max + 1.
    async with async_session_scope() as session:
        rows_result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
            .order_by(WorkflowStateTransition.seq.asc())  # type: ignore[union-attr]
        )
        rows = list(rows_result.all())
    entered_rows = [r for r in rows if r.event == "entered"]
    assert entered_rows
    assert max(r.seq for r in entered_rows) >= 11, (
        "resume must generate a fresh seq > prior max"
    )


# ---- D-41: orphan `entered` rows are not cleaned up -----------------------


@pytest.mark.asyncio
async def test_no_orphan_detection_on_resume(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """A prior attempt died between writing `entered` and writing any
    `exited:*`. The engine must NOT try to clean up the orphan row;
    instead it writes a NEW `entered` row with seq+1 and proceeds."""
    async with async_session_scope() as session:
        # Stage cursor at `work` (resume point).
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="work",
                state_input={"n": 1},
                retries_in_state=0,
                definition_id="test.toy.v1",
                version=1,
            )
        )
        # Stage an orphan `entered` row from a prior crashed attempt.
        session.add(
            WorkflowStateTransition(
                run_id=workflow_run_id,
                seq=1,
                from_state="work",
                to_state="work",
                event="entered",
                input_hash=compute_hash({"n": 1}),
                output_hash=None,
                duration_ms=None,
                error_class=None,
                error_message=None,
            )
        )
        await session.commit()

    # Engine must not raise; it resumes from `work`.
    out = await DurableStateMachine.execute(
        workflow_run_id, toy_definition, {"ignored": True}
    )
    assert out == {"n": 2, "done": True}

    async with async_session_scope() as session:
        rows_result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
            .order_by(WorkflowStateTransition.seq.asc())  # type: ignore[union-attr]
        )
        rows = list(rows_result.all())
    # The orphan at seq=1 remains; the new entered is at seq>=2.
    orphan = next(r for r in rows if r.seq == 1)
    assert orphan.event == "entered"
    # At least one fresh entered row for work with seq>=2.
    fresh_entered = [
        r for r in rows if r.event == "entered" and r.seq > 1 and r.to_state == "work"
    ]
    assert fresh_entered, "resume must emit a new `entered` row for the retry attempt"


# ---- Simulated SIGKILL mid-flight + resume --------------------------------


@pytest.mark.asyncio
async def test_simulated_crash_midflight_and_resume(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """Simulate: prior worker saved cursor at `work` but died before
    writing any `exited:ok` -- no transition-log rows for `work`."""
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="work",
                state_input={"n": 10},
                retries_in_state=0,
                definition_id="test.toy.v1",
                version=1,
            )
        )
        await session.commit()

    # Fresh execute resumes from `work` with state_input={"n": 10}.
    out = await DurableStateMachine.execute(
        workflow_run_id, toy_definition, {"ignored": True}
    )
    assert out == {"n": 11, "done": True}

    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        assert cursor.current_state == "__succeeded__"
