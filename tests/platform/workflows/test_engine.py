"""Happy-path tests for DurableStateMachine.execute.

3-state toy workflow: ``start -> work -> __succeeded__``. Covers:
  - end-to-end execute returns terminal output (D-02, D-23)
  - cursor row ends on reserved terminal state (D-17)
  - idempotent re-execution on terminal state (D-26)
  - unknown next_state -> non-retriable failure -> __crashed__ (T-178-07)
"""
from __future__ import annotations

import pytest

from aila.platform.workflows import (
    DurableStateMachine,
    StateResult,
    StateSpec,
    WorkflowDefinition,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor


@pytest.mark.asyncio
async def test_happy_path_reaches_terminal(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    out = await DurableStateMachine.execute(
        workflow_run_id, toy_definition, {"n": 0}
    )
    assert out == {"n": 2, "done": True}


@pytest.mark.asyncio
async def test_cursor_ends_on_terminal(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    await DurableStateMachine.execute(workflow_run_id, toy_definition, {"n": 0})
    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        assert cursor.current_state == "__succeeded__"
        assert cursor.version == 2
        assert cursor.retries_in_state == 0


@pytest.mark.asyncio
async def test_idempotent_reexecution_on_terminal(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """Re-executing on a terminal cursor is a no-op (D-26)."""
    await DurableStateMachine.execute(workflow_run_id, toy_definition, {"n": 0})
    # Second invocation must not invoke any handler (cursor already terminal).
    out = await DurableStateMachine.execute(
        workflow_run_id, toy_definition, {"n": 999}
    )
    assert out == {"n": 2, "done": True}
    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        assert cursor.version == 2, (
            "idempotent re-execution must not bump version"
        )


@pytest.mark.asyncio
async def test_unknown_next_state_is_non_retriable(workflow_run_id: str) -> None:
    """A handler returning a next_state not in the definition is
    treated as non-retriable (T-178-07). The engine routes to
    on_failure (unset here -> __crashed__)."""
    from tests.platform.workflows.conftest import ToyServices, toy_services_factory

    async def bogus_handler(state_input: dict, services: ToyServices) -> StateResult:
        return StateResult(next_state="does_not_exist", output={})

    definition = WorkflowDefinition(
        definition_id="test.bogus.v1",
        start_state="start",
        states={"start": StateSpec(handler=bogus_handler)},
        services_factory=toy_services_factory,
    )
    out = await DurableStateMachine.execute(workflow_run_id, definition, {})
    # Failure routed to __crashed__ (no on_failure set).
    assert isinstance(out, dict)
    assert "error" in out or "origin_state" in out or "failed_state" in out
    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        assert cursor.current_state == "__crashed__"


# ---- Phase 178 amendment (2026-04-13): two-level dispatch handoff ----------


@pytest.mark.asyncio
async def test_phase_handoff_resets_cursor_and_runs_new_definition(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """Terminal cursor + different definition_id + allow_phase_handoff=True
    must reset the cursor to the new start_state and run to its terminal."""
    from tests.platform.workflows.conftest import toy_services_factory

    await DurableStateMachine.execute(workflow_run_id, toy_definition, {"n": 0})
    async with async_session_scope() as session:
        pre = await session.get(WorkflowStateCursor, workflow_run_id)
        assert pre is not None
        assert pre.current_state == "__succeeded__"
        pre_version = pre.version

    async def phase2_only(state_input: dict, services: object) -> StateResult:
        return StateResult(
            next_state="__succeeded__",
            output={"phase2": True, "carried": state_input.get("carry")},
        )

    phase2 = WorkflowDefinition(
        definition_id="test.phase2.v1",
        start_state="phase2_work",
        states={"phase2_work": StateSpec(handler=phase2_only)},
        services_factory=toy_services_factory,
        allow_phase_handoff=True,
    )

    out = await DurableStateMachine.execute(
        workflow_run_id, phase2, {"carry": "abc"}
    )
    assert out == {"phase2": True, "carried": "abc"}

    async with async_session_scope() as session:
        post = await session.get(WorkflowStateCursor, workflow_run_id)
        assert post is not None
        assert post.current_state == "__succeeded__"
        assert post.definition_id == "test.phase2.v1"
        # +1 for handoff reset, +1 for phase2_work -> __succeeded__
        assert post.version == pre_version + 2


@pytest.mark.asyncio
async def test_phase_handoff_writes_synthetic_transition_row(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """The handoff must emit exactly one exited:phase_handoff audit row
    whose from_state is the previous terminal and to_state is the new
    definition's start_state."""
    from sqlmodel import select

    from aila.storage.db_models import WorkflowStateTransition
    from tests.platform.workflows.conftest import toy_services_factory

    await DurableStateMachine.execute(workflow_run_id, toy_definition, {"n": 0})

    async def phase2_only(state_input: dict, services: object) -> StateResult:
        return StateResult(next_state="__succeeded__", output={"ok": True})

    phase2 = WorkflowDefinition(
        definition_id="test.phase2.v1",
        start_state="phase2_work",
        states={"phase2_work": StateSpec(handler=phase2_only)},
        services_factory=toy_services_factory,
        allow_phase_handoff=True,
    )
    await DurableStateMachine.execute(workflow_run_id, phase2, {"carry": "x"})

    async with async_session_scope() as session:
        rows = (
            await session.execute(
                select(WorkflowStateTransition)
                .where(WorkflowStateTransition.run_id == workflow_run_id)
                .where(WorkflowStateTransition.event == "exited:phase_handoff")
            )
        ).scalars().all()
        assert len(rows) == 1
        handoff = rows[0]
        assert handoff.from_state == "__succeeded__"
        assert handoff.to_state == "phase2_work"
        assert handoff.error_class is None


@pytest.mark.asyncio
async def test_phase_handoff_disabled_preserves_idempotent_reexecute(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """With allow_phase_handoff=False (default), a different definition_id
    on a terminal cursor must NOT trigger a reset; the existing terminal
    state is returned verbatim (preserves D-26)."""
    from tests.platform.workflows.conftest import toy_services_factory

    await DurableStateMachine.execute(workflow_run_id, toy_definition, {"n": 0})

    async def other_handler(state_input: dict, services: object) -> StateResult:
        return StateResult(next_state="__succeeded__", output={"other": True})

    other = WorkflowDefinition(
        definition_id="test.other.v1",
        start_state="other_start",
        states={"other_start": StateSpec(handler=other_handler)},
        services_factory=toy_services_factory,
        # allow_phase_handoff defaults to False
    )
    out = await DurableStateMachine.execute(workflow_run_id, other, {"x": 1})
    # Must return toy_definition's terminal output, NOT other's.
    assert out == {"n": 2, "done": True}

    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        # definition_id unchanged -- no handoff occurred.
        assert cursor.definition_id == "test.toy.v1"


@pytest.mark.asyncio
async def test_phase_handoff_same_definition_id_is_still_idempotent(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """allow_phase_handoff=True + SAME definition_id on a terminal cursor
    must remain idempotent (ARQ-retry-after-terminal semantics)."""
    from tests.platform.workflows.conftest import toy_services_factory

    handoff_toy = WorkflowDefinition(
        definition_id=toy_definition.definition_id,
        start_state=toy_definition.start_state,
        states=dict(toy_definition.states),
        services_factory=toy_services_factory,
        allow_phase_handoff=True,
    )
    await DurableStateMachine.execute(workflow_run_id, handoff_toy, {"n": 0})
    out = await DurableStateMachine.execute(
        workflow_run_id, handoff_toy, {"n": 999}
    )
    assert out == {"n": 2, "done": True}
    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        assert cursor.version == 2  # no handoff bump


@pytest.mark.asyncio
async def test_phase_handoff_not_triggered_on_non_terminal_cursor(
    workflow_run_id: str,
) -> None:
    """A non-terminal cursor must never be disrupted by a different
    definition -- only RESERVED_TERMINAL_STATES gate the handoff."""
    from tests.platform.workflows.conftest import toy_services_factory

    # Pre-seed a non-terminal cursor at state "midflight".
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="midflight",
                state_input={"keep": True},
                retries_in_state=0,
                definition_id="test.original.v1",
                version=5,
            )
        )
        await session.commit()

    async def other_handler(state_input: dict, services: object) -> StateResult:
        return StateResult(next_state="__succeeded__", output={"other": True})

    other = WorkflowDefinition(
        definition_id="test.other.v1",
        start_state="other_start",
        states={"other_start": StateSpec(handler=other_handler)},
        services_factory=toy_services_factory,
        allow_phase_handoff=True,
    )
    # Must not hand off; the engine should attempt to step from the loaded
    # non-terminal state under the new definition, which raises
    # UnknownNextStateError (state "midflight" isn't in other.states).
    from aila.platform.workflows.errors import UnknownNextStateError

    with pytest.raises(UnknownNextStateError):
        await DurableStateMachine.execute(workflow_run_id, other, {})

    # Critical assertion: no handoff row was written and cursor was not
    # reset to other.start_state.
    from sqlmodel import select

    from aila.storage.db_models import WorkflowStateTransition

    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        assert cursor.current_state == "midflight"
        assert cursor.definition_id == "test.original.v1"
        assert cursor.version == 5
        handoff_rows = (
            await session.execute(
                select(WorkflowStateTransition)
                .where(WorkflowStateTransition.run_id == workflow_run_id)
                .where(WorkflowStateTransition.event == "exited:phase_handoff")
            )
        ).scalars().all()
        assert handoff_rows == []
