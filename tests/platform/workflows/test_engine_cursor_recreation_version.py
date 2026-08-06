"""Cursor-recreation version-chain bug (issue #40-4).

Background
----------
``DurableStateMachine._commit_transition`` holds a FOR UPDATE lock on the
run's ``workflow_state_cursor`` row before advancing it. If the row is
missing at that point (e.g. the parent_reconciler sweep raced the commit
and deleted a mid-state cursor), the engine recovers by INSERTing a
fresh row with the transition's ``new_state`` payload rather than
raising ``WorkflowConflictError`` and burning an ARQ retry.

Historical bug: the recovery INSERT wrote ``version=1`` unconditionally.
Callers construct ``new_state`` with ``version=loaded_state.version + 1``
and ``_commit_transition`` returns that ``new_state`` back to the engine
loop. The next iteration then calls ``_commit_transition`` with
``loaded_state = <that returned new_state>`` (version N+1), but the DB
row is at version 1. The FOR UPDATE reports ``current_version=1`` while
``loaded_state.version=N+1``; the mismatch check fires and raises
``WorkflowConflictError``, which under ARQ becomes a spurious retry.

Fix: write ``version=loaded_state.version + 1`` in the recreation
branch so the in-memory State matches the row the next iteration will
lock. See ``src/aila/platform/workflows/engine.py`` -- the recreation
site inside ``_commit_transition``.
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
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    WorkflowStateCursor,
    WorkflowStateTransition,
)
from tests.platform.workflows.conftest import (
    ToyServices,
    toy_services_factory,
)

# ---- Handlers used to drive the recreation path --------------------------


async def _delete_cursor_then_advance(
    state_input: dict[str, Any], services: ToyServices
) -> StateResult:
    """Handler that simulates a parent-reconciler race by deleting its
    own cursor row inside its OWN transaction before returning. The
    engine's subsequent ``_commit_transition`` will hit the recreation
    path because the FOR UPDATE lookup returns no row.
    """
    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, services.run_id)
        if cursor is not None:
            await session.delete(cursor)
            await session.commit()
    return StateResult(next_state="finalize", output={"deleted": True})


async def _finalize(
    state_input: dict[str, Any], services: ToyServices
) -> StateResult:
    """Runs after the recreation-path commit. If the recreated cursor's
    version continues the chain (loaded_state.version + 1), this
    handler's commit finds a matching current_version and cleanly moves
    to __succeeded__. If the recreated cursor was reset to 1 (bug), the
    engine loop's in-memory State is at loaded_state.version + 1 and
    the FOR UPDATE detects the mismatch, raising ``WorkflowConflictError``.
    """
    return StateResult(next_state="__succeeded__", output={"finalized": True})


# ---- Test 1: recreated cursor's version equals staged+1 (not 1) ----------


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_recreation_writes_loaded_version_plus_one(
    workflow_run_id: str,
) -> None:
    """One-shot workflow: single handler deletes the cursor and returns
    __succeeded__. After ``execute`` returns, the DB row must carry the
    staged version + 1, proving the recreation branch preserved the
    optimistic-lock chain rather than resetting to 1.
    """
    staged_version = 9

    async def _handler(
        state_input: dict[str, Any], services: ToyServices
    ) -> StateResult:
        async with async_session_scope() as session:
            cursor = await session.get(WorkflowStateCursor, services.run_id)
            if cursor is not None:
                await session.delete(cursor)
                await session.commit()
        return StateResult(next_state="__succeeded__", output={"ok": True})

    definition = WorkflowDefinition(
        definition_id="test.recreation.oneshot.v1",
        start_state="delete_then_end",
        states={
            "delete_then_end": StateSpec(handler=_handler),
        },
        services_factory=toy_services_factory,
    )

    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="delete_then_end",
                state_input={},
                retries_in_state=0,
                definition_id="test.recreation.oneshot.v1",
                version=staged_version,
            )
        )
        await session.commit()

    out = await DurableStateMachine.execute(workflow_run_id, definition, {})
    assert out == {"ok": True}

    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None, (
            "recreation branch must INSERT the cursor; got None"
        )
        assert cursor.version == staged_version + 1, (
            f"recreated cursor.version={cursor.version} (expected "
            f"{staged_version + 1}); the recreation branch reset the "
            "optimistic-lock chain and the next commit would burn a retry"
        )
        assert cursor.current_state == "__succeeded__"


# ---- Test 2: subsequent advance does not burn a version-conflict retry ---


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_recreation_next_advance_does_not_burn_retry(
    workflow_run_id: str,
) -> None:
    """Two-state workflow. The first state deletes its own cursor and
    transitions to ``finalize``. ``_commit_transition`` writes the
    recreated cursor with the chain preserved (version = staged + 1).
    The engine loop immediately runs ``finalize`` and commits again;
    that second commit's FOR UPDATE must see a matching version and
    advance cleanly to __succeeded__ (staged + 2). If the recreation
    branch reset to 1, this second commit would raise
    ``WorkflowConflictError`` and no ``exited:retry`` audit row would
    ever land because ``_step_once`` propagates the raise up through
    ``execute`` instead of self-retrying. Both signals are asserted.
    """
    staged_version = 5

    definition = WorkflowDefinition(
        definition_id="test.recreation.chain.v1",
        start_state="delete_cursor",
        states={
            "delete_cursor": StateSpec(handler=_delete_cursor_then_advance),
            "finalize": StateSpec(handler=_finalize),
        },
        services_factory=toy_services_factory,
    )

    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="delete_cursor",
                state_input={},
                retries_in_state=0,
                definition_id="test.recreation.chain.v1",
                version=staged_version,
            )
        )
        await session.commit()

    # Whole run must complete without raising. Pre-fix, the finalize
    # commit raised WorkflowConflictError because the recreated cursor
    # was at version=1 while the engine loop was carrying an in-memory
    # State at version=staged_version+1.
    out = await DurableStateMachine.execute(workflow_run_id, definition, {})
    assert out == {"finalized": True}

    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        # Recreation bumps staged -> staged+1; normal advance to
        # __succeeded__ bumps to staged+2. Both must be visible.
        assert cursor.version == staged_version + 2, (
            f"final cursor.version={cursor.version} (expected "
            f"{staged_version + 2}); a version-conflict retry, an extra "
            "advance, or a reset in the recreation branch would break "
            "this equality"
        )
        assert cursor.current_state == "__succeeded__"

        # No exited:retry audit rows: the engine never triggered a
        # WorkflowConflictError-driven retry cycle.
        result = await session.exec(
            select(WorkflowStateTransition).where(
                WorkflowStateTransition.run_id == workflow_run_id
            )
        )
        events = [r.event for r in result.all()]
        retries = [e for e in events if e == "exited:retry"]
        assert retries == [], (
            f"expected no exited:retry rows; got {retries!r} in {events!r}. "
            "The recreated cursor's version desynced from the engine's "
            "in-memory State and the next commit burned a spurious retry."
        )
        # Positive shape check: recreation commit's exited:ok, plus the
        # normal advance to __succeeded__.
        ok_events = [e for e in events if e.startswith("exited:")]
        assert ok_events.count("exited:ok") >= 2, (
            f"expected two exited:ok transitions (recreation commit "
            f"and finalize commit); got {ok_events!r}"
        )


# ---- Test 3: retries_in_state is preserved across the recreation --------


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_recreation_preserves_retries_in_state(
    workflow_run_id: str,
) -> None:
    """The recreation branch writes ``retries_in_state=new_state.retries_in_state``.
    On a normal (non-retry) transition ``new_state.retries_in_state == 0``,
    so this test stages a run whose delete-cursor handler transitions
    into the same state with a bumped retries_in_state via the manual
    ``StateResult`` chain would require a retriable exception. Instead
    we verify the simpler invariant: the recreated cursor's
    ``retries_in_state`` matches ``new_state.retries_in_state`` (0 on
    the happy path) and the ``current_state`` matches ``new_state.current``.
    Regressions that swap in stale values from the missing lookup row
    would fail this.
    """
    staged_version = 2

    async def _hop(
        state_input: dict[str, Any], services: ToyServices
    ) -> StateResult:
        async with async_session_scope() as session:
            cursor = await session.get(WorkflowStateCursor, services.run_id)
            if cursor is not None:
                await session.delete(cursor)
                await session.commit()
        return StateResult(next_state="__succeeded__", output={"hopped": True})

    definition = WorkflowDefinition(
        definition_id="test.recreation.fields.v1",
        start_state="hop",
        states={"hop": StateSpec(handler=_hop)},
        services_factory=toy_services_factory,
    )

    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="hop",
                state_input={"seed": 1},
                # Stage retries_in_state > 0 so we can prove the
                # recreation branch does NOT copy the DELETED row's
                # value (there is no row) and instead uses the
                # new_state payload the caller constructed (retries=0
                # on a successful transition).
                retries_in_state=7,
                definition_id="test.recreation.fields.v1",
                version=staged_version,
            )
        )
        await session.commit()

    out = await DurableStateMachine.execute(workflow_run_id, definition, {})
    assert out == {"hopped": True}

    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
        assert cursor is not None
        assert cursor.current_state == "__succeeded__"
        assert cursor.retries_in_state == 0, (
            "recreation branch must adopt new_state.retries_in_state "
            "(0 on a successful advance), not resurrect the deleted "
            f"row's value; got {cursor.retries_in_state}"
        )
        assert cursor.version == staged_version + 1, (
            f"cursor.version={cursor.version}, expected {staged_version + 1}"
        )
