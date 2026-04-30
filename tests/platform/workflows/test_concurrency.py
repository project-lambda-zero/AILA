"""Optimistic-lock concurrency tests (D-32, T-178-03).

The engine's cursor UPDATE is guarded by ``WHERE version = :loaded_version``.
When two workers both load version N and race to write, exactly one wins
(bumps to N+1); the other's UPDATE affects 0 rows and raises
``WorkflowConflictError``.

These tests drive ``_save_state`` directly rather than going through
``asyncio.gather(execute, execute)`` -- the direct path proves the
mechanism deterministically without timing flakiness. A real
concurrent-execute test would add value but is prone to races and is
covered implicitly by the direct-call tests plus ARQ's retry contract.
"""
from __future__ import annotations

import pytest

from aila.platform.workflows import (
    DurableStateMachine,
    State,
    WorkflowConflictError,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor


@pytest.mark.asyncio
async def test_stale_version_update_raises_conflict(
    workflow_run_id: str,
) -> None:
    """Stage cursor at version=5. Worker A saves (bumps to 6). Worker B
    attempts to save with stale loaded_version=5 -> raises
    WorkflowConflictError (D-32)."""
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="start",
                state_input={},
                retries_in_state=0,
                definition_id="test.conflict.v1",
                version=5,
            )
        )
        await session.commit()

    # Worker A: save succeeds, bumps version to 6.
    await DurableStateMachine._save_state(
        run_id=workflow_run_id,
        loaded_version=5,
        new_state=State(
            current="work", input={"n": 1}, retries_in_state=0, version=6
        ),
        definition_id="test.conflict.v1",
    )

    # Worker B: still has loaded_version=5; its UPDATE affects 0 rows.
    with pytest.raises(WorkflowConflictError):
        await DurableStateMachine._save_state(
            run_id=workflow_run_id,
            loaded_version=5,
            new_state=State(
                current="work", input={"n": 99}, retries_in_state=0, version=6
            ),
            definition_id="test.conflict.v1",
        )


@pytest.mark.asyncio
async def test_worker_b_next_attempt_sees_new_version(
    workflow_run_id: str,
) -> None:
    """After a conflict, worker B's retry reloads the cursor, sees
    version=6, and can proceed without conflict (the ARQ-retry flow)."""
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="start",
                state_input={},
                retries_in_state=0,
                definition_id="test.conflict.v1",
                version=5,
            )
        )
        await session.commit()

    # Worker A saves -> bumps to version 6.
    await DurableStateMachine._save_state(
        run_id=workflow_run_id,
        loaded_version=5,
        new_state=State(
            current="work", input={"n": 1}, retries_in_state=0, version=6
        ),
        definition_id="test.conflict.v1",
    )

    # Worker B's next attempt reloads the cursor (simulates ARQ retry).
    async with async_session_scope() as session:
        row = await session.get(WorkflowStateCursor, workflow_run_id)
        assert row is not None
        assert row.version == 6
        assert row.current_state == "work"

    # Worker B now saves with the new version and succeeds.
    await DurableStateMachine._save_state(
        run_id=workflow_run_id,
        loaded_version=6,
        new_state=State(
            current="__succeeded__",
            input={"n": 2, "done": True},
            retries_in_state=0,
            version=7,
        ),
        definition_id="test.conflict.v1",
    )

    async with async_session_scope() as session:
        row = await session.get(WorkflowStateCursor, workflow_run_id)
        assert row is not None
        assert row.version == 7
        assert row.current_state == "__succeeded__"


@pytest.mark.asyncio
async def test_conflict_error_message_is_generic(
    workflow_run_id: str,
) -> None:
    """Phase 178 fix 9: the public exception message is generic and does
    NOT leak the run_id / version numbers -- those go to structlog at
    warning level. Operators correlate via the log, not the string."""
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=workflow_run_id,
                current_state="start",
                state_input={},
                retries_in_state=0,
                definition_id="test.conflict.v1",
                version=0,
            )
        )
        await session.commit()

    await DurableStateMachine._save_state(
        run_id=workflow_run_id,
        loaded_version=0,
        new_state=State(
            current="work", input={}, retries_in_state=0, version=1
        ),
        definition_id="test.conflict.v1",
    )

    with pytest.raises(WorkflowConflictError) as exc_info:
        await DurableStateMachine._save_state(
            run_id=workflow_run_id,
            loaded_version=0,
            new_state=State(
                current="work", input={}, retries_in_state=0, version=1
            ),
            definition_id="test.conflict.v1",
        )

    message = str(exc_info.value)
    assert message == "Concurrent workflow modification detected"
    # Correlation data must NOT be in the public message.
    assert workflow_run_id not in message
    assert "loaded" not in message.lower()
