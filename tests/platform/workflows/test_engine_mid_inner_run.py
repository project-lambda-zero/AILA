"""Integration tests for _handle_mid_inner_run (Phase 183 Plan 01).

These tests verify that when a dispatcher definition's execute() call
re-enters _load_or_init_cursor while the cursor is mid-inner-run under a
different definition_id, the engine returns a synthetic __succeeded__ state
rather than crashing with UnknownNextStateError.

All three tests depend on WorkflowDefinition.is_dispatcher which is added in
Plan 02 (183-02). They are skipped until that field lands.

No mocks. No monkeypatching. Real PostgreSQL via the test_db fixture.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from typing import Any

import pytest

from aila.platform.workflows import (
    DurableStateMachine,
    StateResult,
    StateSpec,
    WorkflowDefinition,
    WorkflowServices,
)
from aila.platform.workflows.types import RESERVED_SUCCEEDED
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateCursor

pytestmark = pytest.mark.asyncio

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INNER_DEF_ID = "vulnerability.full_analysis.v1"
_DISPATCHER_DEF_ID = "vulnerability.dispatcher.v1"


@dataclass
class _ToyServices:
    run_id: str
    handler_calls: dict[str, int] = field(default_factory=dict)

    @classmethod
    async def build(cls, run_id: str) -> _ToyServices:
        return cls(run_id=run_id)


async def _toy_services_factory(run_id: str) -> WorkflowServices:
    return await _ToyServices.build(run_id)


async def _routing_handler(
    state_input: dict[str, Any], services: _ToyServices
) -> StateResult:
    return StateResult(
        next_state="__succeeded__",
        output={"selected_definition_id": _INNER_DEF_ID},
    )


def _make_run_id() -> str:
    return str(uuid.uuid4())


async def _insert_run_record(run_id: str) -> None:
    """Insert a minimal WorkflowRunRecord so the FK constraint is satisfied."""
    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(
                id=run_id,
                query_text="test",
                action_id="test",
                module_id="test",
            )
        )
        await session.commit()


async def _insert_cursor(
    run_id: str,
    *,
    current_state: str,
    definition_id: str,
    state_input: dict[str, Any] | None = None,
    version: int = 1,
) -> None:
    """Insert a WorkflowStateCursor row directly, bypassing the engine."""
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=run_id,
                current_state=current_state,
                definition_id=definition_id,
                state_input=state_input or {},
                retries_in_state=0,
                version=version,
            )
        )
        await session.commit()


def _make_inner_definition() -> WorkflowDefinition:
    """Build a minimal inner WorkflowDefinition used as a dispatches_to target."""
    async def _inner_handler(
        state_input: dict[Any, Any], services: _ToyServices
    ) -> StateResult:
        return StateResult(next_state="__succeeded__", output={"inner": True})

    return WorkflowDefinition(
        definition_id=_INNER_DEF_ID,
        start_state="inner_state",
        allow_phase_handoff=True,
        states={
            "inner_state": StateSpec(handler=_inner_handler),
        },
        services_factory=_toy_services_factory,
    )


def _make_dispatcher_definition() -> WorkflowDefinition:
    """Build a minimal dispatcher WorkflowDefinition.

    Plan 02 (183-02) delivers is_dispatcher + dispatches_to. Now that
    is_dispatcher=True requires non-empty dispatches_to, supply a minimal
    inner definition keyed by _INNER_DEF_ID.
    """
    inner = _make_inner_definition()
    return WorkflowDefinition(
        definition_id=_DISPATCHER_DEF_ID,
        start_state="routing",
        states={
            "routing": StateSpec(handler=_routing_handler),
        },
        services_factory=_toy_services_factory,
        is_dispatcher=True,
        dispatches_to={_INNER_DEF_ID: inner},
    )


def _skip_if_no_is_dispatcher() -> None:
    """Raise pytest.skip if WorkflowDefinition does not yet accept is_dispatcher."""
    try:
        _make_dispatcher_definition()
    except (TypeError, ValueError):
        pytest.skip(reason="depends on 183-02 WorkflowDefinition.is_dispatcher field")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_mid_inner_run_returns_synthetic_succeeded(test_db: None) -> None:
    """Fourth branch: cursor at mid-inner-run state returns synthetic __succeeded__.

    Setup:
        - Cursor exists at state "intel" under inner definition_id.
        - Dispatcher calls _load_or_init_cursor.
    Expected:
        - Returns State(current=__succeeded__) with selected_definition_id set.
    """
    _skip_if_no_is_dispatcher()

    run_id = _make_run_id()
    await _insert_run_record(run_id)
    await _insert_cursor(
        run_id,
        current_state="intel",
        definition_id=_INNER_DEF_ID,
        state_input={"target": "10.0.0.1"},
    )

    dispatcher = _make_dispatcher_definition()
    state = await DurableStateMachine._load_or_init_cursor(
        run_id, dispatcher, {}
    )

    assert state.current == RESERVED_SUCCEEDED
    assert state.input["selected_definition_id"] == _INNER_DEF_ID
    # Inner state_input is merged in
    assert state.input.get("target") == "10.0.0.1"


async def test_mid_inner_run_returns_existing_terminal_when_already_advanced(
    test_db: None,
) -> None:
    """Post-lock re-check: cursor already at terminal under dispatcher definition.

    Setup:
        - Cursor is at __succeeded__ under the dispatcher's definition_id.
    Expected:
        - Returns State(current=__succeeded__) directly without synthesising.
    """
    _skip_if_no_is_dispatcher()

    run_id = _make_run_id()
    await _insert_run_record(run_id)
    await _insert_cursor(
        run_id,
        current_state=RESERVED_SUCCEEDED,
        definition_id=_DISPATCHER_DEF_ID,
        state_input={"selected_definition_id": _INNER_DEF_ID},
        version=3,
    )

    dispatcher = _make_dispatcher_definition()
    # The cursor is terminal under the dispatcher def -- fourth branch guard
    # requires row.current_state NOT in RESERVED_TERMINAL_STATES, so this
    # actually falls through to the catch-all branch and returns the terminal
    # state as-is. Either way, the result must be the terminal state.
    state = await DurableStateMachine._load_or_init_cursor(
        run_id, dispatcher, {}
    )

    assert state.current == RESERVED_SUCCEEDED
    assert state.version == 3


async def test_mid_inner_run_concurrent_retries_both_succeed(
    test_db: None,
) -> None:
    """Concurrent retries on the same run_id both return synthetic __succeeded__.

    FOR UPDATE serialises the reads but does NOT prevent both from succeeding.
    The dispatch layer (Plan 02) owns idempotency of dual __succeeded__.

    Both results must:
        - Have current == __succeeded__
        - Have the same selected_definition_id
        - Not raise any exception
    """
    _skip_if_no_is_dispatcher()

    run_id = _make_run_id()
    await _insert_run_record(run_id)
    await _insert_cursor(
        run_id,
        current_state="intel",
        definition_id=_INNER_DEF_ID,
        state_input={"target": "10.0.0.2"},
    )

    dispatcher = _make_dispatcher_definition()

    state_a, state_b = await asyncio.gather(
        DurableStateMachine._load_or_init_cursor(run_id, dispatcher, {}),
        DurableStateMachine._load_or_init_cursor(run_id, dispatcher, {}),
    )

    assert state_a.current == RESERVED_SUCCEEDED
    assert state_b.current == RESERVED_SUCCEEDED
    assert state_a.input["selected_definition_id"] == _INNER_DEF_ID
    assert state_b.input["selected_definition_id"] == _INNER_DEF_ID
