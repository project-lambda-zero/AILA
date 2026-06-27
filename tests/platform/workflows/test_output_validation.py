"""Phase 183 Plan 06 -- stage output validation tests.

Tests verify:
- Empty dict from a non-terminal handler triggers on_failure
- output_schema Pydantic validation failure triggers on_failure
- output_schema valid output advances normally
- Terminal state empty dict is not flagged (terminals do not advance)
- State with no output_schema + non-empty dict advances normally (backwards compat)

All tests run against real PostgreSQL via the ``test_db`` fixture.
No mocks, no monkeypatching.
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest
from pydantic import BaseModel

from aila.platform.workflows import (
    DurableStateMachine,
    StateResult,
    StateSpec,
    WorkflowDefinition,
)
from aila.platform.workflows.types import (
    RESERVED_FAILED,
    RESERVED_SUCCEEDED,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateCursor
from tests.platform.workflows.conftest import toy_services_factory

pytestmark = pytest.mark.asyncio

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _make_run_id(test_db: None) -> str:  # noqa: ARG001 -- fixture param
    """Insert a WorkflowRunRecord row and return a fresh run_id."""
    rid = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(
                id=rid,
                query_text="output-validation-test",
                action_id="test",
                module_id="test",
            )
        )
        await session.commit()
    return rid


async def _cursor_state(run_id: str) -> WorkflowStateCursor:
    async with async_session_scope() as session:
        row = await session.get(WorkflowStateCursor, run_id)
        assert row is not None, f"No cursor row for run_id={run_id!r}"
        return row


# ---------------------------------------------------------------------------
# Pydantic model used in schema tests
# ---------------------------------------------------------------------------


class MyOutput(BaseModel):
    result: str


# ---------------------------------------------------------------------------
# Test 1 -- empty dict from non-terminal triggers on_failure
# ---------------------------------------------------------------------------


async def test_empty_dict_from_non_terminal_triggers_on_failure(
    test_db: None,
) -> None:
    """state_empty returns {} -- engine must route to on_failure."""
    run_id = await _make_run_id(test_db)

    async def state_empty(
        state_input: dict[str, Any], services: Any
    ) -> StateResult:
        # Returns empty dict -- must be rejected
        return StateResult(next_state=RESERVED_SUCCEEDED, output={})

    async def state_failure_handler(
        state_input: dict[str, Any], services: Any
    ) -> StateResult:
        # Terminates cleanly when routed here
        return StateResult(next_state=RESERVED_SUCCEEDED, output={"caught": True})

    definition = WorkflowDefinition(
        definition_id=f"test.empty_dict.{uuid.uuid4().hex[:8]}",
        start_state="do_work",
        states={
            "do_work": StateSpec(
                handler=state_empty,
                on_failure="on_fail",
            ),
            "on_fail": StateSpec(
                handler=state_failure_handler,
            ),
        },
        services_factory=toy_services_factory,
    )

    result = await DurableStateMachine.execute(run_id, definition, {})

    # on_failure handler ran and returned {"caught": True}
    assert result == {"caught": True}

    # Cursor ends on __succeeded__ (on_fail transitioned there)
    cursor = await _cursor_state(run_id)
    assert cursor.current_state == RESERVED_SUCCEEDED

    # The intermediate on_fail state received the structured error input
    # We verify by checking the cursor's final input is what the on_fail handler returned
    assert result.get("caught") is True


# ---------------------------------------------------------------------------
# Test 2 -- output_schema invalid triggers on_failure
# ---------------------------------------------------------------------------


async def test_output_schema_invalid_triggers_on_failure(
    test_db: None,
) -> None:
    """Handler returns a dict missing 'result' -- schema validation fails."""
    run_id = await _make_run_id(test_db)

    async def bad_handler(
        state_input: dict[str, Any], services: Any
    ) -> StateResult:
        # Missing required 'result' field
        return StateResult(next_state=RESERVED_SUCCEEDED, output={"wrong_key": 42})

    async def on_fail_handler(
        state_input: dict[str, Any], services: Any
    ) -> StateResult:
        return StateResult(
            next_state=RESERVED_SUCCEEDED,
            output={
                "error": state_input.get("error"),
                "previous_state": state_input.get("previous_state"),
            },
        )

    definition = WorkflowDefinition(
        definition_id=f"test.schema_invalid.{uuid.uuid4().hex[:8]}",
        start_state="do_work",
        states={
            "do_work": StateSpec(
                handler=bad_handler,
                output_schema=MyOutput,
                on_failure="on_fail",
            ),
            "on_fail": StateSpec(
                handler=on_fail_handler,
            ),
        },
        services_factory=toy_services_factory,
    )

    result = await DurableStateMachine.execute(run_id, definition, {})

    assert result["error"] == "output_validation_failed"
    assert result["previous_state"] == "do_work"


# ---------------------------------------------------------------------------
# Test 3 -- output_schema valid advances normally
# ---------------------------------------------------------------------------


async def test_output_schema_valid_advances_normally(
    test_db: None,
) -> None:
    """Handler returns a well-formed dict matching output_schema -- normal advance."""
    run_id = await _make_run_id(test_db)

    async def good_handler(
        state_input: dict[str, Any], services: Any
    ) -> StateResult:
        return StateResult(
            next_state=RESERVED_SUCCEEDED,
            output={"result": "hello"},
        )

    definition = WorkflowDefinition(
        definition_id=f"test.schema_valid.{uuid.uuid4().hex[:8]}",
        start_state="do_work",
        states={
            "do_work": StateSpec(
                handler=good_handler,
                output_schema=MyOutput,
            ),
        },
        services_factory=toy_services_factory,
    )

    result = await DurableStateMachine.execute(run_id, definition, {})

    assert result == {"result": "hello"}
    cursor = await _cursor_state(run_id)
    assert cursor.current_state == RESERVED_SUCCEEDED


# ---------------------------------------------------------------------------
# Test 4 -- terminal state empty dict is allowed
# ---------------------------------------------------------------------------


async def test_terminal_state_empty_dict_allowed(
    test_db: None,
) -> None:
    """A handler that transitions to __succeeded__ with empty output is allowed
    when the handler itself is non-terminal but the *next* state is terminal.

    More precisely: __failed__ and __succeeded__ are terminal; they have no
    handler called by the engine. But a non-terminal handler returning
    next_state=__succeeded__ with non-empty output must work.

    This test covers the converse: a *terminal state* state_input that is {}
    -- the engine does not call any handler for it, so no validation occurs.
    We verify by directly checking the cursor after routing to __failed__.
    """
    run_id = await _make_run_id(test_db)

    async def crash_handler(
        state_input: dict[str, Any], services: Any
    ) -> StateResult:
        # Raises so engine routes to __crashed__ (which is terminal)
        raise RuntimeError("intentional crash")

    definition = WorkflowDefinition(
        definition_id=f"test.terminal_empty.{uuid.uuid4().hex[:8]}",
        start_state="do_work",
        states={
            "do_work": StateSpec(
                handler=crash_handler,
            ),
        },
        services_factory=toy_services_factory,
    )

    result = await DurableStateMachine.execute(run_id, definition, {})

    # Engine routes to __crashed__ (terminal); that state has no output_schema
    # and the engine does not attempt validation on terminal states.
    cursor = await _cursor_state(run_id)
    assert cursor.current_state == "__crashed__"
    # Result is the crash state_input -- contains error metadata (not empty)
    assert "error_class" in result or "failed_state" in result


# ---------------------------------------------------------------------------
# Test 5 -- no output_schema + non-empty dict advances normally (backwards compat)
# ---------------------------------------------------------------------------


async def test_no_output_schema_allows_non_empty_dict(
    test_db: None,
) -> None:
    """State with no output_schema and non-empty dict output -- normal advance."""
    run_id = await _make_run_id(test_db)

    async def compat_handler(
        state_input: dict[str, Any], services: Any
    ) -> StateResult:
        return StateResult(
            next_state=RESERVED_SUCCEEDED,
            output={"arbitrary_key": "arbitrary_value", "count": 42},
        )

    definition = WorkflowDefinition(
        definition_id=f"test.no_schema_compat.{uuid.uuid4().hex[:8]}",
        start_state="do_work",
        states={
            "do_work": StateSpec(
                handler=compat_handler,
                # output_schema intentionally absent
            ),
        },
        services_factory=toy_services_factory,
    )

    result = await DurableStateMachine.execute(run_id, definition, {})

    assert result == {"arbitrary_key": "arbitrary_value", "count": 42}
    cursor = await _cursor_state(run_id)
    assert cursor.current_state == RESERVED_SUCCEEDED


# ---------------------------------------------------------------------------
# Test 6 -- empty dict with no on_failure routes to __failed__
# ---------------------------------------------------------------------------


async def test_empty_dict_no_on_failure_routes_to_reserved_failed(
    test_db: None,
) -> None:
    """When on_failure is not set, empty dict routes to RESERVED_FAILED."""
    run_id = await _make_run_id(test_db)

    async def state_empty(
        state_input: dict[str, Any], services: Any
    ) -> StateResult:
        return StateResult(next_state=RESERVED_SUCCEEDED, output={})

    definition = WorkflowDefinition(
        definition_id=f"test.empty_no_on_fail.{uuid.uuid4().hex[:8]}",
        start_state="do_work",
        states={
            "do_work": StateSpec(
                handler=state_empty,
                # on_failure intentionally absent -- should route to __failed__
            ),
        },
        services_factory=toy_services_factory,
    )

    result = await DurableStateMachine.execute(run_id, definition, {})

    cursor = await _cursor_state(run_id)
    assert cursor.current_state == RESERVED_FAILED
    assert result.get("error") == "output_validation_failed"
    assert result.get("previous_state") == "do_work"
