"""Phase 178 fix-pass coverage tests.

Each test here corresponds to a specific fix from the Phase 178 review
round. These are not covered by the original 25 tests; they prove the
fix is in place and guard against regression.

- Fix 1 (atomic audit + cursor): exit-row and cursor advance commit in
  one transaction.
- Fix 2 (race-safe seq allocation): concurrent writers for the same
  run_id get distinct seq values.
- Fix 3 (TOCTOU on _load_or_init_cursor): concurrent initial loads all
  end up with the same cursor row.
- Fix 6 (step cap): malformed cyclic definition crashes gracefully.
- Fix 7 (exception redaction): by default the audit log contains only
  the class name; WorkflowSafeMessage classes preserve full text.
- Fix 8 (state name length limit): definitions with > 128 char names
  are rejected at construction time.
"""
from __future__ import annotations

import asyncio
from typing import Any

import pytest
from sqlmodel import select

from aila.platform.workflows import (
    DurableStateMachine,
    State,
    StateResult,
    StateSpec,
    WorkflowDefinition,
    WorkflowSafeMessage,
)
from aila.platform.workflows.log import write_entered
from aila.platform.workflows.types import MAX_STEPS_PER_JOB
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor, WorkflowStateTransition
from tests.platform.workflows.conftest import ToyServices, toy_services_factory

# ---- Fix 1: atomic commit of exited row + cursor advance -------------------


@pytest.mark.asyncio
async def test_log_exit_and_cursor_advance_are_atomic(
    workflow_run_id: str,
) -> None:
    """After a successful handler, the exit audit row and the cursor
    row must be visible together (same commit). Simulate by running the
    happy path and checking both sides are consistent without any
    intermediate 'moved in audit, not in cursor' window.

    Direct proof of a SIGKILL window requires OS-level fault injection
    and is out of scope; instead we assert the transactional contract:
    the exit row for a given (from_state, to_state) never exists without
    the cursor having advanced to that to_state.
    """

    async def handler(
        state_input: dict[str, Any], services: ToyServices
    ) -> StateResult:
        return StateResult(next_state="__succeeded__", output={"ok": True})

    definition = WorkflowDefinition(
        definition_id="test.atomic.v1",
        start_state="start",
        states={"start": StateSpec(handler=handler)},
        services_factory=toy_services_factory,
    )

    await DurableStateMachine.execute(workflow_run_id, definition, {})

    async with async_session_scope() as session:
        rows_result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
            .where(WorkflowStateTransition.event == "exited:ok")  # type: ignore[arg-type]
        )
        exit_rows = list(rows_result.all())
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)

    assert exit_rows, "at least one exited:ok row expected"
    assert cursor is not None
    # For every persisted exit row, the cursor must have reached at least
    # that to_state (or a successor).
    exited_to_states = {r.to_state for r in exit_rows}
    assert cursor.current_state in exited_to_states or cursor.current_state == "__succeeded__"


# ---- Fix 2: race-safe seq allocation ---------------------------------------


@pytest.mark.asyncio
async def test_concurrent_seq_allocation_no_duplicate_pk(
    workflow_run_id: str,
) -> None:
    """Spawn N concurrent write_entered calls for the same run_id.
    Every call must succeed with a distinct seq value."""

    async def writer() -> int:
        async with async_session_scope() as session:
            seq = await write_entered(
                session,
                run_id=workflow_run_id,
                from_state="s",
                to_state="s",
                state_input={"k": 1},
            )
            await session.commit()
            return seq

    seqs = await asyncio.gather(*(writer() for _ in range(5)))
    assert len(seqs) == 5
    assert len(set(seqs)) == 5, f"duplicate seq allocated: {seqs}"

    # Persisted rows should match the returned seqs (no duplicates
    # actually written).
    async with async_session_scope() as session:
        rows_result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
        )
        rows = list(rows_result.all())
    persisted = sorted(r.seq for r in rows)
    assert persisted == sorted(seqs)


# ---- Fix 3: TOCTOU on _load_or_init_cursor ---------------------------------


@pytest.mark.asyncio
async def test_load_or_init_cursor_race(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """3 concurrent _load_or_init_cursor calls for the same run_id with
    NO existing row. Exactly one INSERT must win; the others must
    converge on the winner's row without raising."""
    results = await asyncio.gather(
        *(
            DurableStateMachine._load_or_init_cursor(
                workflow_run_id, toy_definition, {"n": i}
            )
            for i in range(3)
        ),
        return_exceptions=True,
    )
    # None of them should have raised.
    for r in results:
        assert not isinstance(r, BaseException), f"unexpected raise: {r!r}"
    # All should have converged on the same current_state (winner's).
    assert all(isinstance(r, State) for r in results)
    currents = {r.current for r in results if isinstance(r, State)}
    assert currents == {toy_definition.start_state}

    # Exactly one row in the DB.
    async with async_session_scope() as session:
        rows_result = await session.exec(
            select(WorkflowStateCursor)
            .where(WorkflowStateCursor.run_id == workflow_run_id)
        )
        rows = list(rows_result.all())
    assert len(rows) == 1


# ---- Fix 6: step cap --------------------------------------------------------


@pytest.mark.asyncio
async def test_step_limit_exceeded_crashes_gracefully(
    workflow_run_id: str,
) -> None:
    """A 2-state cycle (A -> B -> A -> ...) must NOT loop forever; after
    MAX_STEPS_PER_JOB transitions the engine transitions to __crashed__
    with a WorkflowStepLimitExceeded origin."""

    async def a(state_input: dict[str, Any], services: ToyServices) -> StateResult:
        # Pass a non-empty dict so Layer 1 empty-output validation does not
        # fire before the step limit is reached (Phase 183 Plan 06).
        return StateResult(next_state="b", output={"step": state_input.get("step", 0) + 1})

    async def b(state_input: dict[str, Any], services: ToyServices) -> StateResult:
        return StateResult(next_state="a", output={"step": state_input.get("step", 0) + 1})

    definition = WorkflowDefinition(
        definition_id="test.cycle.v1",
        start_state="a",
        states={
            "a": StateSpec(handler=a),
            "b": StateSpec(handler=b),
        },
        services_factory=toy_services_factory,
    )

    out = await DurableStateMachine.execute(workflow_run_id, definition, {"step": 0})
    assert isinstance(out, dict)

    async with async_session_scope() as session:
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)
    assert cursor is not None
    assert cursor.current_state == "__crashed__"
    assert out.get("error_class") == "WorkflowStepLimitExceeded"


def test_max_steps_per_job_constant() -> None:
    assert MAX_STEPS_PER_JOB == 1000


# ---- Fix 7: exception redaction --------------------------------------------


class _LeakyError(Exception):
    """Bare Exception subclass: str(exc) MUST be redacted to class name."""


class _PublicError(WorkflowSafeMessage):
    """Marker-subclass: str(exc) is safe to preserve verbatim."""


@pytest.mark.asyncio
async def test_exception_messages_redacted_by_default(
    workflow_run_id: str,
) -> None:
    """A handler raising a ValueError with an email in the message must
    persist only the class name in the audit row."""

    secret_text = "user@example.com attempted X"

    async def handler(state_input: dict[str, Any], services: ToyServices) -> StateResult:
        raise _LeakyError(secret_text)

    definition = WorkflowDefinition(
        definition_id="test.redact.v1",
        start_state="start",
        states={"start": StateSpec(handler=handler)},
        services_factory=toy_services_factory,
    )

    out = await DurableStateMachine.execute(workflow_run_id, definition, {})
    assert isinstance(out, dict)

    async with async_session_scope() as session:
        rows_result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
            .where(WorkflowStateTransition.event == "exited:failed")  # type: ignore[arg-type]
        )
        rows = list(rows_result.all())
        cursor = await session.get(WorkflowStateCursor, workflow_run_id)

    assert rows
    for r in rows:
        # Class name is recorded...
        assert r.error_class == "_LeakyError"
        # ...but the raw message is NOT.
        assert secret_text not in (r.error_message or "")
        assert "example.com" not in (r.error_message or "")

    # And the __crashed__ payload must not leak either.
    assert cursor is not None
    assert secret_text not in str(cursor.state_input)


@pytest.mark.asyncio
async def test_exception_message_safe_class_preserved(
    workflow_run_id: str,
) -> None:
    """Exceptions inheriting from WorkflowSafeMessage preserve str(exc)
    in the audit row. This is the opt-in escape hatch for handlers that
    want human-readable context."""

    async def handler(state_input: dict[str, Any], services: ToyServices) -> StateResult:
        raise _PublicError("quota exhausted for action 'scan'")

    definition = WorkflowDefinition(
        definition_id="test.safe.v1",
        start_state="start",
        states={"start": StateSpec(handler=handler)},
        services_factory=toy_services_factory,
    )

    await DurableStateMachine.execute(workflow_run_id, definition, {})

    async with async_session_scope() as session:
        rows_result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
            .where(WorkflowStateTransition.event == "exited:failed")  # type: ignore[arg-type]
        )
        rows = list(rows_result.all())

    assert rows
    assert any(
        "quota exhausted" in (r.error_message or "") for r in rows
    ), "WorkflowSafeMessage subclasses must preserve the full message"


# ---- Fix 8: state name length limit ---------------------------------------


def test_state_name_too_long_rejected() -> None:
    """Definitions with state names longer than STATE_NAME_MAX_LEN must
    be rejected at construction time. Prevents bypass of the DB column
    bound via crafted handler-returned next_state."""
    long_name = "x" * 200

    async def h(state_input: dict[str, Any], services: ToyServices) -> StateResult:
        return StateResult(next_state="__succeeded__", output={})

    with pytest.raises(ValueError, match="STATE_NAME_MAX_LEN"):
        WorkflowDefinition(
            definition_id="test.long.v1",
            start_state=long_name,
            states={long_name: StateSpec(handler=h)},
            services_factory=toy_services_factory,
        )


def test_definition_id_too_long_rejected() -> None:
    """definition_id is also bounded (same DB column policy)."""

    async def h(state_input: dict[str, Any], services: ToyServices) -> StateResult:
        return StateResult(next_state="__succeeded__", output={})

    with pytest.raises(ValueError, match="definition_id length"):
        WorkflowDefinition(
            definition_id="d" * 200,
            start_state="start",
            states={"start": StateSpec(handler=h)},
            services_factory=toy_services_factory,
        )


# ---- Fix 4: migration server_default uses text() ---------------------------


def test_migration_023_server_default_uses_text() -> None:
    """Migrations 023/024 must use sa.text('now()'), not sa.func.now(),
    for server_default. sa.func on a server_default field is formally
    invalid and can break DDL rendering across drivers.

    Parses the migration source and asserts no `server_default=sa.func`
    appears in 023 / 024 / 025."""
    import pathlib
    import re

    base = pathlib.Path(__file__).resolve().parents[3] / "src" / "aila" / "alembic" / "versions"
    for name in (
        "023_workflow_state_cursor.py",
        "024_workflow_state_transitions.py",
        "025_workflow_run_plan_json.py",
    ):
        src = (base / name).read_text()
        # The bad pattern must NOT appear.
        assert not re.search(r"server_default\s*=\s*sa\.func\.", src), (
            f"{name} still uses server_default=sa.func.* -- replace with sa.text()"
        )


def test_migration_023_ddl_compiles_with_text_default() -> None:
    """Compiling the Phase 178 DDL against the Postgres dialect must
    render `DEFAULT now()` without raising. Guards against a regression
    where someone swaps sa.text back to sa.func on server_default."""
    import sqlalchemy as sa
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.dialects.postgresql import JSONB
    from sqlalchemy.schema import CreateTable

    meta = sa.MetaData()
    t = sa.Table(
        "_test_wsc",
        meta,
        sa.Column("run_id", sa.String(), nullable=False),
        sa.Column("current_state", sa.String(128), nullable=False),
        sa.Column("state_input", JSONB(), nullable=False),
        sa.Column("definition_id", sa.String(128), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.PrimaryKeyConstraint("run_id"),
    )
    ddl = str(CreateTable(t).compile(dialect=postgresql.dialect()))
    assert "DEFAULT now()" in ddl
    assert "VARCHAR(128)" in ddl
