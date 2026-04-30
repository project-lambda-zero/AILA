"""Audit-log shape and hash-stability assertions (D-25).

Audit replay and operator debugging rely on two invariants:
  - ``compute_hash`` is stable across dict key order so a re-executed
    handler produces the same output hash for equal content.
  - ``seq`` values are monotonically increasing per run_id; each
    ``entered`` row is paired with an ``exited:*`` row of the same
    (from_state, to_state) for the success case.

These tests are the audit-log contract; regressions here break Phase 181's
admin UI and any future replay harness.
"""
from __future__ import annotations

import pytest
from sqlmodel import select

from aila.platform.workflows import DurableStateMachine, WorkflowDefinition
from aila.platform.workflows.log import compute_hash
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateTransition

# ---- Unit: compute_hash ----------------------------------------------------


def test_compute_hash_stable_across_key_order() -> None:
    a = compute_hash({"a": 1, "b": 2})
    b = compute_hash({"b": 2, "a": 1})
    assert a == b
    assert a is not None
    assert len(a) == 16


def test_compute_hash_returns_none_for_none() -> None:
    assert compute_hash(None) is None


def test_compute_hash_differs_for_different_content() -> None:
    a = compute_hash({"n": 1})
    b = compute_hash({"n": 2})
    assert a != b


# ---- Integration: audit rows produced by the engine -----------------------


@pytest.mark.asyncio
async def test_happy_path_emits_paired_entered_exited(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """A 3-state flow produces exactly 4 audit rows.

    start(entered), start->work(exited:ok), work(entered),
    work->__succeeded__(exited:ok).
    """
    await DurableStateMachine.execute(workflow_run_id, toy_definition, {"n": 0})
    async with async_session_scope() as session:
        result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
            .order_by(WorkflowStateTransition.seq.asc())  # type: ignore[union-attr]
        )
        rows = list(result.all())

    assert len(rows) == 4, [
        (r.seq, r.event, r.from_state, r.to_state) for r in rows
    ]

    # Row 0: entered `start` (initial entry -- previous_state is None, so
    # from_state falls back to state.current; to_state==current).
    assert rows[0].event == "entered"
    assert rows[0].from_state == "start"
    assert rows[0].to_state == "start"
    # Row 1: exited:ok start -> work.
    assert rows[1].event == "exited:ok"
    assert rows[1].from_state == "start"
    assert rows[1].to_state == "work"
    # Row 2: entered `work` (Phase 178 fix 11: from_state carries the
    # PREVIOUS state so cross-state transitions show real arrows in the
    # audit trail).
    assert rows[2].event == "entered"
    assert rows[2].from_state == "start"
    assert rows[2].to_state == "work"
    # Row 3: exited:ok work -> __succeeded__.
    assert rows[3].event == "exited:ok"
    assert rows[3].from_state == "work"
    assert rows[3].to_state == "__succeeded__"

    # seq is monotonic.
    seqs = [r.seq for r in rows]
    assert seqs == sorted(seqs)
    assert len(set(seqs)) == len(seqs), "seq values must be unique per run"


@pytest.mark.asyncio
async def test_duration_ms_non_negative(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    await DurableStateMachine.execute(workflow_run_id, toy_definition, {"n": 0})
    async with async_session_scope() as session:
        result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
            .where(WorkflowStateTransition.event.like("exited:%"))  # type: ignore[union-attr]
        )
        exited_rows = list(result.all())
    assert exited_rows
    for row in exited_rows:
        assert row.duration_ms is not None
        assert row.duration_ms >= 0, f"seq={row.seq} duration_ms={row.duration_ms}"


@pytest.mark.asyncio
async def test_input_output_hashes_match_payloads(
    workflow_run_id: str, toy_definition: WorkflowDefinition
) -> None:
    """`exited:ok` for `start` carries output_hash of {"n":1}; the
    subsequent `entered` for `work` carries input_hash of the same
    payload (engine passes the same dict through)."""
    await DurableStateMachine.execute(workflow_run_id, toy_definition, {"n": 0})
    async with async_session_scope() as session:
        result = await session.exec(
            select(WorkflowStateTransition)
            .where(WorkflowStateTransition.run_id == workflow_run_id)
            .order_by(WorkflowStateTransition.seq.asc())  # type: ignore[union-attr]
        )
        rows = list(result.all())

    start_exited = next(
        r for r in rows if r.event == "exited:ok" and r.from_state == "start"
    )
    # Phase 178 fix 11: entered.from_state now carries the previous state,
    # so work's entered row has from_state="start" (not "work").
    work_entered = next(
        r for r in rows if r.event == "entered" and r.to_state == "work"
    )

    expected = compute_hash({"n": 1})
    assert start_exited.output_hash == expected
    assert work_entered.input_hash == expected
