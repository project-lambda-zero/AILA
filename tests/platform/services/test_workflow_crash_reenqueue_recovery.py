"""Workflow crash -> re-enqueue recovery coverage (#62).

The audit surfaced this bridge as untested: a workflow whose durable cursor
parks on the reserved ``__crashed__`` terminal cannot be resumed by the
engine on the next dispatch, and the operator's ``/re-enqueue`` handler is
the only path back to running. Its atomicity guarantee (wipe the crashed
cursor + submit fresh) is what turns a stuck workflow into a running one,
so a regression that stopped wiping the row would silently make every
re-enqueue call a no-op.

The tests here exercise ``purge_investigation_cursors`` -- the
platform-owned crashed-cursor wipe -- and the ``taskrecord.kwargs_json``
legacy join fallback that keeps pre-migration cursors reachable. They also
sanity-check the ``only_crashed=False`` full-wipe mode (used by the operator
"reset investigation" path) so a regression in the crashed-only filter
cannot mask itself as the fuller sweep.
"""
from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text as sql_text

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.services.investigation_lifecycle import (
    purge_investigation_cursors,
    reenqueue_investigation,
)
from aila.platform.uow import UnitOfWork
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    WorkflowRunRecord,
    WorkflowStateCursor,
)


async def _make_run_record(run_id: str) -> None:
    """Insert a WorkflowRunRecord anchor for a workflow_state_cursor row."""
    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(
                id=run_id,
                query_text="crash-recovery test",
                action_id="test",
                module_id="test",
            ),
        )
        await session.commit()


async def _make_cursor(
    run_id: str,
    *,
    current_state: str,
    definition_id: str,
    investigation_id: str | None,
) -> None:
    """Insert a WorkflowStateCursor row at the requested state."""
    async with async_session_scope() as session:
        session.add(
            WorkflowStateCursor(
                run_id=run_id,
                current_state=current_state,
                state_input={},
                retries_in_state=0,
                definition_id=definition_id,
                investigation_id=investigation_id,
            ),
        )
        await session.commit()


async def _cursor_states_by_run(run_ids: list[str]) -> dict[str, str | None]:
    """Return ``{run_id: current_state | None}`` for the given run ids."""
    out: dict[str, str | None] = {rid: None for rid in run_ids}
    if not run_ids:
        return out
    async with async_session_scope() as session:
        stmt = sql_text(
            "SELECT run_id, current_state FROM workflow_state_cursor "
            "WHERE run_id = ANY(:rids)"
        ).bindparams(rids=run_ids)
        rows = (await session.exec(stmt)).all()
    for row in rows:
        out[str(row[0])] = str(row[1])
    return out


@pytest.mark.asyncio
async def test_purge_crashed_cursor_by_investigation_id(test_db) -> None:
    """A cursor parked at ``__crashed__`` with ``investigation_id`` set is
    wiped by ``purge_investigation_cursors(only_crashed=True)``.

    Reproduces the bridge the operator's ``/re-enqueue`` handler crosses to
    unblock the workflow engine: without the wipe, the next dispatch fails
    because the engine refuses to resume across a reserved-terminal cursor.
    """
    del test_db
    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    run_id = str(uuid.uuid4())
    await _make_run_record(run_id)
    await _make_cursor(
        run_id,
        current_state="__crashed__",
        definition_id="test.workflow.v1",
        investigation_id=inv_id,
    )

    async with async_session_scope() as session:
        deleted = await purge_investigation_cursors(
            session, inv_id, only_crashed=True,
        )
        await session.commit()

    assert deleted == 1
    states = await _cursor_states_by_run([run_id])
    assert states[run_id] is None


@pytest.mark.asyncio
async def test_purge_only_crashed_leaves_live_cursor_alone(test_db) -> None:
    """The ``only_crashed=True`` filter must NOT touch non-crashed cursors.

    A regression that dropped the ``current_state = '__crashed__'`` predicate
    would clear live cursors on every ``/re-enqueue`` call and destroy in-flight
    workflow progress -- the exact opposite of the recovery intent.
    """
    del test_db
    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    crashed_run = str(uuid.uuid4())
    live_run = str(uuid.uuid4())

    await _make_run_record(crashed_run)
    await _make_run_record(live_run)
    await _make_cursor(
        crashed_run,
        current_state="__crashed__",
        definition_id="test.workflow.v1",
        investigation_id=inv_id,
    )
    await _make_cursor(
        live_run,
        current_state="running",
        definition_id="test.workflow.v1",
        investigation_id=inv_id,
    )

    async with async_session_scope() as session:
        deleted = await purge_investigation_cursors(
            session, inv_id, only_crashed=True,
        )
        await session.commit()

    assert deleted == 1
    states = await _cursor_states_by_run([crashed_run, live_run])
    assert states[crashed_run] is None, "crashed cursor must be wiped"
    assert states[live_run] == "running", (
        "live cursor must survive an only_crashed sweep"
    )


@pytest.mark.asyncio
async def test_purge_falls_back_to_kwargs_json_join_for_legacy_cursors(
    test_db,
) -> None:
    """Legacy cursors without ``investigation_id`` set are found via the
    ``taskrecord.kwargs_json`` LIKE join.

    Guards the migration-window path: cursors created before the
    ``investigation_id`` column was populated depend on the join through
    ``taskrecord.kwargs_json`` for the wipe to work. Removing that fallback
    would leave every pre-migration crashed workflow un-recoverable.
    """
    del test_db
    from aila.platform.tasks.models import TaskRecord, TaskStatus

    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    run_id = str(uuid.uuid4())
    await _make_run_record(run_id)
    # Legacy cursor: investigation_id column is NULL, so purge must find it
    # via the taskrecord.kwargs_json LIKE fallback.
    await _make_cursor(
        run_id,
        current_state="__crashed__",
        definition_id="test.workflow.legacy.v1",
        investigation_id=None,
    )
    # Seed a taskrecord whose kwargs_json embeds the investigation id --
    # exactly the shape the fallback SQL matches with ``LIKE '%"<inv>"%'``.
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=run_id,
                track="test",
                fn_path="tests.fake.fn",
                fn_module="tests",
                status=TaskStatus.FAILED,
                user_id="test-user",
                group_id="operator",
                kwargs_json=json.dumps({"investigation_id": inv_id}),
                team_id=None,
            ),
        )
        await session.commit()

    async with async_session_scope() as session:
        deleted = await purge_investigation_cursors(
            session, inv_id, only_crashed=True,
        )
        await session.commit()

    assert deleted == 1, (
        f"legacy cursor must be reachable via kwargs_json join; got {deleted}"
    )
    states = await _cursor_states_by_run([run_id])
    assert states[run_id] is None


@pytest.mark.asyncio
async def test_purge_full_wipe_removes_every_cursor_for_investigation(
    test_db,
) -> None:
    """``only_crashed=False`` clears every cursor for the investigation.

    This is the operator "reset" mode. It's asserted here so a change that
    accidentally makes the ``only_crashed`` filter default to True (or the
    inverse) fails loudly.
    """
    del test_db
    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    r_crashed = str(uuid.uuid4())
    r_live = str(uuid.uuid4())

    await _make_run_record(r_crashed)
    await _make_run_record(r_live)
    await _make_cursor(
        r_crashed,
        current_state="__crashed__",
        definition_id="test.workflow.v1",
        investigation_id=inv_id,
    )
    await _make_cursor(
        r_live,
        current_state="running",
        definition_id="test.workflow.v1",
        investigation_id=inv_id,
    )

    async with async_session_scope() as session:
        deleted = await purge_investigation_cursors(
            session, inv_id, only_crashed=False,
        )
        await session.commit()

    assert deleted == 2
    states = await _cursor_states_by_run([r_crashed, r_live])
    assert states[r_crashed] is None
    assert states[r_live] is None


@pytest.mark.asyncio
async def test_purge_returns_zero_when_no_matching_investigation(test_db) -> None:
    """The recovery bridge is a no-op when there is nothing to recover.

    A regression that raised on an empty investigation would break the
    operator's ``/re-enqueue`` retry semantics (idempotent by contract).
    """
    del test_db
    inv_id = f"inv-{uuid.uuid4().hex[:8]}"
    async with async_session_scope() as session:
        deleted = await purge_investigation_cursors(
            session, inv_id, only_crashed=True,
        )
        await session.commit()
    assert deleted == 0


@pytest.mark.asyncio
async def test_reenqueue_nulls_wall_clock_origin(test_db) -> None:
    """``reenqueue_investigation`` resets ``started_at`` to NULL.

    A re-enqueued investigation had a stall gap between the old run and
    the resumed one; those dead hours are not real work time and must not
    count against the wall-clock cap. The dispatch-hub setup re-stamps
    ``started_at = now`` on the next worker pick-up, so nulling here gives
    the resumed run a fresh 6h budget instead of inheriting the stall.
    """
    del test_db
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="wallclock-reset", slug="wallclock-reset",
            description="", theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name="wallclock reset", kind="source_repo",
            descriptor_json=json.dumps({"repo_url": "https://example.invalid/x"}),
            primary_language="java", secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        target_id = target.id

    async with async_session_scope() as session:
        inv = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            kind="discovery",
            title="wall clock reset",
            initial_question="test",
            status="stalled",
            pause_reason=None,
            auto_pilot=True,
            strategy_family="vulnerability_research.discovery_research",
            cost_budget_usd=50.0,
            started_at=datetime.now(UTC) - timedelta(hours=16),
            updated_at=datetime.now(UTC),
        )
        session.add(inv)
        await session.commit()
        await session.refresh(inv)
        inv_id = inv.id

    submitted: list[str] = []

    async def _submit_one(investigation_id: str, _branch_id: str | None) -> None:
        submitted.append(investigation_id)

    summary = await reenqueue_investigation(
        inv_id,
        inv_model=VRInvestigationRecord,
        fn_path_pattern="%/run_vr%",
        submit_one=_submit_one,
    )

    assert summary["submitted"] == 1
    assert submitted == [inv_id]

    async with async_session_scope() as session:
        row = await session.get(VRInvestigationRecord, inv_id)
        assert row is not None
        assert row.status == "created"
        assert row.started_at is None, (
            "re-enqueue must null started_at so the wall-clock cap "
            "restarts from the resumed run, not the stall gap"
        )
