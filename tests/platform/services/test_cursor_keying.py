"""RFC-02 cursor keying tests.

Pins the Class-A defect: the workflow_state_cursor PK is the random ARQ
task uuid (``run_id = task_context.task_id`` at
``platform/tasks/template.py``), so the lifecycle service's pause /
resume archival path used to query cursors by
``run_id = ANY(investigation_id, branch_id...)`` which matched zero rows
in production; both operations silently no-oped.

The fix denormalises ``investigation_id`` + ``branch_id`` onto the
cursor row at engine cursor-creation time (populated from the task's
``initial_input`` kwargs). The lifecycle service queries by those
columns and keeps the ``run_id = ANY(...)`` clause as a legacy fallback
so pre-migration cursors still resume.

Every test here runs against the create_all-populated ``test_db``
fixture; no alembic migration needed for the new columns to be visible.

Live pause / resume on a running investigation is an operator smoke-gate
at merge -- this pins the unit-level behavior only.
"""
from __future__ import annotations

import json
import uuid
from typing import Any
from unittest.mock import AsyncMock

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.workflow.pause_resume import (
    pause_investigation_atomic,
    resume_investigation_atomic,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.engine import DurableStateMachine
from aila.platform.workflows.types import RESERVED_PAUSED
from aila.storage.db_models import (
    WorkflowRunRecord,
    WorkflowStateCursor,
)

pytestmark = pytest.mark.asyncio

# ----------------------------------------------------------------------
# Seed helpers
# ----------------------------------------------------------------------


async def _seed_target(slug: str) -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"ck-{slug}", slug=f"ck-{slug}",
            description="", theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name=f"ck {slug}", kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/x.apk"}),  # noqa: S108
            primary_language=None, secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


async def _seed_inv(
    target_id: str,
    status: InvestigationStatus = InvestigationStatus.RUNNING,
) -> str:
    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=target_id, team_id="admin",
            kind="variant_hunt", title="ck inv", initial_question="test",
            status=status.value, auto_pilot=False,
            strategy_family="vulnerability_research.test",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.commit()
        await uow.session.refresh(inv)
        return inv.id


async def _seed_branch(investigation_id: str) -> str:
    async with UnitOfWork() as uow:
        br = VRInvestigationBranchRecord(
            investigation_id=investigation_id,
            status="active",
            turn_count=5,
            fork_reason="primary",
        )
        uow.session.add(br)
        await uow.session.commit()
        await uow.session.refresh(br)
        return br.id


async def _seed_run_record(run_id: str) -> None:
    async with UnitOfWork() as uow:
        uow.session.add(
            WorkflowRunRecord(
                id=run_id,
                query_text="test investigation",
                action_id="vr.investigate",
                module_id="vr",
                status="running",
                team_id="admin",
            )
        )
        await uow.session.commit()


async def _seed_cursor_direct(
    run_id: str, *,
    investigation_id: str | None,
    branch_id: str | None,
    current_state: str = "investigation_loop",
) -> None:
    """Seed a cursor row with explicit join-key values.

    Passing ``investigation_id=None, branch_id=None`` produces a legacy
    row (pre-migration shape) so the fallback query path can be
    exercised.
    """
    await _seed_run_record(run_id)
    async with UnitOfWork() as uow:
        uow.session.add(
            WorkflowStateCursor(
                run_id=run_id,
                current_state=current_state,
                definition_id="VR_INVESTIGATE_V1",
                state_input={},
                updated_at=utc_now(),
                version=0,
                investigation_id=investigation_id,
                branch_id=branch_id,
            )
        )
        await uow.session.commit()


async def _read_cursor(run_id: str) -> WorkflowStateCursor:
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(WorkflowStateCursor)
            .where(WorkflowStateCursor.run_id == run_id),
        )).first()
    assert row is not None, f"cursor {run_id!r} missing"
    return row


# ----------------------------------------------------------------------
# Engine cursor creation populates join keys
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_engine_cursor_creation_populates_join_keys() -> None:
    """``_load_or_init_cursor`` writes investigation_id + branch_id
    from the task's initial_input so the lifecycle service can find
    the row by (investigation_id, branch_id).
    """
    run_id = f"arq-{uuid.uuid4().hex[:12]}"
    inv_id = f"inv-{uuid.uuid4().hex[:12]}"
    br_id = f"br-{uuid.uuid4().hex[:12]}"
    await _seed_run_record(run_id)

    definition: Any = _stub_definition()
    initial_input = {"investigation_id": inv_id, "branch_id": br_id}

    await DurableStateMachine._load_or_init_cursor(
        run_id, definition, initial_input,
    )

    row = await _read_cursor(run_id)
    assert row.investigation_id == inv_id
    assert row.branch_id == br_id
    # PK is still the ARQ task uuid; investigation_id / branch_id are
    # denormalised join keys, not the primary key.
    assert row.run_id == run_id


@pytest.mark.usefixtures("test_db")
async def test_engine_cursor_creation_leaves_join_keys_null_for_non_investigation() -> None:
    """A workflow whose initial_input carries no investigation keys leaves
    both columns NULL so the row is invisible to the lifecycle service
    (as it should be)."""
    run_id = f"arq-{uuid.uuid4().hex[:12]}"
    await _seed_run_record(run_id)
    definition: Any = _stub_definition()

    await DurableStateMachine._load_or_init_cursor(
        run_id, definition, {"query": "adhoc"},
    )

    row = await _read_cursor(run_id)
    assert row.investigation_id is None
    assert row.branch_id is None


# ----------------------------------------------------------------------
# Pause finds cursor by investigation_id (not by ARQ task uuid)
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_pause_finds_cursor_by_investigation_id_column() -> None:
    """The RFC-02 Class-A defect: cursor.run_id != branch_id / inv_id.
    With the new column populated, pause archives the cursor even
    though the ``run_id = ANY(inv_id, branch_id...)`` clause can never
    match a random ARQ uuid.
    """
    target_id = await _seed_target("p_inv_col")
    inv_id = await _seed_inv(target_id)
    br_id = await _seed_branch(inv_id)

    # Simulate production: the cursor row's PK is an unrelated ARQ
    # task uuid, not the branch id.
    arq_run_id = f"arq-{uuid.uuid4().hex[:12]}"
    assert arq_run_id != br_id and arq_run_id != inv_id
    await _seed_cursor_direct(
        arq_run_id,
        investigation_id=inv_id,
        branch_id=br_id,
        current_state="investigation_loop",
    )

    summary = await pause_investigation_atomic(
        inv_id, user_id="op", reason="operator",
    )

    row = await _read_cursor(arq_run_id)
    assert row.current_state == RESERVED_PAUSED
    assert row.archived_state == "investigation_loop"
    assert summary["paused_cursors"] == 1


@pytest.mark.usefixtures("test_db")
async def test_resume_restores_cursor_and_submits_correct_branch_id() -> None:
    """Resume must restore the archived state AND submit the ARQ task
    with ``branch_id = <branch column>``, not ``branch_id = <run_id>``.
    """
    target_id = await _seed_target("re_inv_col")
    inv_id = await _seed_inv(target_id)
    br_id = await _seed_branch(inv_id)
    arq_run_id = f"arq-{uuid.uuid4().hex[:12]}"

    # Seed cursor already at __paused__ with archived_state set (the
    # state we want restored on resume).
    await _seed_cursor_direct(
        arq_run_id,
        investigation_id=inv_id,
        branch_id=br_id,
        current_state="investigation_loop",
    )
    await pause_investigation_atomic(
        inv_id, user_id="op", reason="operator",
    )

    fake_queue = AsyncMock()
    fake_queue.submit = AsyncMock(return_value=None)
    summary = await resume_investigation_atomic(
        inv_id,
        user_id="op",
        task_queue=fake_queue,
        auth_user_id="op",
        auth_role="operator",
        auth_team_id="admin",
    )

    row = await _read_cursor(arq_run_id)
    assert row.current_state == "investigation_loop"
    assert row.archived_state is None
    assert summary["resumed_cursors"] == 1
    assert summary["submitted_tasks"] == 1

    fake_queue.submit.assert_awaited_once()
    call_kwargs = fake_queue.submit.await_args.kwargs
    # The submit MUST carry the real branch id from the join-key column,
    # not the ARQ task uuid we used as run_id.
    assert call_kwargs["kwargs"] == {
        "investigation_id": inv_id,
        "branch_id": br_id,
    }


# ----------------------------------------------------------------------
# Legacy fallback: cursor with NULL join keys keyed by branch_id run_id
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_pause_legacy_fallback_by_run_id() -> None:
    """A pre-migration cursor (NULL investigation_id / branch_id) whose
    ``run_id`` happens to equal the branch id still gets paused via
    the ``run_id = ANY(...)`` fallback. This preserves the resume path
    for investigations that ran before the join-key columns shipped.
    """
    target_id = await _seed_target("p_legacy")
    inv_id = await _seed_inv(target_id)
    br_id = await _seed_branch(inv_id)

    # Legacy shape: cursor keyed with run_id = branch id, join columns NULL.
    await _seed_cursor_direct(
        br_id,
        investigation_id=None,
        branch_id=None,
        current_state="investigation_loop",
    )

    summary = await pause_investigation_atomic(
        inv_id, user_id="op", reason="operator",
    )

    row = await _read_cursor(br_id)
    assert row.current_state == RESERVED_PAUSED
    assert row.archived_state == "investigation_loop"
    assert summary["paused_cursors"] == 1


@pytest.mark.usefixtures("test_db")
async def test_resume_legacy_fallback_by_run_id() -> None:
    """Legacy cursor round-trip: pause + resume both find the row via
    the ``run_id = ANY(...)`` clause and the fan-out submits with
    ``branch_id = run_id`` (that path is the only way pause could have
    archived the row in the first place)."""
    target_id = await _seed_target("re_legacy")
    inv_id = await _seed_inv(target_id)
    br_id = await _seed_branch(inv_id)

    await _seed_cursor_direct(
        br_id,
        investigation_id=None,
        branch_id=None,
        current_state="investigation_loop",
    )
    await pause_investigation_atomic(
        inv_id, user_id="op", reason="operator",
    )

    fake_queue = AsyncMock()
    fake_queue.submit = AsyncMock(return_value=None)
    summary = await resume_investigation_atomic(
        inv_id,
        user_id="op",
        task_queue=fake_queue,
        auth_user_id="op",
        auth_role="operator",
        auth_team_id="admin",
    )

    row = await _read_cursor(br_id)
    assert row.current_state == "investigation_loop"
    assert row.archived_state is None
    assert summary["resumed_cursors"] == 1

    call_kwargs = fake_queue.submit.await_args.kwargs
    # Legacy path: the branch id was inferred from run_id since the
    # branch_id column is NULL.
    assert call_kwargs["kwargs"] == {
        "investigation_id": inv_id,
        "branch_id": br_id,
    }


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _stub_definition() -> Any:
    """Minimal object satisfying ``_load_or_init_cursor``'s attribute
    access (``start_state``, ``definition_id``, ``allow_phase_handoff``,
    ``is_dispatcher``) without pulling a whole WorkflowDefinition."""

    class _Stub:
        start_state = "investigation_setup"
        definition_id = "VR_INVESTIGATE_V1"
        allow_phase_handoff = False
        is_dispatcher = False

    return _Stub()
