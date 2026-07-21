"""Phase B -- atomic pause/resume + cursor SSOT.

Exercises the pause_investigation_atomic / resume_investigation_atomic
task bodies (vr/workflow/pause_resume.py) and the cursor SSOT contract
(workflow_state_cursor.current_state = '__paused__' / archived_state
round-trip). Plus a coverage test for the §233 variant_hunt_order
zombie-investigation fix in outcome_dispatcher.
"""
from __future__ import annotations

import json
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
    PauseInvestigationError,
    ResumeInvestigationError,
    pause_investigation_atomic,
    resume_investigation_atomic,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import RESERVED_PAUSED
from aila.storage.db_models import WorkflowStateCursor


async def _seed_target(slug: str) -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"pb-{slug}", slug=f"pb-{slug}",
            description="", theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name=f"pb {slug}", kind="android_apk",
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
            kind="variant_hunt", title="pb inv", initial_question="test",
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


async def _seed_cursor(run_id: str, current_state: str = "investigation_loop") -> None:
    """Seed both WorkflowRunRecord and WorkflowStateCursor.

    The cursor table has an FK on workflowrunrecord.id; without the run
    row the INSERT fails with a foreign-key violation. The run row's
    `id` matches the cursor's `run_id`.
    """
    from aila.storage.db_models import WorkflowRunRecord  # noqa: PLC0415

    async with UnitOfWork() as uow:
        run = WorkflowRunRecord(
            id=run_id,
            query_text="test investigation",
            action_id="vr.investigate",
            module_id="vr",
            status="running",
            team_id="admin",
        )
        uow.session.add(run)
        cursor = WorkflowStateCursor(
            run_id=run_id,
            current_state=current_state,
            definition_id="VR_INVESTIGATE_V1",
            state_input={},
            updated_at=utc_now(),
            version=0,
        )
        uow.session.add(cursor)
        await uow.session.commit()

# ----------------------------------------------------------------------
# pause_investigation_atomic
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_pause_flips_cursor_to_paused_with_archived_state() -> None:
    """Pause must archive the prior cursor state + write __paused__."""
    target_id = await _seed_target("pa1")
    inv_id = await _seed_inv(target_id)
    branch_id = await _seed_branch(inv_id)
    await _seed_cursor(branch_id, current_state="investigation_loop")

    summary = await pause_investigation_atomic(
        inv_id, user_id="test-operator", reason="operator",
    )

    # Cursor flipped
    async with UnitOfWork() as uow:
        cursor = (await uow.session.exec(
            select(WorkflowStateCursor)
            .where(WorkflowStateCursor.run_id == branch_id),
        )).first()
    assert cursor.current_state == RESERVED_PAUSED
    assert cursor.archived_state == "investigation_loop"
    assert summary["paused_cursors"] >= 1
    assert summary["inv_status"] == InvestigationStatus.PAUSED.value
    assert summary["noop"] is False


@pytest.mark.usefixtures("test_db")
async def test_pause_flips_investigation_status_to_paused() -> None:
    target_id = await _seed_target("pa2")
    inv_id = await _seed_inv(target_id)
    await _seed_branch(inv_id)

    await pause_investigation_atomic(inv_id, user_id="alice", reason=None)

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.id == inv_id),
        )).first()
    assert inv.status == InvestigationStatus.PAUSED.value


@pytest.mark.usefixtures("test_db")
async def test_pause_on_completed_raises() -> None:
    target_id = await _seed_target("pa3")
    inv_id = await _seed_inv(target_id, status=InvestigationStatus.COMPLETED)

    with pytest.raises(PauseInvestigationError, match="status"):
        await pause_investigation_atomic(inv_id, user_id="x", reason="operator")


@pytest.mark.usefixtures("test_db")
async def test_pause_on_missing_raises() -> None:
    with pytest.raises(PauseInvestigationError, match="not found"):
        await pause_investigation_atomic(
            "00000000-0000-0000-0000-000000000000",
            user_id="x", reason="operator",
        )


@pytest.mark.usefixtures("test_db")
async def test_pause_already_paused_is_noop() -> None:
    target_id = await _seed_target("pa4")
    inv_id = await _seed_inv(target_id, status=InvestigationStatus.PAUSED)

    summary = await pause_investigation_atomic(
        inv_id, user_id="x", reason="operator",
    )
    assert summary["noop"] is True
    assert summary["paused_cursors"] == 0


@pytest.mark.usefixtures("test_db")
async def test_pause_cursor_already_paused_skips_re_flip() -> None:
    """When a cursor is already at __paused__, the pause UPDATE skips it."""
    target_id = await _seed_target("pa5")
    inv_id = await _seed_inv(target_id)
    branch_id = await _seed_branch(inv_id)
    await _seed_cursor(branch_id, current_state=RESERVED_PAUSED)

    summary = await pause_investigation_atomic(
        inv_id, user_id="x", reason="operator",
    )

    async with UnitOfWork() as uow:
        cursor = (await uow.session.exec(
            select(WorkflowStateCursor)
            .where(WorkflowStateCursor.run_id == branch_id),
        )).first()
    # Already paused -- archived_state should NOT have been overwritten
    # (it was None on seed; the UPDATE is gated on current_state != __paused__).
    assert cursor.current_state == RESERVED_PAUSED
    assert cursor.archived_state is None
    assert summary["paused_cursors"] == 0


@pytest.mark.usefixtures("test_db")
async def test_pause_handles_unknown_reason() -> None:
    """Unknown reason strings degrade to OPERATOR per the contract enum."""
    target_id = await _seed_target("pa6")
    inv_id = await _seed_inv(target_id)
    await _seed_branch(inv_id)

    await pause_investigation_atomic(
        inv_id, user_id="x", reason="totally-fake-reason-string",
    )

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.id == inv_id),
        )).first()
    # Reason coerced to OPERATOR (the enum default) not the raw string
    assert inv.pause_reason == "operator"



@pytest.mark.usefixtures("test_db")
async def test_pause_flips_active_branches_to_paused() -> None:
    """Pause must flip every active branch's projection status to paused.

    Phase B observed bug: UI rendered investigation as paused
    but every branch chip stayed green-and-pulsing because the cursor
    SSOT was correct but ``vr_investigation_branches.status`` was never
    touched.
    """
    target_id = await _seed_target("pa_br_flip")
    inv_id = await _seed_inv(target_id)
    # Seed 3 active branches + 1 completed branch (completed must stay)
    active_ids = [await _seed_branch(inv_id) for _ in range(3)]
    async with UnitOfWork() as uow:
        finished = VRInvestigationBranchRecord(
            investigation_id=inv_id,
            status="completed",
            turn_count=10,
            fork_reason="primary",
            closed_reason="terminal_submit",
        )
        uow.session.add(finished)
        await uow.session.commit()
        await uow.session.refresh(finished)
        finished_id = finished.id

    summary = await pause_investigation_atomic(
        inv_id, user_id="op", reason="operator",
    )
    assert summary["paused_branches"] == 3

    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == inv_id),
        )).all()
    statuses = {r.id: r.status for r in rows}
    for bid in active_ids:
        assert statuses[bid] == "paused", f"branch {bid} should be paused"
    assert statuses[finished_id] == "completed", "completed branch must not flip"


@pytest.mark.usefixtures("test_db")
async def test_resume_flips_paused_branches_back_to_active() -> None:
    """Resume must reverse pause's branch-status flip.

    Symmetric with ``test_pause_flips_active_branches_to_paused`` --
    closes the operator-visible UI gap where resume left branch chips
    stuck on the paused colour.
    """
    target_id = await _seed_target("re_br_flip")
    inv_id = await _seed_inv(target_id)
    active_ids = [await _seed_branch(inv_id) for _ in range(2)]
    # Seed cursors so the resume path has something to fan out
    for bid in active_ids:
        await _seed_cursor(bid, current_state="investigation_loop")

    await pause_investigation_atomic(
        inv_id, user_id="op", reason="operator",
    )
    # All 2 branches should now be paused (verified by previous test).

    fake_queue = AsyncMock()
    fake_queue.submit = AsyncMock(return_value=None)
    summary = await resume_investigation_atomic(
        inv_id, user_id="op",
        task_queue=fake_queue,
        auth_user_id="op", auth_role="operator", auth_team_id="admin",
    )
    assert summary["resumed_branches"] == 2
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == inv_id),
        )).all()
    for r in rows:
        assert r.status == "active", f"branch {r.id} should be active again"

# ----------------------------------------------------------------------
# resume_investigation_atomic
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_resume_restores_cursor_from_archive() -> None:
    target_id = await _seed_target("re1")
    inv_id = await _seed_inv(target_id)
    branch_id = await _seed_branch(inv_id)
    await _seed_cursor(branch_id, current_state="investigation_loop")

    # Pause to populate archived_state
    await pause_investigation_atomic(inv_id, user_id="x", reason="operator")
    # Resume should restore
    mock_queue = AsyncMock()
    mock_queue.submit = AsyncMock(return_value=None)
    summary = await resume_investigation_atomic(
        inv_id, user_id="x",
        task_queue=mock_queue,
        auth_user_id="x", auth_role="operator", auth_team_id="admin",
    )

    async with UnitOfWork() as uow:
        cursor = (await uow.session.exec(
            select(WorkflowStateCursor)
            .where(WorkflowStateCursor.run_id == branch_id),
        )).first()
    assert cursor.current_state == "investigation_loop"
    assert cursor.archived_state is None
    assert summary["inv_status"] == InvestigationStatus.RUNNING.value
    assert summary["resumed_cursors"] >= 1


@pytest.mark.usefixtures("test_db")
async def test_resume_fans_out_one_task_per_paused_cursor() -> None:
    """Per §34 -- resume must submit ONE task per cursor, not just one for primary."""
    target_id = await _seed_target("re2")
    inv_id = await _seed_inv(target_id)
    branch_ids = [await _seed_branch(inv_id) for _ in range(3)]
    for bid in branch_ids:
        await _seed_cursor(bid)

    await pause_investigation_atomic(inv_id, user_id="x", reason="operator")

    mock_queue = AsyncMock()
    mock_queue.submit = AsyncMock(return_value=None)
    summary = await resume_investigation_atomic(
        inv_id, user_id="x",
        task_queue=mock_queue,
        auth_user_id="x", auth_role="operator", auth_team_id="admin",
    )

    # 3 cursors paused -> 3 tasks fan out (per §34 fix)
    assert summary["resumed_cursors"] == 3
    assert summary["submitted_tasks"] == 3
    assert mock_queue.submit.await_count == 3


@pytest.mark.usefixtures("test_db")
async def test_resume_on_running_raises() -> None:
    target_id = await _seed_target("re3")
    inv_id = await _seed_inv(target_id, status=InvestigationStatus.RUNNING)

    mock_queue = AsyncMock()
    mock_queue.submit = AsyncMock(return_value=None)
    with pytest.raises(ResumeInvestigationError, match="status"):
        await resume_investigation_atomic(
            inv_id, user_id="x", task_queue=mock_queue,
            auth_user_id="x", auth_role="operator", auth_team_id="admin",
        )


@pytest.mark.usefixtures("test_db")
async def test_resume_requires_task_queue() -> None:
    """task_queue is auth-bound and must be passed explicitly."""
    target_id = await _seed_target("re4")
    inv_id = await _seed_inv(target_id, status=InvestigationStatus.PAUSED)

    with pytest.raises(ResumeInvestigationError, match="task_queue"):
        await resume_investigation_atomic(
            inv_id, user_id="x", task_queue=None,
            auth_user_id="x", auth_role="operator", auth_team_id="admin",
        )


@pytest.mark.usefixtures("test_db")
async def test_resume_with_no_paused_cursors_returns_zero_resumed() -> None:
    """Investigation in PAUSED status but no cursors archived (legacy or
    operator-edited state). Resume should still flip inv.status to
    RUNNING but report resumed_cursors=0."""
    target_id = await _seed_target("re5")
    inv_id = await _seed_inv(target_id, status=InvestigationStatus.PAUSED)

    mock_queue = AsyncMock()
    mock_queue.submit = AsyncMock(return_value=None)
    summary = await resume_investigation_atomic(
        inv_id, user_id="x", task_queue=mock_queue,
        auth_user_id="x", auth_role="operator", auth_team_id="admin",
    )
    assert summary["resumed_cursors"] == 0
    assert summary["submitted_tasks"] == 0
    assert summary["inv_status"] == InvestigationStatus.RUNNING.value


# ----------------------------------------------------------------------
# §233 -- variant_hunt_order enqueues child investigation
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_dispatch_variant_hunt_order_enqueues_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """§233 -- standalone VARIANT_HUNT_ORDER outcome must enqueue
    run_vr_investigate for the child investigation. Prior to the fix
    the child sat at status=CREATED forever (zombie investigation).
    """
    target_id = await _seed_target("vh1")
    parent_id = await _seed_inv(target_id)

    # Mock the task queue submit so we can assert the enqueue happened
    # without actually running ARQ.
    submitted_kwargs: list[dict[str, Any]] = []

    class FakeQueue:
        async def submit(self, **kwargs: Any) -> None:
            submitted_kwargs.append(kwargs)

    def fake_default_task_queue() -> FakeQueue:
        return FakeQueue()

    # outcome_dispatcher.py does `from aila.modules.vr._task_queue import
    # default_task_queue` at module load and calls `default_task_queue()`
    # via the local binding. Patching the source module is a no-op for
    # that call site; the patch must target the imported name inside
    # outcome_dispatcher instead.
    monkeypatch.setattr(
        "aila.modules.vr.agents.outcome_dispatcher.default_task_queue",
        fake_default_task_queue,
    )

    # Construct the dispatcher and call _dispatch_variant_hunt_order
    from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher  # noqa: PLC0415

    dispatcher = OutcomeDispatcher(knowledge=None)
    payload = {
        "title": "test variant hunt",
        "question": "find variants of CVE-2025-X",
        "cost_budget_usd": 10.0,
    }
    # Create a dummy outcome row to pass
    from aila.modules.vr.db_models import VRInvestigationOutcomeRecord  # noqa: PLC0415
    # Outcome requires a branch_id (NOT NULL). Seed a placeholder branch
    # on the parent so the outcome row inserts cleanly.
    placeholder_branch_id = await _seed_branch(parent_id)
    async with UnitOfWork() as uow:
        outcome = VRInvestigationOutcomeRecord(
            investigation_id=parent_id,
            branch_id=placeholder_branch_id,
            outcome_kind="variant_hunt_order",
            confidence="strong",
            state="approved",
            payload_json=json.dumps(payload),
            evidence_refs_json="[]",
            accepted_by_operator=False,
        )
        uow.session.add(outcome)
        await uow.session.commit()
        await uow.session.refresh(outcome)
        outcome_id = outcome.id

    result = await dispatcher._dispatch_variant_hunt_order(
        outcome_id=outcome_id,
        investigation_id=parent_id,
        payload=payload,
    )

    # Child investigation row must exist
    assert result.dispatch_target.startswith("vr_investigation:")
    child_id = result.dispatch_target.split(":", 1)[1]
    async with UnitOfWork() as uow:
        child = (await uow.session.exec(
            select(VRInvestigationRecord)
            .where(VRInvestigationRecord.id == child_id),
        )).first()
    assert child is not None
    assert child.parent_investigation_id == parent_id

    # CRITICAL §233 assertion: the run_vr_investigate task must have been
    # enqueued for the child. Prior to the fix this list was empty.
    assert len(submitted_kwargs) == 1
    assert submitted_kwargs[0]["track"] == "vr"
    assert submitted_kwargs[0]["kwargs"] == {"investigation_id": child_id}
    assert submitted_kwargs[0]["group_id"] == "vr_variant_hunt_order"


pytestmark = pytest.mark.asyncio


# ----------------------------------------------------------------------
# §47 / §54 -- frontend cursor exposure via VRBranchSummary
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_branch_summary_carries_cursor_state_after_pause() -> None:
    """After pause_investigation_atomic flips cursors to __paused__,
    the _branch_summary helper exposes that via cursor_state +
    cursor_archived_state fields on VRBranchSummary so the frontend
    can distinguish 'operator paused' from 'task crashed' (both used
    to collapse to status=PAUSED).
    """
    from aila.modules.vr.api_router import _branch_summary  # noqa: PLC0415
    from aila.storage.db_models import WorkflowStateCursor  # noqa: PLC0415

    target_id = await _seed_target("cs1")
    inv_id = await _seed_inv(target_id)
    branch_id = await _seed_branch(inv_id)
    await _seed_cursor(branch_id, current_state="investigation_loop")
    await pause_investigation_atomic(inv_id, user_id="x", reason="operator")

    async with UnitOfWork() as uow:
        branch = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.id == branch_id),
        )).first()
        cursor = (await uow.session.exec(
            select(WorkflowStateCursor)
            .where(WorkflowStateCursor.run_id == branch_id),
        )).first()

    summary = _branch_summary(
        branch,
        cursor_state=cursor.current_state,
        cursor_archived_state=cursor.archived_state,
    )
    assert summary.cursor_state == "__paused__"
    assert summary.cursor_archived_state == "investigation_loop"


@pytest.mark.usefixtures("test_db")
async def test_branch_summary_carries_none_when_no_cursor() -> None:
    """Backward-compatible: a branch with no cursor yet (very short
    window between investigation_setup spawn and first cursor write)
    serializes with cursor_state=None / cursor_archived_state=None."""
    from aila.modules.vr.api_router import _branch_summary  # noqa: PLC0415

    target_id = await _seed_target("cs2")
    inv_id = await _seed_inv(target_id)
    branch_id = await _seed_branch(inv_id)

    async with UnitOfWork() as uow:
        branch = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.id == branch_id),
        )).first()

    summary = _branch_summary(branch)
    assert summary.cursor_state is None
    assert summary.cursor_archived_state is None


# ----------------------------------------------------------------------
# #44 -- investigation loop routes a mid-LLM-retry cancellation to a
# clean exit_reason instead of letting LLMCancelledError escape and
# finalise the workflow as FAILED.
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_investigation_loop_llm_cancel_is_clean_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``LLMCancelledError`` from ``run_turn`` exits with cancellation_token_set.

    The retry loop raises ``LLMCancelledError`` when a pause flips the
    run's token during a provider backoff. That exception is NOT in the
    researcher's narrow decide-block tuple, so it propagates out of
    ``run_turn`` uncaught. The investigation loop must catch it as a
    clean cancel (same exit as the turn-boundary poll) rather than
    letting it escape and mark the run FAILED.
    """
    from types import SimpleNamespace  # noqa: PLC0415
    from unittest.mock import MagicMock  # noqa: PLC0415

    from aila.modules.vr.agents import HonestVulnResearcher  # noqa: PLC0415
    from aila.modules.vr.workflow.states import (  # noqa: PLC0415
        investigation_loop as loop_mod,
    )
    from aila.platform.llm.cancellation import (  # noqa: PLC0415
        LLMCancelledError,
        clear_for_investigation,
    )

    target_id = await _seed_target("cancel1")
    inv_id = await _seed_inv(target_id)
    branch_id = await _seed_branch(inv_id)
    # Cursor keyed on branch_id in the investigation_loop state -- matches
    # the SSOT the loop's alive-check reads.
    await _seed_cursor(branch_id, current_state="investigation_loop")
    # A fresh (non-cancelled) token so the turn-boundary alive-check
    # passes; the raise comes from the patched run_turn, not the poll.
    clear_for_investigation(inv_id)

    async def _raise_cancel(_self: Any) -> Any:
        raise LLMCancelledError(f"run {inv_id} cancelled during LLM retry")

    monkeypatch.setattr(HonestVulnResearcher, "run_turn", _raise_cancel)
    # Executor is never used (run_turn raises before any tool_run), but the
    # loop builds it up front; stub the singleton getter to avoid bridge/
    # config construction in the test.
    monkeypatch.setattr(loop_mod, "_get_executor", lambda: MagicMock())

    services = SimpleNamespace(llm_client=MagicMock())
    result = await loop_mod.state_investigation_loop(
        {
            "investigation_id": inv_id,
            "branch_id": branch_id,
            "max_turns": 3,
        },
        services,
    )

    # Clean exit -- no exception escaped, routed to the same terminal
    # emit state as any other loop completion.
    assert result.next_state == "investigation_emit"
    assert result.output["exit_reason"] == "cancellation_token_set"
    # Cleanup the process-local token created by the alive-check.
    clear_for_investigation(inv_id)
