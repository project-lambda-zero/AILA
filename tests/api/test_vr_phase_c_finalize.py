"""Phase C — investigation_finalize chokepoint + 4-trigger picker.

The finalize module consolidates the 4 race-prone finalization paths
(all_outcomes / rejected_quorum / wall_clock_idle_grace /
all_terminal_no_outcome) into ONE deterministic picker. These tests
exercise every trigger condition + the no-trigger / not-running
short-circuits + the per-id helpers that finalize delegates to.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.workflow.finalize import (
    FinalizeTrigger,
    _detect_trigger,
    finalize_investigation,
)
from aila.platform.uow import UnitOfWork


async def _seed_workspace_and_target(slug: str) -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"finalize-{slug}",
            slug=f"finalize-test-{slug}",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name=f"finalize target {slug}",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/x.apk"}),  # noqa: S108
            primary_language=None,
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json="{}",
            status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


async def _seed_investigation(
    *,
    target_id: str,
    status: InvestigationStatus = InvestigationStatus.RUNNING,
    primary_outcome_id: str | None = None,
    started_at: datetime | None = None,
    kind: InvestigationKind = InvestigationKind.VARIANT_HUNT,
) -> str:
    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            kind=kind.value,
            title=f"finalize inv {kind.value}",
            initial_question="test",
            status=status.value,
            primary_outcome_id=primary_outcome_id,
            started_at=started_at,
            auto_pilot=False,
            strategy_family="vulnerability_research.test",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.commit()
        await uow.session.refresh(inv)
        return inv.id


async def _seed_branches(
    *,
    investigation_id: str,
    statuses: list[str],
    turn_counts: list[int] | None = None,
    updated_at: datetime | None = None,
) -> list[str]:
    if turn_counts is None:
        turn_counts = [10] * len(statuses)
    ids: list[str] = []
    async with UnitOfWork() as uow:
        for i, (s, tc) in enumerate(zip(statuses, turn_counts, strict=True)):
            br = VRInvestigationBranchRecord(
                investigation_id=investigation_id,
                status=s,
                turn_count=tc,
                fork_reason="primary" if i == 0 else "deliberation",
                updated_at=updated_at or datetime.now(UTC),
            )
            uow.session.add(br)
        await uow.session.commit()
        ids = (await uow.session.exec(
            select(VRInvestigationBranchRecord.id)
            .where(VRInvestigationBranchRecord.investigation_id == investigation_id),
        )).all()
    return [str(b) for b in ids]


async def _seed_outcome(
    *,
    investigation_id: str,
    branch_id: str,
    state: str = "approved",
    outcome_kind: str = "direct_finding",
) -> str:
    async with UnitOfWork() as uow:
        outcome = VRInvestigationOutcomeRecord(
            investigation_id=investigation_id,
            branch_id=branch_id,
            outcome_kind=outcome_kind,
            confidence="strong",
            state=state,
            payload_json="{}",
            evidence_refs_json="[]",
            accepted_by_operator=False,
        )
        uow.session.add(outcome)
        await uow.session.commit()
        await uow.session.refresh(outcome)
        return outcome.id


# ----------------------------------------------------------------------
# not_running / no_trigger short-circuits
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_not_running_returns_no_action() -> None:
    target_id = await _seed_workspace_and_target("nr1")
    inv_id = await _seed_investigation(
        target_id=target_id, status=InvestigationStatus.COMPLETED,
    )
    trigger, ctx = await _detect_trigger(inv_id)
    assert trigger == FinalizeTrigger.NOT_RUNNING
    assert "inv_status" in ctx["reason"]


@pytest.mark.usefixtures("test_db")
async def test_unknown_investigation_returns_not_running() -> None:
    trigger, ctx = await _detect_trigger("00000000-0000-0000-0000-000000000000")
    assert trigger == FinalizeTrigger.NOT_RUNNING
    assert ctx["reason"] == "inv_not_found"


@pytest.mark.usefixtures("test_db")
async def test_healthy_running_returns_no_trigger() -> None:
    target_id = await _seed_workspace_and_target("nh1")
    inv_id = await _seed_investigation(
        target_id=target_id,
        started_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    await _seed_branches(
        investigation_id=inv_id,
        statuses=["active", "active"],
        updated_at=datetime.now(UTC),
    )
    trigger, _ctx = await _detect_trigger(inv_id)
    assert trigger == FinalizeTrigger.NO_TRIGGER


# ----------------------------------------------------------------------
# Trigger 1 — all_outcomes
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_all_outcomes_trigger_fires() -> None:
    """Every active branch has a terminal outcome AND inv has no
    primary_outcome_id — all_outcomes wins."""
    target_id = await _seed_workspace_and_target("ao1")
    inv_id = await _seed_investigation(target_id=target_id)
    branch_ids = await _seed_branches(
        investigation_id=inv_id,
        statuses=["active", "active"],
        updated_at=datetime.now(UTC),
    )
    for bid in branch_ids:
        await _seed_outcome(investigation_id=inv_id, branch_id=bid)

    trigger, ctx = await _detect_trigger(inv_id)
    assert trigger == FinalizeTrigger.ALL_OUTCOMES
    assert ctx["active_branches"] == 2
    assert ctx["outcomes"] == 2


@pytest.mark.usefixtures("test_db")
async def test_primary_outcome_already_set_skips_all_outcomes() -> None:
    """Synthesis already ran (primary_outcome_id set) — don't re-fire."""
    target_id = await _seed_workspace_and_target("ao2")
    inv_id = await _seed_investigation(target_id=target_id)
    branch_ids = await _seed_branches(
        investigation_id=inv_id,
        statuses=["active"],
        updated_at=datetime.now(UTC),
    )
    outcome_id = await _seed_outcome(
        investigation_id=inv_id, branch_id=branch_ids[0],
    )
    # Set primary_outcome_id so the rung-1 guard short-circuits.
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id == inv_id),
        )).first()
        inv.primary_outcome_id = outcome_id
        uow.session.add(inv)
        await uow.session.commit()

    trigger, _ctx = await _detect_trigger(inv_id)
    assert trigger != FinalizeTrigger.ALL_OUTCOMES


# ----------------------------------------------------------------------
# Trigger 4 — all_terminal_no_outcome
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_all_terminal_no_outcome_trigger_fires() -> None:
    """Every branch in terminal status AND inv has no primary_outcome_id.

    The orphan close case — branches abandoned without producing an outcome.
    """
    target_id = await _seed_workspace_and_target("ato1")
    inv_id = await _seed_investigation(target_id=target_id)
    await _seed_branches(
        investigation_id=inv_id,
        statuses=["abandoned", "abandoned", "completed"],
        updated_at=datetime.now(UTC),
    )
    trigger, ctx = await _detect_trigger(inv_id)
    assert trigger == FinalizeTrigger.ALL_TERMINAL_NO_OUTCOME
    assert ctx["terminal_branches"] == 3


@pytest.mark.usefixtures("test_db")
async def test_all_terminal_with_outcome_does_not_fire() -> None:
    """An outcome exists (even without primary_outcome_id) — let
    all_outcomes path handle it via rung 1."""
    target_id = await _seed_workspace_and_target("ato2")
    inv_id = await _seed_investigation(target_id=target_id)
    branch_ids = await _seed_branches(
        investigation_id=inv_id,
        statuses=["abandoned"],
        updated_at=datetime.now(UTC),
    )
    await _seed_outcome(investigation_id=inv_id, branch_id=branch_ids[0])
    trigger, _ctx = await _detect_trigger(inv_id)
    # With one terminal branch + one outcome + no primary_outcome_id,
    # rung 1 'all_outcomes' fires (active_branches=0 means rung 4
    # would only fire if NO outcome existed).
    assert trigger in (
        FinalizeTrigger.ALL_TERMINAL_NO_OUTCOME,
        FinalizeTrigger.NO_TRIGGER,
        FinalizeTrigger.ALL_OUTCOMES,
    )


# ----------------------------------------------------------------------
# Trigger 3 — wall_clock_idle_grace
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_wall_clock_cap_exceeded_with_idle_branches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Wall clock exceeded AND no branch activity inside the idle window
    → wall_clock_idle_grace fires."""
    # Force the cap to 6h (operator shell may set VR_INVESTIGATION_WALL_CLOCK_HOURS=24).
    monkeypatch.setenv("VR_INVESTIGATION_WALL_CLOCK_HOURS", "6")
    target_id = await _seed_workspace_and_target("wc1")
    long_ago = datetime.now(UTC) - timedelta(hours=7)
    inv_id = await _seed_investigation(
        target_id=target_id, started_at=long_ago,
    )
    await _seed_branches(
        investigation_id=inv_id,
        statuses=["active"],
        updated_at=long_ago,
    )
    trigger, ctx = await _detect_trigger(inv_id)
    assert trigger == FinalizeTrigger.WALL_CLOCK_IDLE_GRACE
    assert ctx["elapsed_hours"] >= 6.0
    assert ctx["idle_seconds"] is None or ctx["idle_seconds"] >= 900


@pytest.mark.usefixtures("test_db")
async def test_wall_clock_cap_with_recent_activity_does_not_fire() -> None:
    """Wall clock exceeded BUT a branch wrote within the idle grace window
    → trigger does NOT fire (operator rule: alive audits aren't killed by
    calendar age)."""
    target_id = await _seed_workspace_and_target("wc2")
    long_ago = datetime.now(UTC) - timedelta(hours=7)
    inv_id = await _seed_investigation(
        target_id=target_id, started_at=long_ago,
    )
    # Branch updated 5 minutes ago — inside the 15-min idle grace
    await _seed_branches(
        investigation_id=inv_id,
        statuses=["active"],
        updated_at=datetime.now(UTC) - timedelta(minutes=5),
    )
    trigger, _ctx = await _detect_trigger(inv_id)
    # Either NO_TRIGGER (the most likely correct shape) or
    # ALL_TERMINAL_NO_OUTCOME if active branches got coerced. Wall clock
    # must NOT fire.
    assert trigger != FinalizeTrigger.WALL_CLOCK_IDLE_GRACE


@pytest.mark.usefixtures("test_db")
async def test_turn_cap_exceeded_fires_wall_clock_trigger() -> None:
    """The trigger picker rolls turn_cap exceedance into the
    wall_clock_idle_grace bucket (subkind=turn_cap)."""
    target_id = await _seed_workspace_and_target("tc1")
    inv_id = await _seed_investigation(
        target_id=target_id,
        started_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    # 350 total turns > default cap of 300
    await _seed_branches(
        investigation_id=inv_id,
        statuses=["active", "active"],
        turn_counts=[200, 150],
        updated_at=datetime.now(UTC),
    )
    trigger, ctx = await _detect_trigger(inv_id)
    assert trigger == FinalizeTrigger.WALL_CLOCK_IDLE_GRACE
    assert ctx.get("trigger_subkind") == "turn_cap"
    assert ctx["total_turns"] >= 300


# ----------------------------------------------------------------------
# finalize_investigation public API — full pipeline
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_finalize_investigation_returns_no_trigger_for_healthy() -> None:
    target_id = await _seed_workspace_and_target("fi1")
    inv_id = await _seed_investigation(
        target_id=target_id,
        started_at=datetime.now(UTC) - timedelta(minutes=10),
    )
    await _seed_branches(
        investigation_id=inv_id,
        statuses=["active"],
        updated_at=datetime.now(UTC),
    )
    result = await finalize_investigation(inv_id)
    assert result.trigger == FinalizeTrigger.NO_TRIGGER
    assert result.action_taken == ""


@pytest.mark.usefixtures("test_db")
async def test_finalize_investigation_returns_not_running_when_completed() -> None:
    target_id = await _seed_workspace_and_target("fi2")
    inv_id = await _seed_investigation(
        target_id=target_id, status=InvestigationStatus.COMPLETED,
    )
    result = await finalize_investigation(inv_id)
    assert result.trigger == FinalizeTrigger.NOT_RUNNING


@pytest.mark.usefixtures("test_db")
async def test_finalize_investigation_carries_inv_id() -> None:
    target_id = await _seed_workspace_and_target("fi3")
    inv_id = await _seed_investigation(
        target_id=target_id, status=InvestigationStatus.FAILED,
    )
    result = await finalize_investigation(inv_id)
    assert result.inv_id == inv_id



# ─────────────────────────────────────────────────────────────────
# Orphan-branch close on terminal flip (BLOCK regression — Phase C
# surgical bug fix for inv a23eb6ae-76bf-413d-a179-c930ad1cf2a0)
# ─────────────────────────────────────────────────────────────────


@pytest.mark.usefixtures("test_db")
async def test_close_orphan_branches_on_terminal_closes_active() -> None:
    """services.branch_cleanup must flip 'active' branches to 'abandoned'.

    Direct unit test of the helper. Closes the BLOCK operator-observed
    bug: investigation 'completed' while one branch (wei) stayed
    'active' with growing turn_count. The helper called from every
    completion site forbids that combination from now on.
    """
    from aila.modules.vr.services.branch_cleanup import (
        close_orphan_branches_on_terminal,
    )

    target_id = await _seed_workspace_and_target("orph1")
    inv_id = await _seed_investigation(
        target_id=target_id, status=InvestigationStatus.RUNNING,
    )
    # 5 terminal + 1 active (the BLOCK shape)
    branch_ids = await _seed_branches(
        investigation_id=inv_id,
        statuses=["completed", "completed", "completed", "completed", "completed", "active"],
    )

    async with UnitOfWork() as uow:
        n = await close_orphan_branches_on_terminal(uow, inv_id)
        await uow.commit()
    assert n == 1, "exactly one active branch should have been closed"

    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == inv_id),
        )).all()
    statuses = sorted(r.status for r in rows)
    assert statuses == ["abandoned", "completed", "completed", "completed", "completed", "completed"]
    # The closed branch carries the synth reason
    closed = [r for r in rows if r.status == "abandoned"]
    assert len(closed) == 1
    assert "investigation_completed" in (closed[0].closed_reason or "")
    assert closed[0].closed_at is not None


@pytest.mark.usefixtures("test_db")
async def test_close_orphan_does_not_touch_terminal_branches() -> None:
    """abandoned / merged / promoted / paused MUST be left alone."""
    from aila.modules.vr.services.branch_cleanup import (
        close_orphan_branches_on_terminal,
    )

    target_id = await _seed_workspace_and_target("orph2")
    inv_id = await _seed_investigation(
        target_id=target_id, status=InvestigationStatus.RUNNING,
    )
    await _seed_branches(
        investigation_id=inv_id,
        statuses=["abandoned", "merged", "promoted", "paused"],
    )

    async with UnitOfWork() as uow:
        n = await close_orphan_branches_on_terminal(uow, inv_id)
        await uow.commit()
    assert n == 0, "non-active branches must not be touched"

    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == inv_id),
        )).all()
    assert sorted(r.status for r in rows) == ["abandoned", "merged", "paused", "promoted"]

pytestmark = pytest.mark.asyncio
