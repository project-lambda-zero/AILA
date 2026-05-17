"""Unit tests for BranchManager.spawn_strategy + list_active_by_strategy (v0.4 GA-50).

DB-bound tests so we exercise the real FK + status guards. Standalone
fixture inserts a workspace + target + investigation + primary branch
directly (POST /vr/investigations needs the platform task queue which
isn't available in unit-test scope).
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from sqlmodel import select

from aila.modules.vr.agents.branch_manager import (
    BranchManager,
    BranchManagerError,
)
from aila.modules.vr.contracts import (
    BranchOperation,
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.uow import UnitOfWork


@pytest_asyncio.fixture
async def fixture_investigation(test_db) -> tuple[str, str]:
    """Create one investigation with a primary branch. Returns (inv_id, primary_branch_id)."""
    del test_db
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="MS test", slug="ms-test-spawn", description="",
            theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name="t",
            kind="native_binary",
            descriptor_json='{"binary_path": "/dev/null"}',
            primary_language="c",
            status="active",
            enrichment_status="unenriched",
        )
        uow.session.add(target)
        await uow.session.flush()

        inv = VRInvestigationRecord(
            target_id=target.id,
            team_id="admin",
            kind=InvestigationKind.AUDIT.value,
            title="MS test",
            initial_question="test multi-strategy spawn",
            status=InvestigationStatus.CREATED.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.audit",
            cost_budget_usd=10.0,
        )
        uow.session.add(inv)
        await uow.session.flush()

        primary = VRInvestigationBranchRecord(
            investigation_id=inv.id,
            status="active",
            fork_reason="primary",
        )
        uow.session.add(primary)
        await uow.session.commit()
        await uow.session.refresh(primary)
        return inv.id, primary.id


@pytest.mark.asyncio
async def test_spawn_strategy_creates_active_branch(
    fixture_investigation: tuple[str, str],
) -> None:
    inv_id, _primary_id = fixture_investigation
    mgr = BranchManager(investigation_id=inv_id)
    result = await mgr.spawn_strategy(
        strategy_family="vulnerability_research.variant_hunt",
        rationale="hunt variants of the same root cause in sibling functions",
    )
    assert result.op == BranchOperation.SPAWN_STRATEGY
    assert result.new_branch_id is not None
    assert result.investigation_id == inv_id

    # New branch row exists with strategy tag
    from sqlmodel import select
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == result.new_branch_id,
            ),
        )).first()
        assert row is not None
        assert row.strategy_family == "vulnerability_research.variant_hunt"
        assert row.status == "active"
        assert row.parent_branch_id is None


@pytest.mark.asyncio
async def test_spawn_strategy_with_parent_inherits_case_state(
    fixture_investigation: tuple[str, str],
) -> None:
    inv_id, primary_id = fixture_investigation
    mgr = BranchManager(investigation_id=inv_id)

    # Seed primary branch with a case_state
    async with UnitOfWork() as uow:
        primary = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == primary_id,
            ),
        )).first()
        assert primary is not None
        primary.case_state_json = '{"hypotheses":[{"id":"h1","claim":"x"}]}'
        primary.turn_count = 4
        uow.session.add(primary)
        await uow.session.commit()

    result = await mgr.spawn_strategy(
        strategy_family="vulnerability_research.patch_diff_analysis",
        parent_branch_id=primary_id,
        rationale="fork to compare patch behaviour",
    )
    assert result.new_branch_id is not None

    async with UnitOfWork() as uow:
        child = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == result.new_branch_id,
            ),
        )).first()
        assert child is not None
        assert child.parent_branch_id == primary_id
        assert "hypotheses" in (child.case_state_json or "")
        assert child.fork_at_turn == 4


@pytest.mark.asyncio
async def test_spawn_strategy_rejects_empty_strategy_family(
    fixture_investigation: tuple[str, str],
) -> None:
    inv_id, _ = fixture_investigation
    mgr = BranchManager(investigation_id=inv_id)
    with pytest.raises(BranchManagerError, match="strategy_family is required"):
        await mgr.spawn_strategy(strategy_family="")
    with pytest.raises(BranchManagerError, match="strategy_family is required"):
        await mgr.spawn_strategy(strategy_family="   ")


@pytest.mark.asyncio
async def test_spawn_strategy_rejects_non_active_parent(
    fixture_investigation: tuple[str, str],
) -> None:
    inv_id, primary_id = fixture_investigation
    mgr = BranchManager(investigation_id=inv_id)

    # Abandon primary first
    await mgr.abandon(primary_id, reason="test setup")

    with pytest.raises(BranchManagerError, match="must be ACTIVE"):
        await mgr.spawn_strategy(
            strategy_family="vr.variant_hunt",
            parent_branch_id=primary_id,
        )


@pytest.mark.asyncio
async def test_list_active_by_strategy_groups_correctly(
    fixture_investigation: tuple[str, str],
) -> None:
    inv_id, _primary_id = fixture_investigation
    mgr = BranchManager(investigation_id=inv_id)

    await mgr.spawn_strategy(strategy_family="vr.discovery_research")
    await mgr.spawn_strategy(strategy_family="vr.discovery_research")
    await mgr.spawn_strategy(strategy_family="vr.variant_hunt")

    groups = await mgr.list_active_by_strategy()
    # Primary branch has no strategy_family → empty-string key
    assert "" in groups
    assert len(groups[""]) == 1
    assert "vr.discovery_research" in groups
    assert len(groups["vr.discovery_research"]) == 2
    assert "vr.variant_hunt" in groups
    assert len(groups["vr.variant_hunt"]) == 1


@pytest.mark.asyncio
async def test_list_active_by_strategy_excludes_abandoned(
    fixture_investigation: tuple[str, str],
) -> None:
    inv_id, _primary_id = fixture_investigation
    mgr = BranchManager(investigation_id=inv_id)

    spawned = await mgr.spawn_strategy(strategy_family="vr.discovery_research")
    await mgr.abandon(spawned.new_branch_id, reason="test")

    groups = await mgr.list_active_by_strategy()
    # The abandoned branch is excluded
    assert "vr.discovery_research" not in groups or not groups["vr.discovery_research"]
