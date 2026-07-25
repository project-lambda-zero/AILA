"""Objective ownership lifecycle on the shared ledger (RFC-13 Phase 3).

Owner-only status writes, plus merge / abandon ownership transfer driven
through the real ``BranchPool`` transitions using VR record models.
"""
from __future__ import annotations

import json

import pytest

from aila.modules.vr.agents.branch_manager import BranchManager
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts.enums import BranchStatus
from aila.platform.services.ledger import LedgerPermissionError, LedgerService
from aila.platform.uow import UnitOfWork


async def _seed_two_branches() -> tuple[str, str, str]:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="ol", slug="ol", description="", theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        tgt = VRTargetRecord(
            workspace_id=ws.id, team_id="admin", display_name="t",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/x.apk"}),  # noqa: S108
            primary_language=None, secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(tgt)
        await uow.session.flush()
        inv = VRInvestigationRecord(
            target_id=tgt.id, team_id="admin", kind="variant_hunt", title="t",
            initial_question="q", status="running", auto_pilot=False,
            strategy_family="vulnerability_research.variant_hunt",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        branch_a = VRInvestigationBranchRecord(
            investigation_id=inv.id, status=BranchStatus.ACTIVE.value,
            turn_count=0, fork_reason="a", persona_voice="halvar",
            parent_branch_id=None,
        )
        branch_b = VRInvestigationBranchRecord(
            investigation_id=inv.id, status=BranchStatus.ACTIVE.value,
            turn_count=0, fork_reason="b", persona_voice="renzo",
            parent_branch_id=None,
        )
        uow.session.add(branch_a)
        uow.session.add(branch_b)
        await uow.session.commit()
        return inv.id, branch_a.id, branch_b.id


@pytest.mark.usefixtures("test_db")
async def test_owner_can_change_status_nonowner_cannot() -> None:
    svc = LedgerService()
    inv = "inv-obj-guard"
    await svc.open_objective(inv, "b1", "extract_c2", "b1")
    # The owner may change status.
    await svc.set_objective_status(inv, "extract_c2", "b1", "met")
    objs = await svc.read_objectives(inv)
    assert objs[0]["status"] == "met"
    # A non-owner is refused and must file a request instead.
    with pytest.raises(LedgerPermissionError):
        await svc.set_objective_status(inv, "extract_c2", "b2", "abandoned")


@pytest.mark.usefixtures("test_db")
async def test_merge_transfers_objectives_to_winner() -> None:
    inv, branch_a, branch_b = await _seed_two_branches()
    svc = LedgerService()
    await svc.open_objective(inv, branch_a, "obj_a", branch_a)
    await svc.open_objective(inv, branch_b, "obj_b", branch_b)
    result = await BranchManager(inv).merge(branch_a, branch_b, merge_reason="test")
    winner = result.new_branch_id
    owners = {
        o["objective_key"]: o["owner_branch_id"]
        for o in await svc.read_objectives(inv)
    }
    assert owners["obj_a"] == winner
    assert owners["obj_b"] == winner


@pytest.mark.usefixtures("test_db")
async def test_abandon_orphans_objectives() -> None:
    inv, branch_a, _branch_b = await _seed_two_branches()
    svc = LedgerService()
    await svc.open_objective(inv, branch_a, "obj_a", branch_a)
    await BranchManager(inv).abandon(branch_a, reason="test")
    owners = {
        o["objective_key"]: o["owner_branch_id"]
        for o in await svc.read_objectives(inv)
    }
    assert owners["obj_a"] is None


@pytest.mark.usefixtures("test_db")
async def test_promote_orphans_sibling_objectives_keeps_own() -> None:
    inv, branch_a, branch_b = await _seed_two_branches()
    svc = LedgerService()
    await svc.open_objective(inv, branch_a, "obj_a", branch_a)
    await svc.open_objective(inv, branch_b, "obj_b", branch_b)
    await BranchManager(inv).promote(branch_a, reason="best")
    owners = {
        o["objective_key"]: o["owner_branch_id"]
        for o in await svc.read_objectives(inv)
    }
    assert owners["obj_a"] == branch_a  # promoted branch keeps its objective
    assert owners["obj_b"] is None  # abandoned sibling orphans its objective
