"""Platform branch pool (RFC-03 Phase 3).

Exercises the extracted BranchPool through VR record models: the fork cap
(including the new SELECT ... FOR UPDATE serialization the RFC adds so
concurrent forks cannot both pass the cap), and the promote / pause /
resume transitions.
"""
from __future__ import annotations

import asyncio
import json

import pytest
from sqlmodel import select

from aila.modules.vr.agents.branch_manager import BranchManager, BranchManagerError
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.agents.branch_pool import BranchPool
from aila.platform.contracts.enums import BranchOperation, BranchStatus
from aila.platform.uow import UnitOfWork


async def _seed() -> tuple[str, str]:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(name="bp", slug="bp", description="",
                               theme="custom", team_id="admin")
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
        br = VRInvestigationBranchRecord(
            investigation_id=inv.id, status=BranchStatus.ACTIVE.value,
            turn_count=0, fork_reason="primary", persona_voice="halvar",
            parent_branch_id=None,
        )
        uow.session.add(br)
        await uow.session.commit()
        return inv.id, br.id


async def _active_count(inv_id: str) -> int:
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.investigation_id == inv_id,
                VRInvestigationBranchRecord.status == BranchStatus.ACTIVE.value,
            ),
        )).all()
    return len(rows)


async def _cap(n: int):
    async def _reader(self: BranchPool) -> int:
        return n
    return _reader


@pytest.mark.usefixtures("test_db")
async def test_fork_under_cap_succeeds(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(BranchPool, "_max_branches", await _cap(24))
    inv_id, primary = await _seed()
    res = await BranchManager(inv_id).fork(
        primary, persona_voice="renzo", fork_reason="test-fork",
    )
    assert res.op == BranchOperation.FORK
    assert res.new_branch_id is not None
    assert res.affected_branch_ids == [primary]
    assert await _active_count(inv_id) == 2


@pytest.mark.usefixtures("test_db")
async def test_fork_at_cap_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _cap_one(self: BranchPool) -> int:
        return 1

    monkeypatch.setattr(BranchPool, "_max_branches", _cap_one)
    inv_id, primary = await _seed()  # 1 active branch already == cap
    with pytest.raises(BranchManagerError, match="cap exceeded"):
        await BranchManager(inv_id).fork(primary, persona_voice="renzo")
    assert await _active_count(inv_id) == 1


@pytest.mark.usefixtures("test_db")
async def test_concurrent_forks_respect_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _cap_two(self: BranchPool) -> int:
        return 2

    monkeypatch.setattr(BranchPool, "_max_branches", _cap_two)
    inv_id, primary = await _seed()  # 1 active, cap 2 -> one more fork fits

    mgr = BranchManager(inv_id)
    results = await asyncio.gather(
        mgr.fork(primary, persona_voice="a"),
        mgr.fork(primary, persona_voice="b"),
        return_exceptions=True,
    )
    ok = [r for r in results if not isinstance(r, Exception)]
    errs = [r for r in results if isinstance(r, BranchManagerError)]
    # The FOR UPDATE lock serializes the two forks: exactly one fits under
    # the cap of 2 (1 existing + 1 new); the other observes the cap and
    # raises. The active count never exceeds the cap.
    assert len(ok) == 1
    assert len(errs) == 1
    assert await _active_count(inv_id) == 2


@pytest.mark.usefixtures("test_db")
async def test_promote_abandons_active_siblings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(BranchPool, "_max_branches", await _cap(24))
    inv_id, primary = await _seed()
    mgr = BranchManager(inv_id)
    fork_res = await mgr.fork(primary, persona_voice="renzo")
    sibling = fork_res.new_branch_id
    assert sibling is not None

    await mgr.promote(sibling, reason="winner")

    async with UnitOfWork() as uow:
        rows = {
            b.id: b.status
            for b in (await uow.session.exec(
                select(VRInvestigationBranchRecord).where(
                    VRInvestigationBranchRecord.investigation_id == inv_id,
                ),
            )).all()
        }
    assert rows[primary] == BranchStatus.ABANDONED.value
    assert rows[sibling] == BranchStatus.PROMOTED.value


@pytest.mark.usefixtures("test_db")
async def test_pause_then_resume_round_trip() -> None:
    inv_id, primary = await _seed()
    mgr = BranchManager(inv_id)

    pause_res = await mgr.pause(primary, reason="operator")
    assert pause_res.op == BranchOperation.PAUSE
    async with UnitOfWork() as uow:
        b = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == primary,
            ),
        )).first()
    assert b.status == BranchStatus.PAUSED.value

    resume_res = await mgr.resume(primary, reason="operator")
    assert resume_res.op == BranchOperation.RESUME
    assert await _active_count(inv_id) == 1
