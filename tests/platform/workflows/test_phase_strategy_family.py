"""Per-phase strategy_family override (RFC-13).

A dispatch phase may override the investigation-level prompt family via
``PhaseSpec.strategy_family``. The loop writes it to the
``_directive.phase_strategy_family`` case-state observable at phase entry;
the turn runner reads that observable and selects the phase's prompt family
instead of the investigation-level one (falling back to the investigation
family when a phase sets no override). This test proves the write half --
the observable channel the turn runner reads.
"""
from __future__ import annotations

import json

from sqlmodel import select

from aila.modules.vr.contracts.branch import PersonaVoice
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.agents.turn_helpers import decode_case_state
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.investigation_loop_base import _write_phase_directive


async def _seed_branch() -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(name="sf", slug="sf", description="", theme="custom", team_id="admin")
        uow.session.add(ws)
        await uow.session.flush()
        tgt = VRTargetRecord(
            workspace_id=ws.id, team_id="admin", display_name="t", kind="native_binary",
            descriptor_json=json.dumps({"path": "/tmp/x"}),  # noqa: S108
            primary_language=None, secondary_languages_json="[]", tags_json="[]",
            mcp_handles_json="{}", status="active", capability_profile_json="{}",
        )
        uow.session.add(tgt)
        await uow.session.flush()
        inv = VRInvestigationRecord(
            target_id=tgt.id, team_id="admin", kind="discovery", title="t",
            initial_question="q", status="running", auto_pilot=False,
            strategy_family="vulnerability_research.discovery_research",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        branch = VRInvestigationBranchRecord(
            investigation_id=inv.id, status="active", turn_count=0,
            fork_reason="primary", persona_voice=PersonaVoice.NOOR.value,
        )
        uow.session.add(branch)
        await uow.session.flush()
        bid = branch.id
        await uow.session.commit()
    return bid


async def _observables(branch_id: str) -> dict:
    async with UnitOfWork() as uow:
        branch = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.id == branch_id),
        )).first()
        return dict(decode_case_state(branch.case_state_json).observables)


async def test_phase_strategy_family_written_to_observable(test_db) -> None:
    del test_db
    bid = await _seed_branch()
    await _write_phase_directive(
        VRInvestigationBranchRecord, bid, "BINARY AUDIT PHASE. Objective: x.",
        strategy_family="vulnerability_research.binary_audit",
    )
    obs = await _observables(bid)
    assert obs["_directive.phase_mission"] == "BINARY AUDIT PHASE. Objective: x."
    assert obs["_directive.phase_strategy_family"] == "vulnerability_research.binary_audit"


async def test_no_strategy_override_leaves_observable_unset(test_db) -> None:
    del test_db
    bid = await _seed_branch()
    await _write_phase_directive(
        VRInvestigationBranchRecord, bid, "RECON PHASE.", strategy_family=None,
    )
    obs = await _observables(bid)
    assert obs["_directive.phase_mission"] == "RECON PHASE."
    # No override -> the turn runner falls back to the investigation family.
    assert "_directive.phase_strategy_family" not in obs
