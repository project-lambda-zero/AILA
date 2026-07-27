"""VR dispatch-hub structure + confirmed-gated poc activation (RFC-13 Phase 5)."""
from __future__ import annotations

import uuid

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.workflow.definitions_hub import (
    VR_HUB_PHASES,
    VR_INVESTIGATE_HUB,
)
from aila.platform.services.ledger import LedgerService
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.phase_graph import DISPATCH_STATE, make_dispatch_router


def test_hub_has_dispatch_and_phase_states() -> None:
    states = VR_INVESTIGATE_HUB.states
    assert DISPATCH_STATE in states
    for name in (
        "recon", "source_audit", "variant_hunt", "binary_audit",
        "mobile_audit", "poc_development",
    ):
        assert name in states
    assert VR_INVESTIGATE_HUB.definition_id == "vr.investigate.hub"


def test_poc_phase_is_confirmed_exploit_dev() -> None:
    by_name = {p.name: p for p in VR_HUB_PHASES}
    assert by_name["poc_development"].capability == "exploit-dev"
    assert by_name["poc_development"].trust == "confirmed"
    # The audit phases are advisory (they work on raw discoveries).
    assert by_name["source_audit"].trust == "advisory"
    assert by_name["binary_audit"].trust == "advisory"


async def test_poc_activates_only_on_confirmed_finding(test_db) -> None:
    del test_db
    inv = "inv-vr-poc"
    svc = LedgerService()
    finding = await svc.append_general(inv, "b1", "discovery", {"exploitable": True})
    router = make_dispatch_router(VR_HUB_PHASES)
    # An exploit-dev branch with every earlier phase visited: an unconfirmed
    # finding must not open the poc phase.
    state = {
        "investigation_id": inv,
        "_branch_capability": "exploit-dev",
        "_dispatch_visited": [
            "recon", "source_audit", "variant_hunt", "binary_audit",
            "mobile_audit",
        ],
    }
    unreviewed = await router(state, None)
    assert unreviewed.next_state != "poc_development"
    # Quorum confirms the finding -> poc activates.
    await svc.append_general(inv, "b2", "decision", {"approved": True, "target": finding})
    confirmed = await router(state, None)
    assert confirmed.next_state == "poc_development"


async def test_capability_routes_branch_to_its_phase(test_db) -> None:
    del test_db
    inv = str(uuid.uuid4())
    # source_audit is kind-gated on source_repo, so the investigation must
    # have a real target row carrying that kind for the phase to activate.
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="cap-ws", slug=f"cap-ws-{inv[:8]}", description="",
            theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name="cap target", kind="source_repo",
            descriptor_json="{}", primary_language="python",
            secondary_languages_json="[]", tags_json="[]",
            mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.flush()
        uow.session.add(VRInvestigationRecord(
            id=inv, target_id=target.id, team_id="admin",
            kind="discovery", title="cap inv", initial_question="test",
            status="running", auto_pilot=False,
            strategy_family="vulnerability_research.discovery_research",
            cost_budget_usd=50.0,
        ))
        await uow.session.commit()
    svc = LedgerService()
    await svc.append_general(inv, "b1", "discovery", {"surface": "parser"})
    router = make_dispatch_router(VR_HUB_PHASES)
    # A source-audit branch, recon done, on a source_repo target: the
    # discovery routes it to source_audit.
    state = {
        "investigation_id": inv,
        "_branch_capability": "source-audit",
        "_dispatch_visited": ["recon"],
    }
    result = await router(state, None)
    assert result.next_state == "source_audit"
