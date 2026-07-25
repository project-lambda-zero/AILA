"""VR dispatch-hub structure + confirmed-gated poc activation (RFC-13 Phase 5)."""
from __future__ import annotations

from aila.modules.vr.workflow.definitions_hub import (
    VR_HUB_PHASES,
    VR_INVESTIGATE_HUB,
)
from aila.platform.services.ledger import LedgerService
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
    inv = "inv-vr-cap"
    svc = LedgerService()
    await svc.append_general(inv, "b1", "discovery", {"surface": "parser"})
    router = make_dispatch_router(VR_HUB_PHASES)
    # A source-audit branch, recon done: the discovery routes it to source_audit.
    state = {
        "investigation_id": inv,
        "_branch_capability": "source-audit",
        "_dispatch_visited": ["recon"],
    }
    result = await router(state, None)
    assert result.next_state == "source_audit"
