"""Tests for the planner oracle -- request routing + ratified apply (RFC-13 Phase 4)."""
from __future__ import annotations

import pytest

from aila.platform.services.ledger import LedgerPermissionError, LedgerService
from aila.platform.services.oracle import Oracle


async def test_route_pending_resolves_owner_by_objective(test_db) -> None:
    del test_db
    inv = "inv-route"
    svc = LedgerService()
    await svc.open_objective(inv, "b1", "unpack_sample", "b1")
    request_id = await svc.append_general(
        inv, "b2", "request",
        {"intent": "write_objective", "target_capability": "re",
         "objective_key": "unpack_sample", "status": "met"},
    )
    pending = await Oracle().route_pending(inv)
    assert len(pending) == 1
    entry = pending[0]
    assert entry["request_id"] == request_id
    assert entry["target_capability"] == "re"
    assert entry["decider"] == "b1"  # owner of the named objective


async def test_apply_on_approval_confirms_discovery(test_db) -> None:
    del test_db
    inv = "inv-apply"
    svc = LedgerService()
    discovery = await svc.append_general(inv, "b1", "discovery", {"packed": True})
    request = await svc.append_general(
        inv, "b1", "request",
        {"intent": "activate_phase", "target_capability": "re",
         "discovery_id": discovery},
    )
    oracle = Oracle()
    await oracle.record_decision(inv, request, "b2", approve=True)
    result = await oracle.apply_decision(inv, request)
    assert result["applied"] is True
    assert result["confirmed"] == discovery
    confirmed = await svc.read_general(inv, kinds=["discovery"], confirmed_only=True)
    assert discovery in [r["id"] for r in confirmed]


async def test_no_apply_on_reject(test_db) -> None:
    del test_db
    inv = "inv-reject"
    svc = LedgerService()
    discovery = await svc.append_general(inv, "b1", "discovery", {"packed": True})
    request = await svc.append_general(
        inv, "b1", "request",
        {"intent": "activate_phase", "discovery_id": discovery},
    )
    oracle = Oracle()
    await oracle.record_decision(inv, request, "b2", approve=False)
    result = await oracle.apply_decision(inv, request)
    assert result["applied"] is False
    confirmed = await svc.read_general(inv, kinds=["discovery"], confirmed_only=True)
    assert discovery not in [r["id"] for r in confirmed]


async def test_self_approval_blocked(test_db) -> None:
    del test_db
    inv = "inv-self"
    svc = LedgerService()
    request = await svc.append_general(inv, "b1", "request", {"intent": "replan"})
    with pytest.raises(LedgerPermissionError):
        await Oracle().record_decision(inv, request, "b1", approve=True)


async def test_open_objective_intent_applies(test_db) -> None:
    del test_db
    inv = "inv-openobj"
    svc = LedgerService()
    request = await svc.append_general(
        inv, "b1", "request",
        {"intent": "open_objective", "objective_key": "extract_c2",
         "owner_branch_id": "b3"},
    )
    oracle = Oracle()
    await oracle.record_decision(inv, request, "b2", approve=True)
    result = await oracle.apply_decision(inv, request)
    assert result["applied"] is True
    owners = {
        o["objective_key"]: o["owner_branch_id"]
        for o in await svc.read_objectives(inv)
    }
    assert owners["extract_c2"] == "b3"


async def test_route_pending_excludes_ratified(test_db) -> None:
    del test_db
    inv = "inv-ratified"
    svc = LedgerService()
    discovery = await svc.append_general(inv, "b1", "discovery", {"x": 1})
    request = await svc.append_general(
        inv, "b1", "request",
        {"intent": "activate_phase", "discovery_id": discovery},
    )
    assert len(await Oracle().route_pending(inv)) == 1
    await Oracle().record_decision(inv, request, "b2", approve=True)
    assert len(await Oracle().route_pending(inv)) == 0


async def test_quorum_k_requires_distinct_approvers(test_db) -> None:
    del test_db
    inv = "inv-quorum"
    svc = LedgerService()
    request = await svc.append_general(inv, "b1", "request", {"intent": "replan"})
    oracle = Oracle()
    await oracle.record_decision(inv, request, "b2", approve=True)
    assert await oracle.is_ratified(inv, request, quorum_k=2) is False
    await oracle.record_decision(inv, request, "b3", approve=True)
    assert await oracle.is_ratified(inv, request, quorum_k=2) is True
