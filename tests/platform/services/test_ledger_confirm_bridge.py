"""Quorum -> ledger confirmation bridge (RFC-13 Phase 4).

`LedgerService.confirm_branch_discoveries` is the bridge from the
outcome-review quorum to the ledger oracle: on a quorum-approved finding,
the proposing branch's discoveries are confirmed by writing decision
entries, so confirmed-trust phase conditions (poc_development) and the
`confirmed_only` ledger read finally see confirmed discoveries. Before this
bridge, nothing wrote `kind='decision'` rows, so no discovery was ever
confirmed and the confirmed-trust tier was inert.
"""
from __future__ import annotations

from aila.platform.services.ledger import LedgerService, make_discovery_condition
from aila.platform.uow import UnitOfWork


async def test_confirm_branch_discoveries_scopes_to_that_branch(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-confirm-bridge"
    async with UnitOfWork() as uow:
        d1 = await svc.append_general(inv, "b1", "discovery", {"n": 1}, session=uow.session)
        d2 = await svc.append_general(inv, "b1", "discovery", {"n": 2}, session=uow.session)
        d3 = await svc.append_general(inv, "b2", "discovery", {"n": 3}, session=uow.session)
        await uow.session.commit()

    # Nothing confirmed yet.
    pre = await svc.read_general(inv, kinds=["discovery"], confirmed_only=True)
    assert pre == []

    confirmed = await svc.confirm_branch_discoveries(inv, "b1")
    assert set(confirmed) == {d1, d2}

    post = await svc.read_general(inv, kinds=["discovery"], confirmed_only=True)
    post_ids = {r["id"] for r in post}
    assert post_ids == {d1, d2}  # b2's discovery d3 stays unconfirmed
    assert d3 not in post_ids


async def test_confirm_branch_discoveries_is_idempotent(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-confirm-idem"
    async with UnitOfWork() as uow:
        d1 = await svc.append_general(inv, "b1", "discovery", {"n": 1}, session=uow.session)
        await uow.session.commit()
    first = await svc.confirm_branch_discoveries(inv, "b1")
    second = await svc.confirm_branch_discoveries(inv, "b1")
    assert first == [d1]
    assert second == [d1]
    # Exactly one confirmed discovery, no duplicate decision inflation.
    confirmed = await svc.read_general(inv, kinds=["discovery"], confirmed_only=True)
    assert {r["id"] for r in confirmed} == {d1}
    decisions = await svc.read_general(inv, kinds=["decision"])
    assert len([r for r in decisions if (r["payload"] or {}).get("target") == d1]) == 1


async def test_confirmed_trust_condition_fires_after_bridge(test_db) -> None:
    del test_db
    # The poc_development gate: make_discovery_condition with confirmed trust.
    svc = LedgerService()
    inv = "inv-confirm-cond"
    async with UnitOfWork() as uow:
        await svc.append_general(inv, "b1", "discovery", {"n": 1}, session=uow.session)
        await uow.session.commit()
    condition = make_discovery_condition("discovery")

    # Before confirmation: a confirmed-trust phase cannot activate.
    ok_before, _ = await condition(
        {"investigation_id": inv, "_dispatch_phase_trust": "confirmed"},
    )
    assert ok_before is False

    await svc.confirm_branch_discoveries(inv, "b1")

    # After confirmation: it fires.
    ok_after, reason = await condition(
        {"investigation_id": inv, "_dispatch_phase_trust": "confirmed"},
    )
    assert ok_after is True
    assert "discovery" in reason.lower()
