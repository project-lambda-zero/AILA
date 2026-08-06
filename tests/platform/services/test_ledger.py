"""Tests for the investigation ledger (RFC-13 Phase 1).

The table has no foreign keys, so tests append with plain string ids
against the shared `aila_test` schema (create_all sees the new table).
"""
from __future__ import annotations

from aila.platform.services.ledger import LedgerService


async def test_append_and_read_roundtrip(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-append"
    i1 = await svc.append_general(inv, "b1", "discovery", {"packed": True})
    i2 = await svc.append_general(inv, "b2", "note", {"text": "hi"})
    rows = await svc.read_general(inv)
    assert [r["id"] for r in rows] == [i1, i2]
    assert rows[0]["kind"] == "discovery"
    assert rows[0]["payload"] == {"packed": True}
    assert rows[0]["author_branch_id"] == "b1"


async def test_read_kind_filter(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-kind"
    await svc.append_general(inv, "b1", "discovery", {"a": 1})
    await svc.append_general(inv, "b1", "note", {"b": 2})
    disc = await svc.read_general(inv, kinds=["discovery"])
    assert len(disc) == 1
    assert disc[0]["kind"] == "discovery"


async def test_idempotent_append(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-idem"
    a = await svc.append_general(inv, "b1", "discovery", {"x": 1}, idempotency_key="k1")
    b = await svc.append_general(inv, "b1", "discovery", {"x": 1}, idempotency_key="k1")
    assert a == b  # retry is a no-op returning the same row
    c = await svc.append_general(inv, "b1", "discovery", {"x": 1}, idempotency_key="k2")
    assert c != a
    assert len(await svc.read_general(inv)) == 2


async def test_non_idempotent_appends_distinct(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-noidem"
    a = await svc.append_general(inv, "b1", "note", {})
    b = await svc.append_general(inv, "b1", "note", {})
    assert a != b
    assert len(await svc.read_general(inv)) == 2


async def test_objective_open_read_status(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-obj"
    await svc.open_objective(inv, "b1", "extract_c2", "b1")
    objs = await svc.read_objectives(inv)
    assert len(objs) == 1
    assert objs[0]["objective_key"] == "extract_c2"
    assert objs[0]["owner_branch_id"] == "b1"
    assert objs[0]["status"] == "open"
    await svc.set_objective_status(inv, "extract_c2", "b1", "met")
    objs2 = await svc.read_objectives(inv)
    assert len(objs2) == 1  # folded to the latest entry per key
    assert objs2[0]["status"] == "met"


async def test_objective_owner_transfer(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-transfer"
    await svc.open_objective(inv, "b1", "attribute", "b1")
    await svc.transfer_objective_owner(inv, "attribute", "b2")
    objs = await svc.read_objectives(inv)
    assert objs[0]["owner_branch_id"] == "b2"
    assert objs[0]["status"] == "open"  # status carried across the transfer
    await svc.transfer_objective_owner(inv, "attribute", None)
    objs2 = await svc.read_objectives(inv)
    assert objs2[0]["owner_branch_id"] is None  # orphaned to the investigation


async def test_read_objectives_owner_filter(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-objfilter"
    await svc.open_objective(inv, "b1", "o1", "b1")
    await svc.open_objective(inv, "b2", "o2", "b2")
    mine = await svc.read_objectives(inv, owner_branch_id="b1")
    assert [o["objective_key"] for o in mine] == ["o1"]


async def test_confirmed_only_filters_unbacked_discoveries(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-confirmed"
    d1 = await svc.append_general(inv, "b1", "discovery", {"packed": True})
    d2 = await svc.append_general(inv, "b2", "discovery", {"config": True})
    # Approve only d1 via a decision entry naming it.
    await svc.append_general(inv, "b3", "decision", {"approved": True, "target": d1})
    confirmed = await svc.read_general(inv, kinds=["discovery"], confirmed_only=True)
    ids = [r["id"] for r in confirmed]
    assert d1 in ids
    assert d2 not in ids
