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
    # A recon-phase note stays a note; a non-recon note would coerce to
    # discovery (issue #02 L3), so this test uses the recon tag to
    # isolate the read filter from the coercion path.
    await svc.append_general(
        inv, "b1", "note", {"phase": "recon", "b": 2},
    )
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


async def test_default_read_stays_oldest_first(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-default-order"
    d1 = await svc.append_general(inv, "b1", "discovery", {"n": 1})
    n1 = await svc.append_general(inv, "b1", "note", {"n": 2})
    d2 = await svc.append_general(inv, "b1", "discovery", {"n": 3})
    assert [r["id"] for r in await svc.read_general(inv)] == [d1, n1, d2]
    assert [
        r["id"] for r in await svc.read_general(inv, newest_first=False)
    ] == [d1, n1, d2]
    # Default limit keeps the oldest rows, as before.
    assert [r["id"] for r in await svc.read_general(inv, limit=2)] == [d1, n1]


async def test_newest_first_limit_selects_latest_matching_kinds(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-newest-kinds"
    d1 = await svc.append_general(inv, "b1", "discovery", {"n": 1})
    await svc.append_general(inv, "b1", "note", {"n": 2})
    d2 = await svc.append_general(inv, "b1", "discovery", {"n": 3})
    await svc.append_general(inv, "b1", "note", {"n": 4})
    d3 = await svc.append_general(inv, "b1", "discovery", {"n": 5})
    newest_disc = await svc.read_general(
        inv, kinds=["discovery"], limit=2, newest_first=True,
    )
    assert [r["id"] for r in newest_disc] == [d3, d2]
    assert d1 not in [r["id"] for r in newest_disc]
    # Without a kind filter the newest rows of any kind are returned.
    decision = await svc.append_general(inv, "b2", "decision", {"approved": False})
    newest_any = await svc.read_general(inv, limit=2, newest_first=True)
    assert [r["id"] for r in newest_any] == [decision, d3]


async def test_confirmed_only_newest_first_keeps_approvals_outside_window(
    test_db,
) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-confirmed-newest"
    d1 = await svc.append_general(inv, "b1", "discovery", {"packed": True})
    await svc.append_general(inv, "b3", "decision", {"approved": True, "target": d1})
    # Filler rows push the approval outside any newest-N window of raw rows.
    await svc.append_general(inv, "b1", "note", {"n": 1})
    await svc.append_general(inv, "b1", "note", {"n": 2})
    confirmed = await svc.read_general(
        inv, kinds=["discovery"], confirmed_only=True, limit=1, newest_first=True,
    )
    assert [r["id"] for r in confirmed] == [d1]


async def test_confirmed_only_newest_first_orders_confirmed_descending(
    test_db,
) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-confirmed-desc"
    d1 = await svc.append_general(inv, "b1", "discovery", {"n": 1})
    await svc.append_general(inv, "b3", "decision", {"approved": True, "target": d1})
    d2 = await svc.append_general(inv, "b2", "discovery", {"n": 2})
    d3 = await svc.append_general(inv, "b2", "discovery", {"n": 3})
    await svc.append_general(inv, "b3", "decision", {"approved": True, "target": d2})
    confirmed = await svc.read_general(
        inv, kinds=["discovery"], confirmed_only=True, limit=2, newest_first=True,
    )
    # d3 is unconfirmed and skipped; the newest confirmed rows come first.
    assert [r["id"] for r in confirmed] == [d2, d1]
    assert d3 not in [r["id"] for r in confirmed]
