"""Contract C1: ``LedgerService.confirm_branch_discoveries`` optionally
returns ``(discovery_id, hypothesis_id)`` tuples.

The quorum -> ledger bridge (RFC-13 Phase 4) previously returned only the
list of confirmed discovery ids. Stream B needs the originating
hypothesis id per discovery to bridge the confirmation back into the
branch's case_state (belief store). The kwarg is additive: the default
call MUST still return ``list[int]`` so the platform bases inherited by
malware and forensics stay unchanged.
"""
from __future__ import annotations

from aila.platform.services.ledger import LedgerService
from aila.platform.uow import UnitOfWork


async def test_default_return_shape_stays_list_of_int(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-c1-default"
    async with UnitOfWork() as uow:
        d1 = await svc.append_general(
            inv, "b1", "discovery",
            {"hypothesis_id": "h1", "source": "taint_confirmed"},
            session=uow.session,
        )
        d2 = await svc.append_general(
            inv, "b1", "discovery",
            {"hypothesis_id": "h2", "source": "recon_hypothesis"},
            session=uow.session,
        )
        await uow.session.commit()

    result = await svc.confirm_branch_discoveries(inv, "b1")
    assert isinstance(result, list)
    for item in result:
        assert isinstance(item, int)
    assert set(result) == {d1, d2}


async def test_return_hypotheses_yields_pairs(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-c1-pairs"
    async with UnitOfWork() as uow:
        d_with_hid = await svc.append_general(
            inv, "b1", "discovery",
            {"hypothesis_id": "h_alpha", "claim": "alpha"},
            session=uow.session,
        )
        d_without_hid = await svc.append_general(
            inv, "b1", "discovery",
            {"claim": "no-hyp"},
            session=uow.session,
        )
        # A different branch's discovery must not appear in either return.
        await svc.append_general(
            inv, "b2", "discovery",
            {"hypothesis_id": "h_other"},
            session=uow.session,
        )
        await uow.session.commit()

    raw = await svc.confirm_branch_discoveries(
        inv, "b1", return_hypotheses=True,
    )
    assert isinstance(raw, list)
    pairs: list[tuple[int, str | None]] = []
    for item in raw:
        assert isinstance(item, tuple)
        assert len(item) == 2
        did, hid = item
        assert isinstance(did, int)
        assert hid is None or isinstance(hid, str)
        pairs.append((did, hid))

    lookup: dict[int, str | None] = dict(pairs)
    assert lookup[d_with_hid] == "h_alpha"
    assert lookup[d_without_hid] is None
    # Sibling branch discovery is untouched.
    assert set(lookup.keys()) == {d_with_hid, d_without_hid}


async def test_return_hypotheses_is_idempotent(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-c1-idem"
    async with UnitOfWork() as uow:
        d1 = await svc.append_general(
            inv, "b1", "discovery",
            {"hypothesis_id": "h1"}, session=uow.session,
        )
        await uow.session.commit()

    first = await svc.confirm_branch_discoveries(
        inv, "b1", return_hypotheses=True,
    )
    second = await svc.confirm_branch_discoveries(
        inv, "b1", return_hypotheses=True,
    )
    assert first == [(d1, "h1")]
    assert second == [(d1, "h1")]
    # Confirmed exactly once -- the confirm:<id> idempotency key holds.
    decisions = await svc.read_general(inv, kinds=["decision"])
    assert (
        len([r for r in decisions if (r["payload"] or {}).get("target") == d1])
        == 1
    )
