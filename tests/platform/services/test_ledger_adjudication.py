"""Adjudication ledger kind tests.

Covers the ledger-owned document fix for issue #07 (ledger economics,
RFC #253/#266):

* :meth:`LedgerService.append_adjudication` writes a first-class
  ``adjudication`` kind entry (payload shape aligned to the batch
  Contract) that ``read_general(kinds=[ADJUDICATION_KIND])`` returns
  intact so sibling branches consume the reject / refute verdicts.

Note-kind coercion is owned by ``turn_runner._post_ledger_writes``
(phase-keyed on the recon directive) and covered by
``test_recon_discovery_coercion.py``; the ledger layer stores the kind
it is given.
"""
from __future__ import annotations

import pytest

from aila.platform.services.ledger import (
    ADJUDICATION_KIND,
    LedgerService,
)

pytestmark = pytest.mark.asyncio


async def test_append_adjudication_rejected_hypothesis(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-adj-hyp"
    entry_id = await svc.append_adjudication(
        inv,
        "b1",
        verdict="rejected",
        target_hypothesis_id="h7",
        reason="reachability probe returned empty; no caller",
        cited_evidence=["file.c:42", "audit_mcp:callers_of:h7"],
    )
    assert isinstance(entry_id, int)
    rows = await svc.read_general(inv, kinds=[ADJUDICATION_KIND])
    assert len(rows) == 1
    payload = rows[0]["payload"]
    assert payload["verdict"] == "rejected"
    assert payload["target_hypothesis_id"] == "h7"
    assert payload["target_outcome_id"] is None
    assert payload["reason"].startswith("reachability probe")
    assert payload["cited_evidence"] == ["file.c:42", "audit_mcp:callers_of:h7"]
    assert payload["author_branch_id"] == "b1"


async def test_append_adjudication_refuted_outcome(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-adj-out"
    await svc.append_adjudication(
        inv,
        "b2",
        verdict="refuted",
        target_outcome_id="out-42",
        reason="patch v2 removes the sink",
        cited_evidence=["commit:abcd"],
    )
    rows = await svc.read_general(inv, kinds=[ADJUDICATION_KIND])
    assert len(rows) == 1
    assert rows[0]["payload"]["verdict"] == "refuted"
    assert rows[0]["payload"]["target_outcome_id"] == "out-42"


async def test_adjudication_idempotent_per_target_branch(test_db) -> None:
    del test_db
    svc = LedgerService()
    inv = "inv-adj-idem"
    a = await svc.append_adjudication(
        inv, "b1", verdict="rejected", target_hypothesis_id="h1",
        reason="r", cited_evidence=[],
    )
    b = await svc.append_adjudication(
        inv, "b1", verdict="rejected", target_hypothesis_id="h1",
        reason="r2", cited_evidence=["extra"],
    )
    assert a == b
    rows = await svc.read_general(inv, kinds=[ADJUDICATION_KIND])
    assert len(rows) == 1


async def test_adjudication_rejects_bad_verdict(test_db) -> None:
    del test_db
    svc = LedgerService()
    with pytest.raises(ValueError):
        await svc.append_adjudication(
            "inv-x", "b1", verdict="maybe",
            target_hypothesis_id="h1", reason="r", cited_evidence=[],
        )


async def test_adjudication_requires_a_target(test_db) -> None:
    del test_db
    svc = LedgerService()
    with pytest.raises(ValueError):
        await svc.append_adjudication(
            "inv-x", "b1", verdict="rejected", reason="r", cited_evidence=[],
        )

