"""RFC-12 Phase 5: trust-tier labeling + retrieval-journal write (ASI06).

Covers the pure trust-tier map and the best-effort ``_journal_retrieval``
helper that records what an investigation retrieved. The retrieve_routed ->
journal integration is exercised live; here we lock the tier mapping, the
journal payload shape, and the never-raises contract without a DB.
"""
from __future__ import annotations

import aila.platform.services.journal as journal_mod
from aila.platform.services.knowledge import (
    TRUST_TIER_TARGET_DERIVED,
    TRUST_TIER_VERIFIED,
    _journal_retrieval,
    trust_tier_from_namespace,
)


def test_trust_tier_from_namespace_maps_verified_vs_target_derived() -> None:
    # Finding / audit_memo kinds are quorum-gated by writer contract and
    # stay verified without any metadata hint.
    assert trust_tier_from_namespace("vr.finding.workspace.x") == TRUST_TIER_VERIFIED
    assert trust_tier_from_namespace("vr.audit_memo.global") == TRUST_TIER_VERIFIED
    # RFC-12 D1: model-distilled kinds (``*.semantic.*`` / ``*.pattern.*``)
    # are target_derived UNTIL the writer stamps ``confirmed=true``. The
    # namespace alone no longer authorizes trust.
    assert (
        trust_tier_from_namespace("malware.pattern.workspace.x")
        == TRUST_TIER_TARGET_DERIVED
    )
    assert (
        trust_tier_from_namespace(
            "malware.pattern.workspace.x", {"confirmed": True},
        )
        == TRUST_TIER_VERIFIED
    )
    assert (
        trust_tier_from_namespace("vr.semantic.workspace.x")
        == TRUST_TIER_TARGET_DERIVED
    )
    assert (
        trust_tier_from_namespace(
            "vr.semantic.workspace.x", {"confirmed": True},
        )
        == TRUST_TIER_VERIFIED
    )
    # observation namespaces are burned straight off tool output -> untrusted
    assert (
        trust_tier_from_namespace("vr.observation.workspace.x")
        == TRUST_TIER_TARGET_DERIVED
    )
    assert (
        trust_tier_from_namespace("malware.observation.workspace.x")
        == TRUST_TIER_TARGET_DERIVED
    )
    # Even ``confirmed=true`` metadata never lifts an observation row --
    # the target-derived kind wins over the flag.
    assert (
        trust_tier_from_namespace(
            "vr.observation.workspace.x", {"confirmed": True},
        )
        == TRUST_TIER_TARGET_DERIVED
    )
    # empty / unknown defaults to the conservative tier
    assert trust_tier_from_namespace(None) == TRUST_TIER_TARGET_DERIVED
    assert trust_tier_from_namespace("") == TRUST_TIER_TARGET_DERIVED


async def test_journal_retrieval_writes_entry_with_tiers(monkeypatch) -> None:
    captured: dict[str, object] = {}

    async def _fake_append(session, *, entry, team_id=None):
        captured["entry"] = entry
        captured["team_id"] = team_id
        return None

    monkeypatch.setattr(journal_mod, "append_or_deadletter", _fake_append)

    gated = [
        {"id": 1, "namespace": "vr.finding.workspace.w", "score": 0.71,
         "classification": "public"},
        {"id": 2, "namespace": "vr.observation.workspace.w", "score": 0.42,
         "classification": "internal"},
    ]
    await _journal_retrieval(
        route="simple",
        query="lateral movement",
        min_score=0.3,
        namespaces=["vr.finding.workspace.w", "vr.observation.workspace.w"],
        gated=gated,
        journal_context={"investigation_id": "inv-1", "team_id": "team-9"},
        session=object(),  # non-None -> caller-session branch, no DB
    )

    entry = captured["entry"]
    assert entry.kind == "knowledge_retrieval"
    assert entry.investigation_id == "inv-1"
    assert captured["team_id"] == "team-9"
    assert entry.payload["route"] == "simple"
    assert entry.payload["result_count"] == 2
    tiers = {r["entry_id"]: r["trust_tier"] for r in entry.payload["results"]}
    assert tiers == {1: TRUST_TIER_VERIFIED, 2: TRUST_TIER_TARGET_DERIVED}


async def test_journal_retrieval_never_raises_on_write_failure(monkeypatch) -> None:
    async def _boom(session, *, entry, team_id=None):
        raise RuntimeError("journal chain unavailable")

    monkeypatch.setattr(journal_mod, "append_or_deadletter", _boom)

    # Must swallow -- retrieval is an augmentation, not a precondition.
    await _journal_retrieval(
        route="simple",
        query="q",
        min_score=0.3,
        namespaces=["vr.finding.workspace.w"],
        gated=[{"id": 1, "namespace": "vr.finding.workspace.w", "score": 0.6}],
        journal_context={"investigation_id": "inv-1"},
        session=object(),
    )
