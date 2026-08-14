"""RFC-08 memory-poisoning tier + provenance tests (batch slice B/D).

Three end-to-end guarantees the memory-poisoning slice must uphold:

* ``ExperienceWriter.record`` stamps ``trust_tier=verified`` on approved
  verdicts and ``trust_tier=negative`` on rejected verdicts, and carries
  a provenance envelope naming the signing quorum outcome id + state.
* :class:`PatternExtractorBase._entry_to_create` builds a create body
  stamped ``trust_tier=unreviewed`` + a provenance envelope naming the
  extractor pipeline + originating outcome / investigation ids.
* :meth:`PatternStoreBase.applicable` returns positives only (NEGATIVE
  rows never appear in the actionable result list) and multiplies the
  score of any returned positive whose applicability overlaps a
  filtered-out NEGATIVE by the resolved penalty factor. Without a
  colliding negative the score is left alone.

The store test uses the VR concrete PatternStore + a stubbed
KnowledgeService (mirrors ``tests/test_pattern_store_floor.py``) so the
platform-side split-and-penalise path is exercised without depending on
a live embedding provider.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.pattern import (
    PatternKind,
    VRPatternCreate,
)
from aila.modules.vr.db_models import (
    VRPatternRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.pattern_store import PatternStore
from aila.platform.agents.pattern_extractor import PatternExtractorBase
from aila.platform.contracts.enums import (
    PatternConfidence,
    PatternScope,
    PatternStatus,
    PatternTrustTier,
)
from aila.platform.eval.experience_writer import ExperienceWriter
from aila.platform.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_REJECTED,
    QuorumOutcome,
)
from aila.platform.services.pattern_store import (
    NEGATIVE_PRIOR_PENALTY_DEFAULT,
)
from aila.platform.uow import UnitOfWork

# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


def _quorum(outcome_id: str, new_state: str) -> QuorumOutcome:
    """Build a :class:`QuorumOutcome` in the requested terminal state."""
    return QuorumOutcome(
        outcome_id=outcome_id,
        new_state=new_state,
        approve_count=2 if new_state == OUTCOME_STATE_APPROVED else 0,
        reject_count=2 if new_state == OUTCOME_STATE_REJECTED else 0,
        request_edit_count=0,
        abstain_count=0,
        quorum_k=2,
        siblings_active=2,
        transition_occurred=True,
        transition_reason=f"test_{new_state}",
    )


async def _seed_workspace(workspace_id: str) -> None:
    """Insert one VR workspace so the pattern FK is satisfied."""
    async with UnitOfWork() as uow:
        uow.session.add(VRWorkspaceRecord(
            id=workspace_id,
            name="rfc08 memory-poisoning test",
            slug=f"rfc08-mp-{workspace_id[:8]}",
            description="",
            theme="custom",
            status="active",
        ))
        await uow.commit()


def _fake_knowledge() -> Any:
    """Fake KnowledgeService returning a stable entry_id per store call."""
    counter = {"n": 0}

    async def _store(**_kwargs: Any) -> dict[str, Any]:
        counter["n"] += 1
        return {"entry_id": counter["n"], "operation": "insert"}

    return type("FK", (), {"store": _store})


# ---------------------------------------------------------------------------
# C3 -- ExperienceWriter stamps VERIFIED / NEGATIVE + provenance envelope
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_experience_writer_approved_stamps_verified_with_provenance(
    test_db,
) -> None:
    """An approved verdict stamps VERIFIED + provenance carries quorum id."""
    del test_db
    workspace_id = str(uuid4())
    outcome_id = str(uuid4())
    await _seed_workspace(workspace_id)

    store = PatternStore(knowledge=_fake_knowledge())
    writer = ExperienceWriter(
        pattern_store=store,
        pattern_create_cls=VRPatternCreate,
        pattern_kind=PatternKind.TRIAGE_RULE,
    )

    result = await writer.record(
        workspace_id=workspace_id,
        investigation_id=None,
        verdict=_quorum(outcome_id, OUTCOME_STATE_APPROVED),
        summary="Bounds check on user index prevented OOB write.",
        body="Pattern body: validate index against len before array access.",
        team_id=None,
        evidence_refs=[outcome_id],
    )
    assert result.pattern_id is not None

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRPatternRecord).where(
                VRPatternRecord.id == result.pattern_id,
            ),
        )).first()
    assert row is not None
    assert row.trust_tier == PatternTrustTier.VERIFIED.value
    provenance = json.loads(row.provenance_json or "{}")
    assert provenance["source"] == "review"
    assert provenance["quorum_outcome_id"] == outcome_id
    assert provenance["state"] == OUTCOME_STATE_APPROVED


@pytest.mark.asyncio
async def test_experience_writer_rejected_stamps_negative_with_provenance(
    test_db,
) -> None:
    """A rejected verdict stamps NEGATIVE + provenance carries quorum id."""
    del test_db
    workspace_id = str(uuid4())
    outcome_id = str(uuid4())
    await _seed_workspace(workspace_id)

    store = PatternStore(knowledge=_fake_knowledge())
    writer = ExperienceWriter(
        pattern_store=store,
        pattern_create_cls=VRPatternCreate,
        pattern_kind=PatternKind.TRIAGE_RULE,
    )

    result = await writer.record(
        workspace_id=workspace_id,
        investigation_id=None,
        verdict=_quorum(outcome_id, OUTCOME_STATE_REJECTED),
        summary="Claimed race on socket teardown; verifier found no shared state.",
        body="Rejected: refcount owner is single-threaded; the race hypothesis is refuted.",
        team_id=None,
        evidence_refs=[outcome_id],
    )
    assert result.pattern_id is not None

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRPatternRecord).where(
                VRPatternRecord.id == result.pattern_id,
            ),
        )).first()
    assert row is not None
    assert row.trust_tier == PatternTrustTier.NEGATIVE.value
    provenance = json.loads(row.provenance_json or "{}")
    assert provenance["source"] == "review"
    assert provenance["quorum_outcome_id"] == outcome_id
    assert provenance["state"] == OUTCOME_STATE_REJECTED


# ---------------------------------------------------------------------------
# C3 -- pattern_extractor stamps UNREVIEWED + pipeline provenance
# ---------------------------------------------------------------------------


class _StubExtractor(PatternExtractorBase):
    """Bind :class:`PatternExtractorBase` to VR's pattern shape.

    Only ``_entry_to_create`` is exercised so the network of
    ``_load`` / ``_load_transcript`` / LLM calls is irrelevant here --
    the class-level attributes below are enough to satisfy the classmethod.
    """

    _pattern_kind_enum = PatternKind
    _pattern_confidence_enum = PatternConfidence
    _pattern_scope_enum = PatternScope
    _pattern_create_cls = VRPatternCreate


def test_pattern_extractor_stamps_unreviewed_with_pipeline_provenance() -> None:
    """The extractor's create body carries UNREVIEWED + pipeline provenance."""
    entry: dict[str, Any] = {
        "kind": PatternKind.TRIAGE_RULE.value,
        "summary": "Reachable strcpy behind is_admin flag needs review.",
        "body": "Pattern body -- audit strcpy calls gated by is_admin.",
        "applicability": {"target_kinds": ["binary"]},
        "confidence": PatternConfidence.MEDIUM.value,
        "evidence_refs": ["msg-1", "msg-2"],
    }
    create = _StubExtractor._entry_to_create(
        entry,
        workspace_id="ws-1",
        investigation_id="inv-1",
        outcome_id="oc-1",
    )

    assert create.trust_tier == PatternTrustTier.UNREVIEWED
    assert create.provenance == {
        "source": "pattern_extractor",
        "outcome_id": "oc-1",
        "investigation_id": "inv-1",
    }


# ---------------------------------------------------------------------------
# C4 -- applicable() filters NEGATIVEs + down-weights overlapping positives
# ---------------------------------------------------------------------------


async def _insert_pattern(
    workspace_id: str,
    *,
    pattern_id: str,
    trust_tier: PatternTrustTier,
    applicability: dict[str, Any],
) -> None:
    """Insert one ACTIVE workspace-scoped pattern with the given tier."""
    async with UnitOfWork() as uow:
        uow.session.add(
            VRPatternRecord(
                id=pattern_id,
                workspace_id=workspace_id,
                investigation_id=None,
                kind=PatternKind.TRIAGE_RULE.value,
                summary=f"Test pattern {pattern_id[:8]}",
                body="Body",
                applicability_json=json.dumps(applicability),
                confidence=PatternConfidence.MEDIUM.value,
                evidence_refs_json="[]",
                status=PatternStatus.ACTIVE.value,
                scope=PatternScope.WORKSPACE.value,
                knowledge_entry_id=None,
                trust_tier=trust_tier.value,
                provenance_json=json.dumps({
                    "source": "test",
                    "trust_tier": trust_tier.value,
                }),
            ),
        )
        await uow.commit()


def _fake_hit(pattern_id: str, score: float) -> dict[str, Any]:
    """Shape a fake ``retrieve_routed`` result row.

    Mirrors the fields :meth:`PatternStoreBase.applicable` reads: ``score``
    for ranking, ``metadata.pattern_id`` for the join back to the
    structured pool, and ``hop`` for the RFC-14 ``matched_by`` branch.
    """
    return {
        "id": 0,
        "content": "irrelevant",
        "metadata": {"pattern_id": pattern_id},
        "score": score,
        "vec_score": score,
        "fts_score": 0.0,
        "source": "graph",
        "namespace": "vr.pattern.workspace.dummy",
        "hop": 0,
        "path": [],
        "incoming_relation": None,
        "incoming_weight": None,
    }


def _routed(hits: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap hits in the ``retrieve_routed`` return envelope."""
    return {
        "status": "retrieved",
        "route": "graph",
        "query": "anything",
        "count": len(hits),
        "results": hits,
        "hop_bound": 2,
    }


@pytest.mark.asyncio
async def test_applicable_filters_negative_and_down_weights_overlap(
    test_db, monkeypatch,
) -> None:
    """Negative absent from results; overlapping positive's score halved."""
    del test_db
    # Force a deterministic penalty via the module default (0.5). Env is
    # explicitly cleared so the ConfigRegistry lookup falls through to the
    # schema default without depending on the ambient host env.
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_NEGATIVE_PRIOR_PENALTY",
        raising=False,
    )
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        raising=False,
    )

    workspace_id = str(uuid4())
    positive_id = str(uuid4())
    negative_id = str(uuid4())
    await _seed_workspace(workspace_id)

    # VERIFIED positive + NEGATIVE with overlapping target_kinds so the
    # C4 overlap check fires (both restrict on ``target_kinds`` and the
    # lists intersect on ``binary``).
    overlap_app: dict[str, Any] = {"target_kinds": ["binary"]}
    await _insert_pattern(
        workspace_id,
        pattern_id=positive_id,
        trust_tier=PatternTrustTier.VERIFIED,
        applicability=overlap_app,
    )
    await _insert_pattern(
        workspace_id,
        pattern_id=negative_id,
        trust_tier=PatternTrustTier.NEGATIVE,
        applicability=overlap_app,
    )

    knowledge = AsyncMock()
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([
            _fake_hit(positive_id, 0.9),
            _fake_hit(negative_id, 0.9),
        ]),
    )
    store = PatternStore(knowledge)

    results = await store.applicable(
        workspace_id=workspace_id,
        team_id=None,
        query="strcpy",
    )
    returned_ids = [r.pattern.id for r in results]
    assert positive_id in returned_ids, (
        "verified positive must reach the researcher prompt"
    )
    assert negative_id not in returned_ids, (
        "NEGATIVE row must never enter the actionable result list"
    )
    positive_result = next(r for r in results if r.pattern.id == positive_id)
    # Score halved by exactly one 0.5 multiplication: one overlapping
    # NEGATIVE, and the positive itself is VERIFIED (no extra penalty).
    assert positive_result.score == pytest.approx(0.9 * NEGATIVE_PRIOR_PENALTY_DEFAULT)


@pytest.mark.asyncio
async def test_applicable_without_negative_leaves_score_unchanged(
    test_db, monkeypatch,
) -> None:
    """No negative collocated -> verified positive keeps its raw score."""
    del test_db
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_NEGATIVE_PRIOR_PENALTY",
        raising=False,
    )
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        raising=False,
    )

    workspace_id = str(uuid4())
    positive_id = str(uuid4())
    await _seed_workspace(workspace_id)
    await _insert_pattern(
        workspace_id,
        pattern_id=positive_id,
        trust_tier=PatternTrustTier.VERIFIED,
        applicability={"target_kinds": ["binary"]},
    )

    knowledge = AsyncMock()
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([_fake_hit(positive_id, 0.9)]),
    )
    store = PatternStore(knowledge)

    results = await store.applicable(
        workspace_id=workspace_id,
        team_id=None,
        query="strcpy",
    )
    assert len(results) == 1
    assert results[0].pattern.id == positive_id
    # No overlap -> factor is 1.0 -> raw score preserved.
    assert results[0].score == pytest.approx(0.9)


@pytest.mark.asyncio
async def test_applicable_unreviewed_positive_gets_single_penalty(
    test_db, monkeypatch,
) -> None:
    """UNREVIEWED ACTIVE positive retrieves at reduced weight even alone."""
    del test_db
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_NEGATIVE_PRIOR_PENALTY",
        raising=False,
    )
    monkeypatch.delenv(
        "AILA_PLATFORM_KNOWLEDGE_PATTERN_RELEVANCE_FLOOR",
        raising=False,
    )

    workspace_id = str(uuid4())
    positive_id = str(uuid4())
    await _seed_workspace(workspace_id)
    await _insert_pattern(
        workspace_id,
        pattern_id=positive_id,
        trust_tier=PatternTrustTier.UNREVIEWED,
        applicability={"target_kinds": ["binary"]},
    )

    knowledge = AsyncMock()
    knowledge.retrieve_routed = AsyncMock(
        return_value=_routed([_fake_hit(positive_id, 0.9)]),
    )
    store = PatternStore(knowledge)

    results = await store.applicable(
        workspace_id=workspace_id,
        team_id=None,
        query="strcpy",
    )
    assert len(results) == 1
    # No negatives, so only the UNREVIEWED single-penalty applies.
    assert results[0].score == pytest.approx(0.9 * NEGATIVE_PRIOR_PENALTY_DEFAULT)
