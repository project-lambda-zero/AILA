"""Tests for the RFC-08 self-improvement services.

Three services covered:

* :class:`ExperienceWriter` -- writes a positive pattern on an approved
  review verdict and a negative pattern on a rejected one; skips draft /
  no-transition tallies. The pattern rows are asserted directly against
  ``vr_patterns`` so the pair-write (module patterns table + knowledge
  mirror) is exercised end-to-end.
* :class:`CalibrationProposer` -- aggregates a synthetic accept/reject
  history into a threshold-adjustment proposal; the persist path writes
  a versioned :class:`CalibrationProposalRecord`; the revert path writes
  a REVERTING row and flips the target's status.
* :class:`RoutingLearner` -- ranks task types for a target_kind by
  approval rate discounted by cost; a high-approval / low-cost task type
  ranks above a low-approval / high-cost one on the same synthetic
  history.

Importing :class:`CalibrationProposalRecord` at module scope registers the
``eval_calibration_proposals`` table on ``SQLModel.metadata`` so the
shared ``test_db`` fixture's ``create_all`` builds it -- the migration
lands via the orchestrator; tests do not need it.

The ExperienceWriter test uses the VR concrete PatternStore + a stubbed
KnowledgeService so the platform-side write path is exercised without
depending on a live embedding provider (mirrors
``tests/test_pattern_store_floor.py``).
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.pattern import PatternKind, VRPatternCreate
from aila.modules.vr.db_models import VRPatternRecord, VRWorkspaceRecord
from aila.modules.vr.services.pattern_store import PatternStore
from aila.platform.contracts.enums import PatternConfidence
from aila.platform.eval.calibration import (
    CALIBRATION_STATUS_ACTIVE,
    CALIBRATION_STATUS_REVERTED,
    CALIBRATION_STATUS_SUPERSEDED,
    CalibrationProposalNotFoundError,
    CalibrationProposalRecord,
    CalibrationProposer,
    CalibrationSample,
)
from aila.platform.eval.experience_writer import (
    EXPERIENCE_POLARITY_KEY,
    EXPERIENCE_POLARITY_NEGATIVE,
    EXPERIENCE_POLARITY_POSITIVE,
    NEGATIVE_SUMMARY_PREFIX,
    ExperienceWriter,
)
from aila.platform.eval.routing_learner import (
    PRE_EXECUTION_SIZING_SEAM_STATUS,
    RoutingLearner,
    RoutingSample,
)
from aila.platform.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    VOTE_APPROVE,
    VOTE_REJECT,
    QuorumOutcome,
)
from aila.platform.uow import UnitOfWork

# ---------------------------------------------------------------------------
# ExperienceWriter
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
        transition_occurred=new_state != OUTCOME_STATE_DRAFT,
        transition_reason=f"test_{new_state}",
    )


async def _seed_workspace(workspace_id: str) -> None:
    """Insert one VR workspace so the pattern FK is satisfied."""
    async with UnitOfWork() as uow:
        uow.session.add(VRWorkspaceRecord(
            id=workspace_id,
            name="rfc08 experience test",
            slug=f"rfc08-{workspace_id[:8]}",
            description="",
            theme="custom",
            status="active",
        ))
        await uow.commit()


def _fake_knowledge() -> Any:
    """Fake KnowledgeService returning a stable entry_id per store call.

    Increments so each pattern gets a distinct id (mirrors the real
    KnowledgeService flush semantics used by PatternStore.create).
    """
    counter = {"n": 0}

    async def _store(**_kwargs: Any) -> dict[str, Any]:
        counter["n"] += 1
        return {"entry_id": counter["n"], "operation": "insert"}

    return type("FK", (), {"store": _store})


@pytest.mark.asyncio
async def test_experience_writer_positive_on_approve(test_db) -> None:
    """Approved verdict writes a positive pattern into the pattern store."""
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
    assert result.polarity == EXPERIENCE_POLARITY_POSITIVE
    assert result.skipped_reason == ""

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRPatternRecord).where(
                VRPatternRecord.id == result.pattern_id,
            ),
        )).first()
    assert row is not None
    assert row.workspace_id == workspace_id
    assert row.investigation_id is None
    assert row.confidence == PatternConfidence.MEDIUM.value
    assert not row.summary.startswith(NEGATIVE_SUMMARY_PREFIX)
    applicability = json.loads(row.applicability_json or "{}")
    assert applicability[EXPERIENCE_POLARITY_KEY] == EXPERIENCE_POLARITY_POSITIVE


@pytest.mark.asyncio
async def test_experience_writer_negative_on_reject(test_db) -> None:
    """Rejected verdict writes a signed negative pattern into the store."""
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
    assert result.polarity == EXPERIENCE_POLARITY_NEGATIVE

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRPatternRecord).where(
                VRPatternRecord.id == result.pattern_id,
            ),
        )).first()
    assert row is not None
    assert row.confidence == PatternConfidence.CAVEATED.value
    assert row.summary.startswith(NEGATIVE_SUMMARY_PREFIX)
    applicability = json.loads(row.applicability_json or "{}")
    assert applicability[EXPERIENCE_POLARITY_KEY] == EXPERIENCE_POLARITY_NEGATIVE


@pytest.mark.asyncio
async def test_experience_writer_skips_non_terminal(test_db) -> None:
    """Draft / no-transition verdicts write no pattern."""
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
        verdict=_quorum(outcome_id, OUTCOME_STATE_DRAFT),
        summary="Any summary",
        body="Any body",
    )
    assert result.pattern_id is None
    assert result.polarity == ""
    assert "non_terminal_state" in result.skipped_reason


@pytest.mark.asyncio
async def test_experience_writer_skips_empty_summary(test_db) -> None:
    """Empty summary or body short-circuits before the store write."""
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
        summary="   ",
        body="body only",
    )
    assert result.pattern_id is None
    assert result.skipped_reason == "empty_summary_or_body"


# ---------------------------------------------------------------------------
# CalibrationProposer
# ---------------------------------------------------------------------------


def _threshold_provider(value: float) -> Any:
    """Return an async callable that always resolves to ``value``."""
    return AsyncMock(return_value=value)


def _samples_biased_high_conf_reject(kind: str) -> list[CalibrationSample]:
    """Build a history where high-confidence outcomes get rejected most.

    Six rejects at 0.85 confidence, three approvals at 0.90, six low
    approvals at 0.40 -- 15 samples total, above the default min_evidence
    of 10, and the high-conf-reject condition dominates so a raise fires.
    """
    samples: list[CalibrationSample] = []
    for _ in range(6):
        samples.append(CalibrationSample(kind, VOTE_REJECT, 0.85))
    for _ in range(3):
        samples.append(CalibrationSample(kind, VOTE_APPROVE, 0.90))
    for _ in range(6):
        samples.append(CalibrationSample(kind, VOTE_APPROVE, 0.40))
    return samples


@pytest.mark.asyncio
async def test_calibration_proposer_raises_threshold_on_high_conf_rejects(
    test_db,
) -> None:
    """A history dominated by high-confidence rejects yields a raise proposal."""
    del test_db
    proposer = CalibrationProposer(
        _threshold_provider(0.70),
        min_evidence=10,
        margin=0.05,
    )
    kind = "direct_finding"
    samples = _samples_biased_high_conf_reject(kind)

    proposal = await proposer.propose(kind, samples)
    assert proposal is not None
    assert proposal.outcome_kind == kind
    assert proposal.before_threshold == pytest.approx(0.70)
    assert proposal.after_threshold > proposal.before_threshold
    assert "raise" in proposal.reasoning
    assert proposal.reject_count == 6
    assert proposal.approve_count == 9
    # Mean high-conf reject = 0.85; after = 0.85 + margin = 0.90.
    assert proposal.after_threshold == pytest.approx(0.90)


@pytest.mark.asyncio
async def test_calibration_proposer_below_min_evidence_returns_none(
    test_db,
) -> None:
    """Under-supported histories produce no proposal (conservative gate)."""
    del test_db
    proposer = CalibrationProposer(
        _threshold_provider(0.7),
        min_evidence=20,
    )
    kind = "audit_memo"
    samples = _samples_biased_high_conf_reject(kind)  # 15 samples < 20
    proposal = await proposer.propose(kind, samples)
    assert proposal is None


@pytest.mark.asyncio
async def test_calibration_proposer_persist_versions_and_supersedes(
    test_db,
) -> None:
    """Persisting a second proposal supersedes the prior active row."""
    del test_db
    proposer = CalibrationProposer(
        _threshold_provider(0.70),
        min_evidence=10,
        margin=0.05,
    )
    kind = f"kind_{uuid4().hex[:6]}"
    samples = _samples_biased_high_conf_reject(kind)

    first_prop = await proposer.propose(kind, samples)
    assert first_prop is not None
    first_id = await proposer.persist(first_prop, actor="tester")

    # Second proposal (same kind) -- supersedes the first.
    second_prop = await proposer.propose(kind, samples)
    assert second_prop is not None
    second_id = await proposer.persist(second_prop, actor="tester")
    assert second_id != first_id

    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(CalibrationProposalRecord).where(
                CalibrationProposalRecord.outcome_kind == kind,
            ).order_by(CalibrationProposalRecord.created_at.asc()),
        )).all()
    assert len(rows) == 2
    first_row = next(r for r in rows if r.id == first_id)
    second_row = next(r for r in rows if r.id == second_id)
    assert first_row.status == CALIBRATION_STATUS_SUPERSEDED
    assert first_row.superseded_by == second_id
    assert second_row.status == CALIBRATION_STATUS_ACTIVE
    assert second_row.superseded_by is None


@pytest.mark.asyncio
async def test_calibration_proposer_revert_flips_before_after(
    test_db,
) -> None:
    """Revert writes a REVERTING row and marks the target row REVERTED."""
    del test_db
    proposer = CalibrationProposer(
        _threshold_provider(0.70),
        min_evidence=10,
        margin=0.05,
    )
    kind = f"kind_{uuid4().hex[:6]}"
    samples = _samples_biased_high_conf_reject(kind)
    proposal = await proposer.propose(kind, samples)
    assert proposal is not None
    original_id = await proposer.persist(proposal, actor="tester")

    revert_id = await proposer.revert(original_id, actor="tester")
    assert revert_id != original_id

    async with UnitOfWork() as uow:
        target = (await uow.session.exec(
            select(CalibrationProposalRecord).where(
                CalibrationProposalRecord.id == original_id,
            ),
        )).first()
        revert = (await uow.session.exec(
            select(CalibrationProposalRecord).where(
                CalibrationProposalRecord.id == revert_id,
            ),
        )).first()

    assert target is not None
    assert revert is not None
    assert target.status == CALIBRATION_STATUS_REVERTED
    assert target.superseded_by == revert_id
    assert revert.status == CALIBRATION_STATUS_ACTIVE
    assert revert.reverted_from == original_id
    # Before/after flipped -- restoring the original threshold.
    assert revert.before_threshold == pytest.approx(target.after_threshold)
    assert revert.after_threshold == pytest.approx(target.before_threshold)


@pytest.mark.asyncio
async def test_calibration_proposer_revert_unknown_id_raises(
    test_db,
) -> None:
    """Reverting a non-existent proposal id raises the typed error."""
    del test_db
    proposer = CalibrationProposer(
        _threshold_provider(0.70),
    )
    with pytest.raises(CalibrationProposalNotFoundError):
        await proposer.revert(str(uuid4()))


# ---------------------------------------------------------------------------
# RoutingLearner
# ---------------------------------------------------------------------------


def _routing_history() -> list[RoutingSample]:
    """Two task types on the same target_kind with clearly different scores.

    ``winner`` -- 5 approves / 1 reject, mean cost $0.01.
    ``loser``  -- 1 approve / 5 rejects, mean cost $0.10.
    Both above ``min_evidence_per_task_type`` (default 3).
    """
    kind = "web_app"
    out: list[RoutingSample] = []
    for _ in range(5):
        out.append(RoutingSample(kind, "winner", VOTE_APPROVE, 0.01))
    out.append(RoutingSample(kind, "winner", VOTE_REJECT, 0.01))
    out.append(RoutingSample(kind, "loser", VOTE_APPROVE, 0.10))
    for _ in range(5):
        out.append(RoutingSample(kind, "loser", VOTE_REJECT, 0.10))
    # Under-sampled candidate that must be filtered out.
    out.append(RoutingSample(kind, "under_sampled", VOTE_APPROVE, 0.01))
    return out


def test_routing_learner_ranks_high_approval_low_cost_first() -> None:
    """The high-approval / low-cost task type ranks above the other."""
    learner = RoutingLearner(min_evidence_per_task_type=3, cost_weight=0.3)
    rec = learner.recommend_from_history("web_app", _routing_history())

    assert rec.target_kind == "web_app"
    assert rec.seam_status == PRE_EXECUTION_SIZING_SEAM_STATUS
    ranked = rec.ranked_task_types
    assert len(ranked) == 2, "under_sampled must be filtered by min_evidence"
    task_types = [s.task_type for s in ranked]
    assert task_types.index("winner") < task_types.index("loser")

    winner = next(s for s in ranked if s.task_type == "winner")
    loser = next(s for s in ranked if s.task_type == "loser")
    assert winner.approval_rate > loser.approval_rate
    assert winner.score > loser.score
    assert winner.accepted == 5
    assert winner.rejected == 1
    assert loser.accepted == 1
    assert loser.rejected == 5


def test_routing_learner_returns_empty_when_no_qualifying() -> None:
    """When no task type meets min_evidence, ranked list is empty."""
    learner = RoutingLearner(min_evidence_per_task_type=10)
    rec = learner.recommend_from_history("web_app", _routing_history())
    assert rec.ranked_task_types == []
    assert rec.total_samples > 0
    assert "min_evidence" in rec.reasoning


def test_routing_learner_returns_empty_on_no_samples() -> None:
    """No samples -> empty ranking + reasoning describes the gap."""
    learner = RoutingLearner()
    rec = learner.recommend_from_history("web_app", [])
    assert rec.ranked_task_types == []
    assert rec.total_samples == 0
    assert "no samples" in rec.reasoning


@pytest.mark.asyncio
async def test_routing_learner_async_recommend_uses_provider() -> None:
    """The async variant fetches samples through the caller's provider."""
    learner = RoutingLearner()
    captured: list[str] = []

    async def _provider(target_kind: str) -> list[RoutingSample]:
        captured.append(target_kind)
        return _routing_history()

    rec = await learner.recommend("web_app", _provider)
    assert captured == ["web_app"]
    assert len(rec.ranked_task_types) == 2
