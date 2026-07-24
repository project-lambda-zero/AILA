"""RFC-08 step 2: per-outcome_kind calibration proposer + versioned journal.

The observed overstatement bias -- accepted low-severity, rejected
high-severity -- is a per-``outcome_kind`` signal in the accept/reject
history that the operator's review quorum already writes. ``CalibrationProposer``
turns that history into a threshold-adjustment proposal without ever
mutating the live threshold: application is gated by the RFC-08 eval +
review quorum, per the propose-and-gate contract.

Storage: :class:`CalibrationProposalRecord` is an append-only journal of
proposals. Each row carries the before / after threshold values plus the
sample counts it was derived from. Reversibility is expressed as a chain
of rows -- reverting a proposal never rewrites the original row; it
inserts a new proposal that flips the before/after values and stamps
``superseded_by`` on the target. Every historical decision stays
grep-able against the row that produced it.

Constraint + index names carry the ``eval_calibration_proposals_`` prefix
so they stay unique across the platform schema (Postgres constraint
names are database-scoped, not table-scoped -- the same lesson eval and
prompt tables learned).

The proposer's aggregation logic is deliberately conservative:

* ``min_evidence`` samples per kind before a proposal is allowed to
  suggest a threshold move at all. Under-supported proposals return
  ``None`` so noise cannot chase the threshold up.
* A raise fires only when high-confidence rejects OUTNUMBER the sum of
  approves and low-confidence rejects at the same confidence band --
  the operator was rejecting confidently-stated findings, so the bar
  needs to be higher than that confidence band. The new threshold is
  the mean of the high-confidence-reject confidences plus ``margin``.
* A drop fires only when high-confidence approvals crowded above the
  current threshold and there were essentially no rejects at that
  band -- the current threshold is over-cautious and dropping it in
  by ``margin`` unlocks accepted findings the panel already agreed on.
* If neither condition holds, ``before == after`` and the proposal
  carries a "no adjustment recommended" reasoning -- still logged so
  the review pass sees that the proposer LOOKED.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from statistics import mean
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text
from sqlmodel import Field, SQLModel, select

from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope

# Vote string literals held here as SINGLE SOURCE for the eval module.
# The canonical declaration is
# ``aila.platform.services.outcome_review.VOTE_APPROVE`` / ``VOTE_REJECT``;
# a module-scope import of that module creates the same load-time cycle
# through ``services/__init__ -> audit -> journal -> db_models ->
# eval.models`` that :mod:`aila.platform.eval.experience_writer` documents.
# Duplicating two seven-character strings is the cheapest cycle-break;
# the RFC-08 test feeds real ``QuorumOutcome`` / vote data through the
# proposer so a drift between the two files would flag immediately.
_VOTE_APPROVE: str = "approve"
_VOTE_REJECT: str = "reject"

__all__ = [
    "CALIBRATION_STATUS_ACTIVE",
    "CALIBRATION_STATUS_REVERTED",
    "CALIBRATION_STATUS_SUPERSEDED",
    "CalibrationProposal",
    "CalibrationProposalNotFoundError",
    "CalibrationProposalRecord",
    "CalibrationProposer",
    "CalibrationSample",
]

_log = logging.getLogger(__name__)


CALIBRATION_STATUS_ACTIVE: str = "active"
CALIBRATION_STATUS_SUPERSEDED: str = "superseded"
CALIBRATION_STATUS_REVERTED: str = "reverted"

_VALID_STATUSES: frozenset[str] = frozenset({
    CALIBRATION_STATUS_ACTIVE,
    CALIBRATION_STATUS_SUPERSEDED,
    CALIBRATION_STATUS_REVERTED,
})


class CalibrationProposalNotFoundError(LookupError):
    """Raised when a proposal id has no matching row (e.g. revert target)."""


class CalibrationProposalRecord(SQLModel, table=True):
    """One append-only calibration proposal row.

    ``status`` starts as :data:`CALIBRATION_STATUS_ACTIVE`. When a newer
    proposal covers the same ``outcome_kind`` and is persisted, the older
    row's status flips to :data:`CALIBRATION_STATUS_SUPERSEDED` and its
    ``superseded_by`` points at the new row. A revert is a special case:
    a NEW row (also ACTIVE) is written whose before/after are the target
    row's after/before, and the target row's status flips to
    :data:`CALIBRATION_STATUS_REVERTED` with ``superseded_by`` pointing at
    the revert row. Every historical decision is still on disk; nothing
    is ever updated in place except the ``status`` + ``superseded_by``
    pair that marks a row as no-longer-current.
    """

    __tablename__ = "eval_calibration_proposals"
    __table_args__ = (
        Index(
            "ix_eval_calibration_proposals_kind_created_at",
            "outcome_kind", "created_at",
        ),
        Index(
            "ix_eval_calibration_proposals_status",
            "status",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    outcome_kind: str = Field(max_length=64, index=True)
    before_threshold: float = Field()
    after_threshold: float = Field()
    approve_count: int = Field(default=0)
    reject_count: int = Field(default=0)
    mean_confidence_reject: float = Field(default=0.0)
    mean_confidence_approve: float = Field(default=0.0)
    reasoning: str = Field(default="", sa_type=Text)
    evidence_json: str = Field(default="{}", sa_type=Text)
    status: str = Field(default=CALIBRATION_STATUS_ACTIVE, max_length=16)
    superseded_by: str | None = Field(default=None, max_length=64)
    reverted_from: str | None = Field(default=None, max_length=64)
    actor: str = Field(default="", max_length=128)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


@dataclass(frozen=True, slots=True)
class CalibrationSample:
    """One accept/reject sample fed to the proposer.

    ``verdict`` MUST be either :data:`VOTE_APPROVE` or :data:`VOTE_REJECT`;
    request_edit / abstain are neither positive nor negative signal for
    calibration and are filtered out before this record is built.
    ``confidence`` is the outcome's ``confidence`` numeric interpretation
    (0.0 to 1.0) at the time of the vote.
    """

    outcome_kind: str
    verdict: str
    confidence: float


@dataclass(frozen=True, slots=True)
class CalibrationProposal:
    """One threshold-adjustment proposal (pre-persist, in-memory shape)."""

    outcome_kind: str
    before_threshold: float
    after_threshold: float
    approve_count: int
    reject_count: int
    mean_confidence_reject: float
    mean_confidence_approve: float
    reasoning: str
    evidence: dict[str, Any]


ThresholdProvider = Callable[[str], Awaitable[float]]


class CalibrationProposer:
    """Aggregate accept/reject samples into a versioned threshold proposal."""

    def __init__(
        self,
        current_threshold_provider: ThresholdProvider,
        *,
        min_evidence: int = 10,
        margin: float = 0.05,
    ) -> None:
        """Bind the current-threshold reader + evidence + margin controls.

        Args:
            current_threshold_provider: Async callable that takes the
                ``outcome_kind`` and returns the threshold currently in
                production for that kind (float in [0, 1]). Modules bind
                it to their :class:`ConfigRegistry` reader so the
                proposer resolves against ``<module>.<threshold_key>``.
            min_evidence: Minimum total sample count per kind before a
                move is proposed. Below this the aggregator returns
                ``None`` -- the operator sees "not enough data" instead
                of a noisy threshold jump.
            margin: Distance from the aggregated confidence to move the
                threshold. Applied ADDITIVELY on raises and
                SUBTRACTIVELY on drops.
        """
        self._current = current_threshold_provider
        self._min_evidence = int(min_evidence)
        self._margin = float(margin)

    def propose_from_history(
        self,
        outcome_kind: str,
        current_threshold: float,
        samples: Sequence[CalibrationSample],
    ) -> CalibrationProposal | None:
        """Aggregate ``samples`` into a proposal for ``outcome_kind``.

        Returns ``None`` when fewer than ``min_evidence`` votes exist for
        this kind (proposer is deliberately conservative -- the signal
        needs a window to overcome per-run noise).
        """
        filtered = [
            s for s in samples
            if s.outcome_kind == outcome_kind
            and s.verdict in {_VOTE_APPROVE, _VOTE_REJECT}
        ]
        if len(filtered) < self._min_evidence:
            return None

        approves = [s for s in filtered if s.verdict == _VOTE_APPROVE]
        rejects = [s for s in filtered if s.verdict == _VOTE_REJECT]
        approve_count = len(approves)
        reject_count = len(rejects)
        mean_conf_approve = (
            mean(s.confidence for s in approves) if approves else 0.0
        )
        mean_conf_reject = (
            mean(s.confidence for s in rejects) if rejects else 0.0
        )

        high_conf_rejects = [
            s for s in rejects if s.confidence >= current_threshold
        ]
        high_conf_approves = [
            s for s in approves if s.confidence >= current_threshold
        ]

        evidence: dict[str, Any] = {
            "total_samples": len(filtered),
            "approve_count": approve_count,
            "reject_count": reject_count,
            "mean_confidence_approve": mean_conf_approve,
            "mean_confidence_reject": mean_conf_reject,
            "high_conf_rejects": len(high_conf_rejects),
            "high_conf_approves": len(high_conf_approves),
        }

        # Raise: high-confidence rejects OUTNUMBER high-confidence
        # approvals at or above the current threshold. The operator is
        # rejecting confidently-stated findings, so the bar must rise
        # above the confidence band those rejects clustered in. New bar
        # = mean(high-conf rejects) + margin, clamped to [0, 1].
        if len(high_conf_rejects) > len(high_conf_approves):
            target = mean(s.confidence for s in high_conf_rejects) + self._margin
            after = min(1.0, max(current_threshold, target))
            reasoning = (
                f"raise: {len(high_conf_rejects)} high-confidence rejects "
                f"outnumber {len(high_conf_approves)} high-confidence approvals "
                f"at or above current threshold {current_threshold:.3f}; "
                f"proposed after={after:.3f} = mean(high-conf-reject)+{self._margin}"
            )
            return CalibrationProposal(
                outcome_kind=outcome_kind,
                before_threshold=current_threshold,
                after_threshold=after,
                approve_count=approve_count,
                reject_count=reject_count,
                mean_confidence_reject=mean_conf_reject,
                mean_confidence_approve=mean_conf_approve,
                reasoning=reasoning,
                evidence=evidence,
            )

        # Drop: high-confidence approvals dominate AND rejects are rare.
        # The threshold is too cautious; drop by margin down to the
        # mean-approve band. Requires reject_count / total <= 0.1 so a
        # borderline mix stays put.
        if (
            len(high_conf_approves) >= 3
            and reject_count / max(len(filtered), 1) <= 0.1
        ):
            target = max(0.0, current_threshold - self._margin)
            reasoning = (
                f"drop: {len(high_conf_approves)} high-confidence approvals "
                f"vs {reject_count} rejects (rate<=10%); "
                f"proposed after={target:.3f} = current-{self._margin}"
            )
            return CalibrationProposal(
                outcome_kind=outcome_kind,
                before_threshold=current_threshold,
                after_threshold=target,
                approve_count=approve_count,
                reject_count=reject_count,
                mean_confidence_reject=mean_conf_reject,
                mean_confidence_approve=mean_conf_approve,
                reasoning=reasoning,
                evidence=evidence,
            )

        # No-move: the signal window shows no systematic overstatement
        # or under-shooting. Emit a proposal that records the aggregation
        # so the review pass has a trail even in a no-op tick.
        return CalibrationProposal(
            outcome_kind=outcome_kind,
            before_threshold=current_threshold,
            after_threshold=current_threshold,
            approve_count=approve_count,
            reject_count=reject_count,
            mean_confidence_reject=mean_conf_reject,
            mean_confidence_approve=mean_conf_approve,
            reasoning=(
                f"no_move: {approve_count} approves / {reject_count} rejects; "
                "neither raise nor drop condition met"
            ),
            evidence=evidence,
        )

    async def propose(
        self,
        outcome_kind: str,
        samples: Sequence[CalibrationSample],
    ) -> CalibrationProposal | None:
        """Look up the current threshold then aggregate."""
        current = float(await self._current(outcome_kind))
        return self.propose_from_history(outcome_kind, current, samples)

    async def persist(
        self,
        proposal: CalibrationProposal,
        *,
        actor: str = "",
    ) -> str:
        """Write ``proposal`` as an ACTIVE row and supersede prior ACTIVE.

        Any existing ACTIVE row for the same ``outcome_kind`` flips to
        :data:`CALIBRATION_STATUS_SUPERSEDED` and its ``superseded_by``
        points at the new row. Returns the id of the new row.
        """
        new_id = str(uuid4())
        async with async_session_scope() as session:
            active_stmt = select(CalibrationProposalRecord).where(
                CalibrationProposalRecord.outcome_kind == proposal.outcome_kind,
                CalibrationProposalRecord.status == CALIBRATION_STATUS_ACTIVE,
            )
            prior = (await session.exec(active_stmt)).all()
            for row in prior:
                row.status = CALIBRATION_STATUS_SUPERSEDED
                row.superseded_by = new_id
                session.add(row)

            new_row = CalibrationProposalRecord(
                id=new_id,
                outcome_kind=proposal.outcome_kind,
                before_threshold=proposal.before_threshold,
                after_threshold=proposal.after_threshold,
                approve_count=proposal.approve_count,
                reject_count=proposal.reject_count,
                mean_confidence_reject=proposal.mean_confidence_reject,
                mean_confidence_approve=proposal.mean_confidence_approve,
                reasoning=proposal.reasoning,
                evidence_json=json.dumps(proposal.evidence, sort_keys=True),
                status=CALIBRATION_STATUS_ACTIVE,
                actor=actor,
            )
            session.add(new_row)
            await session.commit()
        _log.info(
            "calibration_proposer: persisted id=%s kind=%s before=%s after=%s",
            new_id, proposal.outcome_kind,
            proposal.before_threshold, proposal.after_threshold,
        )
        return new_id

    async def revert(
        self, proposal_id: str, *, actor: str = "",
    ) -> str:
        """Write a REVERTING proposal that flips before/after.

        The target row's status flips to :data:`CALIBRATION_STATUS_REVERTED`
        with ``superseded_by`` pointing at the revert row. The revert row
        stamps ``reverted_from`` at the target so the chain is bi-directional.
        Returns the revert row's id.

        Raises :class:`CalibrationProposalNotFoundError` when ``proposal_id``
        does not resolve to a row.
        """
        revert_id = str(uuid4())
        async with async_session_scope() as session:
            target = (await session.exec(
                select(CalibrationProposalRecord).where(
                    CalibrationProposalRecord.id == proposal_id,
                ),
            )).first()
            if target is None:
                raise CalibrationProposalNotFoundError(
                    f"calibration proposal {proposal_id} not found",
                )

            revert_row = CalibrationProposalRecord(
                id=revert_id,
                outcome_kind=target.outcome_kind,
                before_threshold=target.after_threshold,
                after_threshold=target.before_threshold,
                approve_count=target.approve_count,
                reject_count=target.reject_count,
                mean_confidence_reject=target.mean_confidence_reject,
                mean_confidence_approve=target.mean_confidence_approve,
                reasoning=(
                    f"revert of {proposal_id}: "
                    f"restore {target.before_threshold:.3f} "
                    f"(from {target.after_threshold:.3f})"
                ),
                evidence_json=target.evidence_json,
                status=CALIBRATION_STATUS_ACTIVE,
                reverted_from=proposal_id,
                actor=actor,
            )
            session.add(revert_row)

            target.status = CALIBRATION_STATUS_REVERTED
            target.superseded_by = revert_id
            session.add(target)

            await session.commit()
        _log.info(
            "calibration_proposer: reverted id=%s -> new id=%s kind=%s",
            proposal_id, revert_id, target.outcome_kind,
        )
        return revert_id
