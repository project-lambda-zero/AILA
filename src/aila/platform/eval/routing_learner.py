"""RFC-08 step 3: turn historical outcome + cost data into a routing recommendation.

The reward signal for routing is the same accept/reject verdict the review
quorum writes, joined against the ``task_type`` (or persona role) that
served the LLM calls on the branch that produced the outcome. Cost is the
per-call USD amount from :class:`LLMCostRecord` for the same run. The
learner combines the two into a per-task-type score for a given
``target_kind`` -- approval rate discounted by mean cost -- and returns a
:class:`RoutingRecommendation` listing task types ranked by that score.

The recommendation is a proposal only. It does NOT flip any live routing
switch; whether the recommendation is USED by pre-execution sizing is the
sizing layer's decision, which itself is gated by the RFC-08 eval + review
quorum contract. The learner exposes the recommendation and reports the
sizing seam.

Pre-execution sizing seam (RFC-10 SHADOW / CANARY stages, cross-ref #23):
The lifecycle stage vocabulary declares ``SHADOW`` and ``CANARY`` as
reserved-for-later stages (``platform/lifecycle/models.py``); the
controller has no path from ``EVALUATED`` to either stage today, and no
platform component consumes a ``RoutingRecommendation`` at branch spawn
time. Branch creation flows through ``BranchPool`` operations
(``platform/agents/branch_pool.py``) that take a fixed persona / voice
argument, not a sizing hint. Until that seam lands, the learner
publishes the recommendation via ``recommend_from_history`` and the
async ``recommend`` variant that wraps a caller-supplied history
provider; a caller can consume the recommendation manually. Wiring the
recommendation into an automatic pre-execution sizing input is deferred
to the follow-on that ships the SHADOW / CANARY stage transitions in the
lifecycle controller.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from statistics import mean
from typing import Any

from aila.platform.contracts._common import utc_now

# Vote string literals held here as SINGLE SOURCE for the eval module.
# See :mod:`aila.platform.eval.experience_writer` and
# :mod:`aila.platform.eval.calibration` for the same rationale: a
# module-scope import of ``aila.platform.services.outcome_review``
# creates a load-time cycle through ``services/__init__ -> audit ->
# journal -> db_models -> eval.models`` (db_models eagerly registers
# eval tables). Duplicating two seven-character strings is the cheapest
# cycle-break.
_VOTE_APPROVE: str = "approve"
_VOTE_REJECT: str = "reject"

__all__ = [
    "PRE_EXECUTION_SIZING_SEAM_STATUS",
    "RoutingLearner",
    "RoutingRecommendation",
    "RoutingSample",
    "TaskTypeScore",
]


# One-line seam status published as a module constant so a caller can
# introspect the learner's wire-up state without reading source. The RFC-08
# acceptance requirement 5 states the recommendation "feeds #23
# pre-execution sizing"; until the lifecycle SHADOW/CANARY transitions
# ship and the branch-spawn path takes a sizing input, the seam is
# ``recommendation_only``. A follow-up increment flips this to
# ``wired_to_sizing`` alongside the lifecycle change.
PRE_EXECUTION_SIZING_SEAM_STATUS: str = "recommendation_only"


@dataclass(frozen=True, slots=True)
class RoutingSample:
    """One historical (target_kind, task_type, verdict, cost) tuple.

    ``verdict`` MUST be :data:`VOTE_APPROVE` or :data:`VOTE_REJECT`;
    request_edit / abstain are not routing signal and are filtered before
    the sample list is built. ``cost_usd`` is the total per-call cost that
    landed on the branch that produced this outcome (summed if a branch
    made multiple calls before terminal submit).
    """

    target_kind: str
    task_type: str
    verdict: str
    cost_usd: float


@dataclass(frozen=True, slots=True)
class TaskTypeScore:
    """Per-task-type score with the counts that produced it."""

    task_type: str
    accepted: int
    rejected: int
    mean_cost_usd: float
    approval_rate: float
    score: float


@dataclass(frozen=True, slots=True)
class RoutingRecommendation:
    """The learner's ranked recommendation for one ``target_kind``.

    ``ranked_task_types`` is sorted descending by ``score``. When the
    learner has zero qualifying task types (every candidate was under
    ``min_evidence_per_task_type``) the list is empty and the caller
    should fall through to the module's default routing.
    """

    target_kind: str
    ranked_task_types: list[TaskTypeScore]
    total_samples: int
    generated_at: datetime
    reasoning: str
    seam_status: str


HistoryProvider = Callable[[str], Awaitable[Sequence[RoutingSample]]]


class RoutingLearner:
    """Rank task types by (approval_rate discounted by cost) per target_kind."""

    def __init__(
        self,
        *,
        min_evidence_per_task_type: int = 3,
        cost_weight: float = 0.3,
    ) -> None:
        """Bind the aggregation controls.

        Args:
            min_evidence_per_task_type: Minimum sample count PER task type
                before that task type is scored. Below the floor, the
                task type is dropped from the ranking -- an under-sampled
                candidate cannot beat a well-sampled one on noise.
            cost_weight: Weight of the cost penalty in the composite
                score. ``score = approval_rate - cost_weight *
                normalized_cost`` where ``normalized_cost`` is the task
                type's mean cost divided by the max mean cost across the
                candidate set (0 to 1). Zero disables the cost signal;
                one makes cost as strong as approval rate.
        """
        self._min_evidence = int(min_evidence_per_task_type)
        self._cost_weight = float(cost_weight)

    def recommend_from_history(
        self,
        target_kind: str,
        samples: Sequence[RoutingSample],
    ) -> RoutingRecommendation:
        """Turn the sample list into a ranked recommendation.

        Aggregation:
          1. Filter to samples matching ``target_kind`` with a valid verdict.
          2. Group by ``task_type``; drop groups smaller than
             ``min_evidence_per_task_type``.
          3. For each remaining group compute approval_rate, mean_cost.
          4. Normalize mean_cost by the max across groups (so cost_weight
             is comparable across target_kinds with different price
             floors).
          5. Score = approval_rate - cost_weight * normalized_cost.
          6. Sort descending by score.
        """
        filtered = [
            s for s in samples
            if s.target_kind == target_kind
            and s.verdict in {_VOTE_APPROVE, _VOTE_REJECT}
        ]
        total = len(filtered)
        if total == 0:
            return RoutingRecommendation(
                target_kind=target_kind,
                ranked_task_types=[],
                total_samples=0,
                generated_at=utc_now(),
                reasoning=f"no samples for target_kind={target_kind}",
                seam_status=PRE_EXECUTION_SIZING_SEAM_STATUS,
            )

        grouped: dict[str, list[RoutingSample]] = {}
        for s in filtered:
            grouped.setdefault(s.task_type, []).append(s)

        qualifying: dict[str, list[RoutingSample]] = {
            tt: group for tt, group in grouped.items()
            if len(group) >= self._min_evidence
        }
        if not qualifying:
            return RoutingRecommendation(
                target_kind=target_kind,
                ranked_task_types=[],
                total_samples=total,
                generated_at=utc_now(),
                reasoning=(
                    f"no task_type met min_evidence={self._min_evidence} "
                    f"across {len(grouped)} candidate task_types"
                ),
                seam_status=PRE_EXECUTION_SIZING_SEAM_STATUS,
            )

        # Pre-compute per-group counts + costs so both the max-cost pass
        # and the scoring pass reuse the same intermediate values.
        stats: dict[str, dict[str, Any]] = {}
        for tt, group in qualifying.items():
            accepted = sum(1 for s in group if s.verdict == _VOTE_APPROVE)
            rejected = sum(1 for s in group if s.verdict == _VOTE_REJECT)
            mean_cost = mean(s.cost_usd for s in group)
            approval_rate = accepted / len(group)
            stats[tt] = {
                "accepted": accepted,
                "rejected": rejected,
                "mean_cost": mean_cost,
                "approval_rate": approval_rate,
            }

        max_cost = max((v["mean_cost"] for v in stats.values()), default=0.0)
        scores: list[TaskTypeScore] = []
        for tt, s in stats.items():
            if max_cost > 0.0:
                normalized_cost = s["mean_cost"] / max_cost
            else:
                normalized_cost = 0.0
            score = s["approval_rate"] - self._cost_weight * normalized_cost
            scores.append(TaskTypeScore(
                task_type=tt,
                accepted=int(s["accepted"]),
                rejected=int(s["rejected"]),
                mean_cost_usd=float(s["mean_cost"]),
                approval_rate=float(s["approval_rate"]),
                score=float(score),
            ))

        scores.sort(key=lambda x: x.score, reverse=True)
        top = scores[0]
        reasoning = (
            f"ranked {len(scores)} task_types by "
            f"approval_rate - {self._cost_weight}*normalized_cost; "
            f"top={top.task_type} score={top.score:.3f} "
            f"(approval_rate={top.approval_rate:.3f}, "
            f"mean_cost=${top.mean_cost_usd:.4f})"
        )
        return RoutingRecommendation(
            target_kind=target_kind,
            ranked_task_types=scores,
            total_samples=total,
            generated_at=utc_now(),
            reasoning=reasoning,
            seam_status=PRE_EXECUTION_SIZING_SEAM_STATUS,
        )

    async def recommend(
        self,
        target_kind: str,
        history_provider: HistoryProvider,
    ) -> RoutingRecommendation:
        """Async variant that fetches samples through a caller-supplied provider.

        The provider takes the ``target_kind`` and returns the sample
        sequence -- typically a SELECT joining the module's outcome +
        outcome_review + llm_cost tables. The learner never issues SQL
        itself so it stays generic over the module's outcome table.
        """
        samples = await history_provider(target_kind)
        return self.recommend_from_history(target_kind, samples)
