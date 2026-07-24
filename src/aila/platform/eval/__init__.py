"""Platform evaluation harness -- metrics, runner, storage records (RFC-08).

The pure metric layer (``metrics.py``) is dependency-free scoring. The
runner (``runner.py``) scores a candidate prompt version against a
benchmark of pre-scored cases, resolves the current production baseline
via ``PromptVersionStore``, and gates promotion through the strict-beat
gate on the resulting ``EvalReport``. Record-replay ingest against a
live agent loop is a later increment; this increment consumes cases
that have already been resolved by the operator.

RFC-08 self-improvement services (steps 1, 2, 3) sit alongside the
runner: :class:`ExperienceWriter` records signed patterns from review
verdicts, :class:`CalibrationProposer` produces versioned + reversible
threshold proposals from accept/reject history, and
:class:`RoutingLearner` scores task types by approval rate discounted
by cost. All three PROPOSE only; application is gated by the runner
plus the review quorum, per the propose-and-gate contract.
"""
from __future__ import annotations

from .calibration import (
    CALIBRATION_STATUS_ACTIVE,
    CALIBRATION_STATUS_REVERTED,
    CALIBRATION_STATUS_SUPERSEDED,
    CalibrationProposal,
    CalibrationProposalNotFoundError,
    CalibrationProposalRecord,
    CalibrationProposer,
    CalibrationSample,
)
from .experience_writer import (
    EXPERIENCE_POLARITY_KEY,
    EXPERIENCE_POLARITY_NEGATIVE,
    EXPERIENCE_POLARITY_POSITIVE,
    NEGATIVE_SUMMARY_PREFIX,
    ExperienceWriter,
    ExperienceWriteResult,
)
from .metrics import (
    CalibrationBucket,
    CaseOutcome,
    EvalReport,
    calibration_curve,
    determinism_score,
    ece,
    faithfulness_score,
    precision_recall_per_kind,
)
from .models import EvalBenchmarkRecord, EvalRunRecord
from .retrieval_metrics import (
    RetrievalCase,
    RetrievalCaseScore,
    RetrievalReport,
    aggregate_report,
    average_precision,
    dcg_at_k,
    mean_average_precision,
    mean_reciprocal_rank,
    ndcg_at_k,
    precision_at_k,
    recall_at_k,
    reciprocal_rank,
    score_case,
)
from .retrieval_models import (
    RetrievalBenchmarkRecord,
    RetrievalRunRecord,
)
from .retrieval_runner import (
    EmptyRetrievalBenchmarkError,
    RetrievalBenchmarkNotFoundError,
    RetrievalEvalRunner,
    RetrieveFn,
)
from .routing_learner import (
    PRE_EXECUTION_SIZING_SEAM_STATUS,
    RoutingLearner,
    RoutingRecommendation,
    RoutingSample,
    TaskTypeScore,
)
from .runner import (
    PRODUCTION_ALIAS,
    BenchmarkNotFoundError,
    EmptyCaseBundleError,
    EvalRunner,
)

__all__ = [
    "CALIBRATION_STATUS_ACTIVE",
    "CALIBRATION_STATUS_REVERTED",
    "CALIBRATION_STATUS_SUPERSEDED",
    "EXPERIENCE_POLARITY_KEY",
    "EXPERIENCE_POLARITY_NEGATIVE",
    "EXPERIENCE_POLARITY_POSITIVE",
    "NEGATIVE_SUMMARY_PREFIX",
    "PRE_EXECUTION_SIZING_SEAM_STATUS",
    "PRODUCTION_ALIAS",
    "BenchmarkNotFoundError",
    "CalibrationBucket",
    "EmptyRetrievalBenchmarkError",
    "RetrievalBenchmarkNotFoundError",
    "RetrievalBenchmarkRecord",
    "RetrievalCase",
    "RetrievalCaseScore",
    "RetrievalEvalRunner",
    "RetrievalReport",
    "RetrievalRunRecord",
    "RetrieveFn",
    "CalibrationProposal",
    "CalibrationProposalNotFoundError",
    "CalibrationProposalRecord",
    "CalibrationProposer",
    "CalibrationSample",
    "CaseOutcome",
    "EmptyCaseBundleError",
    "EvalBenchmarkRecord",
    "EvalReport",
    "EvalRunRecord",
    "EvalRunner",
    "ExperienceWriteResult",
    "ExperienceWriter",
    "RoutingLearner",
    "RoutingRecommendation",
    "RoutingSample",
    "TaskTypeScore",
    "calibration_curve",
    "aggregate_report",
    "average_precision",
    "dcg_at_k",
    "determinism_score",
    "ece",
    "faithfulness_score",
    "mean_average_precision",
    "mean_reciprocal_rank",
    "ndcg_at_k",
    "precision_at_k",
    "precision_recall_per_kind",
    "recall_at_k",
    "reciprocal_rank",
    "score_case",
]
