"""Platform evaluation harness -- metrics, runner, storage records (RFC-08).

The pure metric layer (``metrics.py``) is dependency-free scoring. The
runner (``runner.py``) scores a candidate prompt version against a
benchmark of pre-scored cases, resolves the current production baseline
via ``PromptVersionStore``, and gates promotion through the strict-beat
gate on the resulting ``EvalReport``. Record-replay ingest against a
live agent loop is a later increment; this increment consumes cases
that have already been resolved by the operator.
"""
from __future__ import annotations

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
from .runner import (
    PRODUCTION_ALIAS,
    BenchmarkNotFoundError,
    EmptyCaseBundleError,
    EvalRunner,
)

__all__ = [
    "PRODUCTION_ALIAS",
    "BenchmarkNotFoundError",
    "CalibrationBucket",
    "CaseOutcome",
    "EmptyCaseBundleError",
    "EvalBenchmarkRecord",
    "EvalReport",
    "EvalRunRecord",
    "EvalRunner",
    "calibration_curve",
    "determinism_score",
    "ece",
    "faithfulness_score",
    "precision_recall_per_kind",
]
