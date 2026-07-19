"""Platform evaluation harness -- metrics and (later) record-replay (#32).

Only the pure metric layer is present today; the record-replay harness and
its storage records land with the #62 test backbone and #32 harness work.
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

__all__ = [
    "CalibrationBucket",
    "CaseOutcome",
    "EvalReport",
    "calibration_curve",
    "determinism_score",
    "ece",
    "faithfulness_score",
    "precision_recall_per_kind",
]
