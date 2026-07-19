"""Tests for the C7 eval metrics (#32 / design metrics)."""
from __future__ import annotations

import pytest

from aila.platform.eval.metrics import (
    CaseOutcome,
    EvalReport,
    calibration_curve,
    determinism_score,
    ece,
    faithfulness_score,
    precision_recall_per_kind,
)


def test_ece_matches_hand_computed_value() -> None:
    # bucket0: conf .05 acc 1.0 -> err .95 (w .25)
    # bucket1: conf .15 acc 0.0 -> err .15 (w .25)
    # bucket9: conf .95 acc 0.5 -> err .45 (w .50)
    # ECE = .25*.95 + .25*.15 + .50*.45 = 0.5
    confidences = [0.05, 0.15, 0.95, 0.95]
    correct = [True, False, True, False]
    assert ece(confidences, correct) == pytest.approx(0.5, abs=1e-9)


def test_ece_perfect_calibration_is_zero() -> None:
    assert ece([1.0, 1.0, 0.0, 0.0], [True, True, False, False]) == pytest.approx(0.0, abs=1e-9)


def test_ece_empty_is_zero() -> None:
    assert ece([], []) == 0.0


def test_ece_length_mismatch_raises() -> None:
    with pytest.raises(ValueError):
        ece([0.5], [True, False])


def test_calibration_curve_omits_empty_buckets() -> None:
    curve = calibration_curve([0.05, 0.95, 0.95], [True, True, False])
    assert len(curve) == 2
    top = curve[-1]
    assert top.count == 2
    assert top.mean_confidence == pytest.approx(0.95)
    assert top.accuracy == pytest.approx(0.5)


def _cases() -> list[CaseOutcome]:
    return [
        CaseOutcome("sqli", "accept", "accept"),
        CaseOutcome("sqli", "accept", "reject"),
        CaseOutcome("sqli", "reject", "accept"),
        CaseOutcome("xss", "reject", "reject"),
    ]


def test_precision_recall_per_kind_basic() -> None:
    precision, recall = precision_recall_per_kind(_cases())
    assert precision["sqli"] == pytest.approx(0.5)
    assert recall["sqli"] == pytest.approx(0.5)


def test_precision_recall_zero_support_is_none() -> None:
    precision, recall = precision_recall_per_kind(_cases())
    # xss has no predicted-accept and no verified-accept -> both undefined.
    assert precision["xss"] is None
    assert recall["xss"] is None


def test_faithfulness_weighted_blend() -> None:
    # sqli weight 3/4, P=R=0.5; xss weight 1/4 contributes 0.
    # faithfulness = 0.75 * (0.5*0.5 + 0.5*0.5) = 0.375
    assert faithfulness_score(_cases()) == pytest.approx(0.375, abs=1e-9)


def test_determinism_partial_and_total() -> None:
    assert determinism_score([(1, "x"), (2, "y")], [(1, "x"), (2, "z")]) == pytest.approx(0.5)
    assert determinism_score([(1, "x")], [(1, "x"), (2, "y")]) == pytest.approx(0.5)
    assert determinism_score([(1, "x")], [(1, "x")]) == 1.0
    assert determinism_score([], []) == 1.0


def _report(**kw) -> EvalReport:
    base = {
        "ece": 0.2,
        "precision_by_kind": {"sqli": 0.9},
        "recall_by_kind": {"sqli": 0.9},
        "determinism_score": 1.0,
        "faithfulness_score": 0.9,
    }
    base.update(kw)
    return EvalReport(**base)


def test_beats_when_ece_lower_and_no_regression() -> None:
    baseline = _report()
    candidate = _report(ece=0.1)
    assert candidate.beats(baseline) is True


def test_recall_only_win_does_not_beat() -> None:
    baseline = _report()
    # Equal ECE, higher recall, higher faithfulness -- still fails (a).
    candidate = _report(recall_by_kind={"sqli": 0.95}, faithfulness_score=0.925)
    assert candidate.beats(baseline) is False


def test_precision_regression_beyond_tol_does_not_beat() -> None:
    baseline = _report()
    # ECE improves but precision drops 0.03 > tol 0.02.
    candidate = _report(ece=0.1, precision_by_kind={"sqli": 0.87})
    assert candidate.beats(baseline) is False


def test_faithfulness_drop_does_not_beat() -> None:
    baseline = _report()
    candidate = _report(ece=0.1, faithfulness_score=0.85)
    assert candidate.beats(baseline) is False
