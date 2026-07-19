"""Evaluation metrics for the C7 eval harness (#32 / design metrics).

Pure, dependency-free scoring functions consumed by the eval harness:

- ``ece`` -- expected calibration error (bucketed confidence vs outcome).
- ``calibration_curve`` -- the per-bucket reliability diagram behind ECE.
- ``precision_recall_per_kind`` -- precision and recall per outcome_kind,
  with zero-support kinds reported as ``None`` (not ``0.0``).
- ``faithfulness_score`` -- case-count-weighted blend of per-kind precision
  and recall.
- ``determinism_score`` -- fraction of replayed turns that match
  byte-for-byte across two replays.
- ``EvalReport`` + ``beats`` -- the promotion gate. A candidate beats the
  baseline only when its ECE is strictly lower, its faithfulness is at
  least equal, and no per-kind precision or recall drops beyond the
  regression tolerance. A recall-only win never beats the baseline
  (RFC-08 amendment 2).

Every function is deterministic and side-effect free so the harness and
the CI benchmark can call them without a database, clock, or model.
"""
from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

__all__ = [
    "CaseOutcome",
    "CalibrationBucket",
    "EvalReport",
    "calibration_curve",
    "determinism_score",
    "ece",
    "faithfulness_score",
    "precision_recall_per_kind",
]

_ACCEPT = "accept"


@dataclass(frozen=True, slots=True)
class CaseOutcome:
    """One scored benchmark case.

    ``predicted_verdict`` and ``verified_verdict`` are each ``"accept"`` or
    ``"reject"``; ``confidence`` is the candidate's stated probability in
    ``[0, 1]`` that its verdict is correct.
    """

    outcome_kind: str
    predicted_verdict: str
    verified_verdict: str
    confidence: float = 0.0


@dataclass(frozen=True, slots=True)
class CalibrationBucket:
    lo: float
    hi: float
    count: int
    mean_confidence: float
    accuracy: float


def _bucket_index(confidence: float, n_buckets: int) -> int:
    idx = int(confidence * n_buckets)
    if idx < 0:
        return 0
    if idx >= n_buckets:
        return n_buckets - 1
    return idx


def calibration_curve(
    confidences: Sequence[float],
    correct: Sequence[bool],
    n_buckets: int = 10,
) -> list[CalibrationBucket]:
    """Return the reliability diagram: one bucket per confidence band.

    Empty bands are omitted. ``correct[i]`` is whether prediction ``i`` was
    right (predicted verdict matched the verified verdict).
    """
    if n_buckets <= 0:
        raise ValueError("n_buckets must be positive")
    if len(confidences) != len(correct):
        raise ValueError("confidences and correct must be the same length")

    bins: list[list[tuple[float, bool]]] = [[] for _ in range(n_buckets)]
    for conf, ok in zip(confidences, correct, strict=True):
        bins[_bucket_index(conf, n_buckets)].append((conf, ok))

    curve: list[CalibrationBucket] = []
    for i, members in enumerate(bins):
        if not members:
            continue
        count = len(members)
        mean_conf = sum(c for c, _ in members) / count
        accuracy = sum(1 for _, ok in members if ok) / count
        curve.append(
            CalibrationBucket(
                lo=i / n_buckets,
                hi=(i + 1) / n_buckets,
                count=count,
                mean_confidence=mean_conf,
                accuracy=accuracy,
            )
        )
    return curve


def ece(
    confidences: Sequence[float],
    correct: Sequence[bool],
    n_buckets: int = 10,
) -> float:
    """Expected calibration error.

    ``ECE = sum_i (n_i / N) * |mean_confidence_i - accuracy_i|`` over the
    non-empty confidence buckets. Overconfident-and-wrong buckets drive it
    up. Returns ``0.0`` for an empty input.
    """
    total = len(confidences)
    if total == 0:
        return 0.0
    error = 0.0
    for bucket in calibration_curve(confidences, correct, n_buckets):
        error += (bucket.count / total) * abs(bucket.mean_confidence - bucket.accuracy)
    return error


def precision_recall_per_kind(
    cases: Sequence[CaseOutcome],
) -> tuple[dict[str, float | None], dict[str, float | None]]:
    """Precision and recall per outcome_kind, treating ``accept`` as positive.

    A kind with no predicted-accept cases has undefined precision (``None``);
    a kind with no verified-accept cases has undefined recall (``None``).
    """
    tp: Counter[str] = Counter()
    predicted_pos: Counter[str] = Counter()
    actual_pos: Counter[str] = Counter()
    kinds: set[str] = set()

    for case in cases:
        kinds.add(case.outcome_kind)
        pred_accept = case.predicted_verdict == _ACCEPT
        actual_accept = case.verified_verdict == _ACCEPT
        if pred_accept:
            predicted_pos[case.outcome_kind] += 1
        if actual_accept:
            actual_pos[case.outcome_kind] += 1
        if pred_accept and actual_accept:
            tp[case.outcome_kind] += 1

    precision: dict[str, float | None] = {}
    recall: dict[str, float | None] = {}
    for kind in kinds:
        precision[kind] = (tp[kind] / predicted_pos[kind]) if predicted_pos[kind] else None
        recall[kind] = (tp[kind] / actual_pos[kind]) if actual_pos[kind] else None
    return precision, recall


def faithfulness_score(cases: Sequence[CaseOutcome], alpha: float = 0.5) -> float:
    """Case-count-weighted blend of per-kind precision and recall.

    ``faithfulness = sum_kind w_kind * (alpha * precision + (1 - alpha) * recall)``
    where ``w_kind`` is the kind's share of all cases. Undefined per-kind
    precision or recall (no support) contributes ``0.0`` for that term.
    """
    total = len(cases)
    if total == 0:
        return 0.0
    precision, recall = precision_recall_per_kind(cases)
    weights = Counter(case.outcome_kind for case in cases)
    score = 0.0
    for kind, weight in weights.items():
        p = precision[kind] or 0.0
        r = recall[kind] or 0.0
        score += (weight / total) * (alpha * p + (1.0 - alpha) * r)
    return score


def determinism_score(
    replay_a: Sequence[tuple[int, str]],
    replay_b: Sequence[tuple[int, str]],
) -> float:
    """Fraction of replayed turns matching byte-for-byte across two replays.

    Each replay is a sequence of ``(turn_number, response_json)`` pairs. A
    turn present in only one replay counts as a mismatch. Two empty replays
    score ``1.0`` (nothing diverged).
    """
    a = dict(replay_a)
    b = dict(replay_b)
    turns = set(a) | set(b)
    if not turns:
        return 1.0
    matches = sum(1 for t in turns if t in a and t in b and a[t] == b[t])
    return matches / len(turns)


@dataclass(frozen=True, slots=True)
class EvalReport:
    """Aggregate metrics for one bundle scored against a benchmark."""

    ece: float
    precision_by_kind: dict[str, float | None]
    recall_by_kind: dict[str, float | None]
    determinism_score: float
    faithfulness_score: float

    def beats(self, baseline: EvalReport, regression_tol: float = 0.02) -> bool:
        """Strict-beat gate against a baseline report.

        Beats only when (a) ECE is strictly lower, (b) faithfulness is at
        least equal, and (c) no per-kind precision or recall drops by more
        than ``regression_tol``. A recall-only improvement fails (a) and so
        never beats the baseline (RFC-08 amendment 2).
        """
        if not self.ece < baseline.ece:
            return False
        if self.faithfulness_score < baseline.faithfulness_score:
            return False
        if _regressed(self.precision_by_kind, baseline.precision_by_kind, regression_tol):
            return False
        if _regressed(self.recall_by_kind, baseline.recall_by_kind, regression_tol):
            return False
        return True


def _regressed(
    candidate: dict[str, float | None],
    baseline: dict[str, float | None],
    tol: float,
) -> bool:
    """True when any kind's candidate value drops below baseline minus tol."""
    for kind, base in baseline.items():
        cand = candidate.get(kind)
        if base is not None and cand is not None and cand < base - tol:
            return True
    return False
