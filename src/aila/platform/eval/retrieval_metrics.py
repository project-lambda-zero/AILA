"""Retrieval metrics for RFC-12 criterion 7 (record-replay retrieval eval).

Pure, dependency-free scoring functions computed from a ranked list of
retrieved ids against a known set of relevant ids per query:

- ``precision_at_k(ranked, relevant, k)`` -- fraction of the top ``k``
  ranked ids that are relevant (denominator is ``k``, unretrieved slots
  count as non-relevant so a truncated result penalises precision).
- ``recall_at_k(ranked, relevant, k)`` -- fraction of the relevant ids
  that appear in the top ``k`` (undefined when there are no relevant ids
  for a query; the aggregator elides those cases from the mean).
- ``reciprocal_rank(ranked, relevant)`` -- ``1/rank`` of the first
  relevant id in the full ranked list; ``0.0`` when none appear.
- ``mean_reciprocal_rank`` -- mean of per-query reciprocal ranks.
- ``dcg_at_k`` / ``ndcg_at_k`` -- binary-relevance discounted cumulative
  gain, normalised against the ideal ranking of the same relevant set.
- ``average_precision`` / ``mean_average_precision`` -- classical AP and
  MAP over the full ranked list, used inside the aggregate report.

``score_case`` scores one recorded query, ``aggregate_report`` folds a
list of per-case scores into a ``RetrievalReport`` with the standard
mean-per-query aggregate metrics plus a ``beats()`` gate. The gate
mirrors the RFC-08 prompt gate: no metric may regress beyond a
tolerance and at least one metric must strictly improve.

Every function is deterministic and side-effect free. The runner and
the CI benchmark call them without a database, clock, or model.
"""
from __future__ import annotations

import math
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

__all__ = [
    "RetrievalCase",
    "RetrievalCaseScore",
    "RetrievalReport",
    "aggregate_report",
    "average_precision",
    "dcg_at_k",
    "mean_average_precision",
    "mean_reciprocal_rank",
    "ndcg_at_k",
    "precision_at_k",
    "reciprocal_rank",
    "recall_at_k",
    "score_case",
]

_METRIC_FIELDS: tuple[str, ...] = (
    "precision_at_k",
    "recall_at_k",
    "mrr",
    "ndcg_at_k",
    "map_score",
)


@dataclass(frozen=True, slots=True)
class RetrievalCase:
    """One recorded query with the ground-truth relevant entry ids.

    ``query_id`` is the stable operator-supplied identifier used to
    correlate a case to its replayed score. ``relevant_ids`` is the set
    of knowledge entry ids that the operator has judged relevant to
    ``query``; missing any of them at retrieval time penalises recall,
    surfacing an unrelated id penalises precision.
    """

    query_id: str
    query: str
    relevant_ids: frozenset[str]


@dataclass(frozen=True, slots=True)
class RetrievalCaseScore:
    """Per-case metrics after one replay through a retrieve function."""

    query_id: str
    ranked_ids: tuple[str, ...]
    precision_at_k: float
    recall_at_k: float
    reciprocal_rank: float
    ndcg_at_k: float
    average_precision: float


def _validate_k(k: int) -> None:
    """Raise ``ValueError`` when ``k`` is not a positive int."""
    if k <= 0:
        raise ValueError("k must be positive")


def precision_at_k(
    ranked_ids: Sequence[str],
    relevant_ids: Iterable[str],
    k: int,
) -> float:
    """Precision at ``k``: hits in the top ``k`` divided by ``k``.

    Unretrieved slots count as non-relevant, so a caller returning
    fewer than ``k`` items is penalised. A caller returning zero items
    scores ``0.0`` at any positive ``k``.
    """
    _validate_k(k)
    top = list(ranked_ids)[:k]
    relevant = set(relevant_ids)
    if not top:
        return 0.0
    hits = sum(1 for rid in top if rid in relevant)
    return hits / k


def recall_at_k(
    ranked_ids: Sequence[str],
    relevant_ids: Iterable[str],
    k: int,
) -> float:
    """Recall at ``k``: hits in the top ``k`` divided by relevant count.

    A query with no relevant ids scores ``0.0`` (undefined recall is
    reported as zero so it never distorts an aggregate mean; the
    aggregator can elide such queries when computing means).
    """
    _validate_k(k)
    relevant = set(relevant_ids)
    if not relevant:
        return 0.0
    top_set = set(list(ranked_ids)[:k])
    hits = sum(1 for rid in relevant if rid in top_set)
    return hits / len(relevant)


def reciprocal_rank(
    ranked_ids: Sequence[str],
    relevant_ids: Iterable[str],
) -> float:
    """Reciprocal rank of the first relevant id in ``ranked_ids``.

    Returns ``1/rank`` for the first relevant hit (rank is 1-based).
    Returns ``0.0`` when no relevant id appears in the ranked list.
    """
    relevant = set(relevant_ids)
    if not relevant:
        return 0.0
    for rank, rid in enumerate(ranked_ids, start=1):
        if rid in relevant:
            return 1.0 / rank
    return 0.0


def mean_reciprocal_rank(
    pairs: Sequence[tuple[Sequence[str], Iterable[str]]],
) -> float:
    """Mean of per-query reciprocal ranks over ``pairs``.

    Each pair is ``(ranked_ids, relevant_ids)``. Returns ``0.0`` on an
    empty input so the aggregate is well-defined at zero queries.
    """
    if not pairs:
        return 0.0
    total = 0.0
    for ranked, relevant in pairs:
        total += reciprocal_rank(ranked, relevant)
    return total / len(pairs)


def dcg_at_k(
    ranked_ids: Sequence[str],
    relevant_ids: Iterable[str],
    k: int,
) -> float:
    """Binary-relevance discounted cumulative gain at ``k``.

    Position discount is ``1 / log2(rank + 1)`` with rank 1-based, so a
    relevant hit at rank 1 contributes ``1.0`` and later hits contribute
    less. Non-relevant slots contribute nothing.
    """
    _validate_k(k)
    relevant = set(relevant_ids)
    score = 0.0
    for rank, rid in enumerate(list(ranked_ids)[:k], start=1):
        if rid in relevant:
            score += 1.0 / math.log2(rank + 1)
    return score


def ndcg_at_k(
    ranked_ids: Sequence[str],
    relevant_ids: Iterable[str],
    k: int,
) -> float:
    """Normalised DCG at ``k``: ``DCG@k / IDCG@k``.

    The ideal DCG places every relevant id in the top positions up to
    ``k``; returns ``0.0`` when there are no relevant ids (undefined
    ratio) so the aggregator can average without special casing.
    """
    _validate_k(k)
    relevant = set(relevant_ids)
    if not relevant:
        return 0.0
    dcg = dcg_at_k(ranked_ids, relevant, k)
    ideal_hits = min(len(relevant), k)
    idcg = sum(1.0 / math.log2(rank + 1) for rank in range(1, ideal_hits + 1))
    return dcg / idcg if idcg > 0.0 else 0.0


def average_precision(
    ranked_ids: Sequence[str],
    relevant_ids: Iterable[str],
) -> float:
    """Average precision over the full ranked list (unbounded ``k``).

    ``AP = (sum over relevant hits of P@rank_of_hit) / |relevant|``.
    Rewards ranking relevant ids near the top and penalises trailing
    hits proportionally. Returns ``0.0`` when there are no relevant ids
    for the query so the aggregate mean stays finite.
    """
    relevant = set(relevant_ids)
    if not relevant:
        return 0.0
    hits = 0
    ap = 0.0
    for rank, rid in enumerate(ranked_ids, start=1):
        if rid in relevant:
            hits += 1
            ap += hits / rank
    return ap / len(relevant)


def mean_average_precision(
    pairs: Sequence[tuple[Sequence[str], Iterable[str]]],
) -> float:
    """Mean of per-query average precisions (classical MAP)."""
    if not pairs:
        return 0.0
    total = 0.0
    for ranked, relevant in pairs:
        total += average_precision(ranked, relevant)
    return total / len(pairs)


def score_case(
    case: RetrievalCase,
    ranked_ids: Sequence[str],
    k: int,
) -> RetrievalCaseScore:
    """Score one replayed case: compute all per-case metrics at once."""
    _validate_k(k)
    ranked_tuple = tuple(ranked_ids)
    return RetrievalCaseScore(
        query_id=case.query_id,
        ranked_ids=ranked_tuple,
        precision_at_k=precision_at_k(ranked_tuple, case.relevant_ids, k),
        recall_at_k=recall_at_k(ranked_tuple, case.relevant_ids, k),
        reciprocal_rank=reciprocal_rank(ranked_tuple, case.relevant_ids),
        ndcg_at_k=ndcg_at_k(ranked_tuple, case.relevant_ids, k),
        average_precision=average_precision(ranked_tuple, case.relevant_ids),
    )


@dataclass(frozen=True, slots=True)
class RetrievalReport:
    """Aggregate retrieval metrics for one replayed benchmark bundle.

    ``per_case`` retains every scored case so a later inspection can
    drill into which queries drove a regression. ``beats`` is the
    promotion gate: candidate must not regress any metric beyond
    ``regression_tol`` and must strictly improve at least one metric.
    Equal metrics on every axis therefore never beat -- a no-change
    replay is not an improvement.
    """

    k: int
    n_queries: int
    precision_at_k: float
    recall_at_k: float
    mrr: float
    ndcg_at_k: float
    map_score: float
    per_case: tuple[RetrievalCaseScore, ...] = field(default_factory=tuple)

    def beats(
        self,
        baseline: RetrievalReport,
        regression_tol: float = 0.02,
    ) -> bool:
        """Return True when candidate strictly improves without regression."""
        if regression_tol < 0.0:
            raise ValueError("regression_tol must be non-negative")
        improved = False
        for metric_name in _METRIC_FIELDS:
            cand = float(getattr(self, metric_name))
            base = float(getattr(baseline, metric_name))
            if cand < base - regression_tol:
                return False
            if cand > base:
                improved = True
        return improved


def aggregate_report(
    scores: Sequence[RetrievalCaseScore],
    k: int,
) -> RetrievalReport:
    """Aggregate per-case scores into a ``RetrievalReport`` at ``k``.

    Mean-per-query aggregation for every metric; empty input returns a
    zero-filled report so the runner can persist the fact that a replay
    saw zero cases without special-casing downstream.
    """
    _validate_k(k)
    if not scores:
        return RetrievalReport(
            k=k, n_queries=0,
            precision_at_k=0.0, recall_at_k=0.0,
            mrr=0.0, ndcg_at_k=0.0, map_score=0.0,
            per_case=(),
        )
    n = len(scores)
    total_p = sum(s.precision_at_k for s in scores)
    total_r = sum(s.recall_at_k for s in scores)
    total_rr = sum(s.reciprocal_rank for s in scores)
    total_ndcg = sum(s.ndcg_at_k for s in scores)
    total_ap = sum(s.average_precision for s in scores)
    return RetrievalReport(
        k=k, n_queries=n,
        precision_at_k=total_p / n,
        recall_at_k=total_r / n,
        mrr=total_rr / n,
        ndcg_at_k=total_ndcg / n,
        map_score=total_ap / n,
        per_case=tuple(scores),
    )
