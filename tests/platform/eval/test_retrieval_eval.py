"""Tests for the RFC-12 criterion 7 record-replay retrieval eval harness.

Covers three layers:

1. Pure metrics on hand-constructed ranked lists vs a known relevant set
   -- exact numeric assertions so a metric drift shows up as a failure.
2. The runner replays a benchmark through a fake ``retrieve_fn`` and
   persists a scored report row (create_all-backed DB fixture).
3. ``RetrievalReport.beats`` accepts a strict improvement and rejects a
   regression beyond tolerance so a retrieval change is eval-gated the
   same way a prompt change is.
"""
from __future__ import annotations

import json
import math
from collections.abc import AsyncGenerator, Sequence
from uuid import uuid4

import pytest
import pytest_asyncio
from sqlmodel import SQLModel

from aila.platform.eval.retrieval_metrics import (
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
from aila.platform.eval.retrieval_models import (
    RetrievalBenchmarkRecord,
    RetrievalRunRecord,
)
from aila.platform.eval.retrieval_runner import (
    EmptyRetrievalBenchmarkError,
    RetrievalBenchmarkNotFoundError,
    RetrievalEvalRunner,
)

# ---------------------------------------------------------------------------
# Pure metric assertions on hand-computed fixtures
# ---------------------------------------------------------------------------

def test_precision_at_k_top_two_of_three_relevant() -> None:
    ranked = ["a", "b", "c", "d"]
    relevant = {"a", "c", "e"}
    assert precision_at_k(ranked, relevant, k=3) == pytest.approx(2.0 / 3.0)


def test_precision_at_k_no_hits_is_zero() -> None:
    assert precision_at_k(["a", "b"], {"z"}, k=2) == 0.0


def test_precision_at_k_truncated_result_penalises() -> None:
    ranked = ["a"]
    assert precision_at_k(ranked, {"a"}, k=5) == pytest.approx(1.0 / 5.0)


def test_precision_at_k_requires_positive_k() -> None:
    with pytest.raises(ValueError):
        precision_at_k(["a"], {"a"}, k=0)


def test_recall_at_k_captures_two_of_three() -> None:
    ranked = ["a", "b", "c", "d"]
    relevant = {"a", "c", "e"}
    assert recall_at_k(ranked, relevant, k=3) == pytest.approx(2.0 / 3.0)


def test_recall_at_k_no_relevant_ids_is_zero() -> None:
    assert recall_at_k(["a"], set(), k=3) == 0.0


def test_reciprocal_rank_second_position_gives_half() -> None:
    assert reciprocal_rank(["x", "a", "b"], {"a"}) == pytest.approx(0.5)


def test_reciprocal_rank_no_hit_is_zero() -> None:
    assert reciprocal_rank(["x", "y"], {"a"}) == 0.0


def test_mean_reciprocal_rank_averages_over_queries() -> None:
    pairs = [
        (["a", "b"], {"a"}),
        (["x", "y", "z"], {"z"}),
        (["p", "q"], {"m"}),
    ]
    expected = (1.0 + (1.0 / 3.0) + 0.0) / 3.0
    assert mean_reciprocal_rank(pairs) == pytest.approx(expected)


def test_dcg_and_ndcg_hand_computed() -> None:
    ranked = ["a", "x", "c"]
    relevant = {"a", "c"}
    expected_dcg = 1.0 / math.log2(2) + 1.0 / math.log2(4)
    ideal_dcg = 1.0 / math.log2(2) + 1.0 / math.log2(3)
    assert dcg_at_k(ranked, relevant, k=3) == pytest.approx(expected_dcg)
    assert ndcg_at_k(ranked, relevant, k=3) == pytest.approx(
        expected_dcg / ideal_dcg,
    )


def test_ndcg_perfect_ordering_is_one() -> None:
    assert ndcg_at_k(["a", "b", "x"], {"a", "b"}, k=3) == pytest.approx(1.0)


def test_average_precision_perfect_and_partial() -> None:
    perfect = average_precision(["a", "b"], {"a", "b"})
    assert perfect == pytest.approx(1.0)
    partial = average_precision(["x", "a", "y", "b"], {"a", "b"})
    expected = ((1.0 / 2.0) + (2.0 / 4.0)) / 2.0
    assert partial == pytest.approx(expected)


def test_mean_average_precision_averages_over_queries() -> None:
    pairs = [
        (["a", "b"], {"a", "b"}),
        (["x", "a"], {"a"}),
    ]
    assert mean_average_precision(pairs) == pytest.approx((1.0 + 0.5) / 2.0)


def test_score_case_bundles_every_metric() -> None:
    case = RetrievalCase(
        query_id="q1", query="sqli mitigation",
        relevant_ids=frozenset({"a", "c"}),
    )
    scored = score_case(case, ["a", "x", "c"], k=3)
    assert scored.precision_at_k == pytest.approx(2.0 / 3.0)
    assert scored.recall_at_k == pytest.approx(1.0)
    assert scored.reciprocal_rank == pytest.approx(1.0)
    assert scored.ndcg_at_k > 0.0
    assert scored.average_precision > 0.0


def test_aggregate_report_means_and_shape() -> None:
    scores = [
        RetrievalCaseScore(
            query_id="q1", ranked_ids=("a",),
            precision_at_k=1.0, recall_at_k=1.0,
            reciprocal_rank=1.0, ndcg_at_k=1.0, average_precision=1.0,
        ),
        RetrievalCaseScore(
            query_id="q2", ranked_ids=("x",),
            precision_at_k=0.0, recall_at_k=0.0,
            reciprocal_rank=0.0, ndcg_at_k=0.0, average_precision=0.0,
        ),
    ]
    report = aggregate_report(scores, k=1)
    assert report.n_queries == 2
    assert report.precision_at_k == pytest.approx(0.5)
    assert report.recall_at_k == pytest.approx(0.5)
    assert report.mrr == pytest.approx(0.5)
    assert report.ndcg_at_k == pytest.approx(0.5)
    assert report.map_score == pytest.approx(0.5)
    assert len(report.per_case) == 2


# ---------------------------------------------------------------------------
# beats() gate: accept improvement, reject regression
# ---------------------------------------------------------------------------

def _report(**overrides: float) -> RetrievalReport:
    base: dict[str, float | int] = {
        "k": 5, "n_queries": 4,
        "precision_at_k": 0.6, "recall_at_k": 0.6,
        "mrr": 0.6, "ndcg_at_k": 0.6, "map_score": 0.6,
    }
    base.update(overrides)
    return RetrievalReport(
        k=int(base["k"]), n_queries=int(base["n_queries"]),
        precision_at_k=float(base["precision_at_k"]),
        recall_at_k=float(base["recall_at_k"]),
        mrr=float(base["mrr"]),
        ndcg_at_k=float(base["ndcg_at_k"]),
        map_score=float(base["map_score"]),
        per_case=(),
    )


def test_beats_accepts_strict_improvement_without_regression() -> None:
    baseline = _report()
    candidate = _report(mrr=0.7)
    assert candidate.beats(baseline) is True


def test_beats_rejects_regression_beyond_tolerance() -> None:
    baseline = _report()
    candidate = _report(mrr=0.7, precision_at_k=0.5)
    assert candidate.beats(baseline, regression_tol=0.05) is False


def test_beats_tolerates_small_regression_within_tolerance() -> None:
    baseline = _report()
    candidate = _report(mrr=0.7, precision_at_k=0.59)
    assert candidate.beats(baseline, regression_tol=0.02) is True


def test_beats_rejects_no_change() -> None:
    assert _report().beats(_report()) is False


def test_beats_rejects_recall_only_regression() -> None:
    baseline = _report()
    candidate = _report(recall_at_k=0.4)
    assert candidate.beats(baseline) is False


def test_beats_negative_tolerance_raises() -> None:
    with pytest.raises(ValueError):
        _report().beats(_report(), regression_tol=-0.1)


# ---------------------------------------------------------------------------
# Runner: replay through a fake retrieve_fn, persist, gate
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="session", autouse=True)
async def _create_retrieval_tables(
    _session_async_engine: object,
) -> AsyncGenerator[None, None]:
    """Ensure retrieval-eval tables exist on the shared session engine.

    ``_session_async_engine`` runs ``create_all`` once at first request;
    this autouse fixture re-issues it after our SQLModel classes are
    registered (via top-level import) so the two retrieval-eval tables
    land on the engine no matter which test collects first. Idempotent
    against existing tables.
    """
    engine = _session_async_engine
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    yield


def _make_cases() -> list[dict[str, object]]:
    return [
        {"query_id": "q1", "query": "sqli mitigation",
         "relevant_ids": ["a", "c"]},
        {"query_id": "q2", "query": "xss csp",
         "relevant_ids": ["b"]},
        {"query_id": "q3", "query": "auth bypass",
         "relevant_ids": ["d", "e"]},
    ]


def _make_retriever(
    responses: dict[str, Sequence[str]],
) -> object:
    """Build a sync retrieve_fn returning canned rankings per query_id."""
    def _fn(query: str, k: int) -> Sequence[str]:
        del k
        for entry in _make_cases():
            if entry["query"] == query:
                return responses[str(entry["query_id"])]
        return []
    return _fn


@pytest.mark.asyncio
async def test_runner_scores_replay_and_persists_report(
    test_db: None,
) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    key = f"knowledge/hybrid-{uuid4().hex[:8]}"
    benchmark = await runner.register_benchmark(
        key=key, name="hybrid-baseline",
        cases=_make_cases(), k=3, created_by="tester",
    )
    perfect = _make_retriever({
        "q1": ["a", "c", "x"],
        "q2": ["b", "y", "z"],
        "q3": ["d", "e", "w"],
    })
    run = await runner.run(
        key=key, benchmark_id=benchmark.id,
        candidate_label="candidate-v1",
        candidate_retrieve_fn=perfect,
        actor="tester",
    )
    assert isinstance(run, RetrievalRunRecord)
    assert run.verdict == "pass"
    assert run.baseline_label is None
    payload = json.loads(run.report_json)
    assert payload["baseline"] is None
    candidate = payload["candidate"]
    assert candidate["n_queries"] == 3
    assert candidate["mrr"] == pytest.approx(1.0)
    assert candidate["recall_at_k"] == pytest.approx(1.0)


@pytest.mark.asyncio
async def test_runner_gates_regression_against_baseline(test_db: None) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    key = f"knowledge/hybrid-{uuid4().hex[:8]}"
    benchmark = await runner.register_benchmark(
        key=key, name="hybrid-vs-vector-only",
        cases=_make_cases(), k=3,
    )
    baseline = _make_retriever({
        "q1": ["a", "c", "x"],
        "q2": ["b", "y", "z"],
        "q3": ["d", "e", "w"],
    })
    worse = _make_retriever({
        "q1": ["x", "y", "z"],
        "q2": ["b", "y", "z"],
        "q3": ["w", "v", "u"],
    })
    run = await runner.run(
        key=key, benchmark_id=benchmark.id,
        candidate_label="candidate-vector-only",
        candidate_retrieve_fn=worse,
        baseline_label="baseline-hybrid",
        baseline_retrieve_fn=baseline,
    )
    assert run.verdict == "fail"
    assert run.baseline_label == "baseline-hybrid"
    payload = json.loads(run.report_json)
    assert payload["baseline"] is not None
    assert payload["candidate"]["mrr"] < payload["baseline"]["mrr"]


@pytest.mark.asyncio
async def test_runner_accepts_improvement_against_baseline(
    test_db: None,
) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    key = f"knowledge/hybrid-{uuid4().hex[:8]}"
    benchmark = await runner.register_benchmark(
        key=key, name="hybrid-improvement",
        cases=_make_cases(), k=3,
    )
    baseline = _make_retriever({
        "q1": ["x", "a", "c"],
        "q2": ["z", "b"],
        "q3": ["w", "d", "e"],
    })
    better = _make_retriever({
        "q1": ["a", "c", "x"],
        "q2": ["b", "z", "y"],
        "q3": ["d", "e", "w"],
    })
    run = await runner.run(
        key=key, benchmark_id=benchmark.id,
        candidate_label="candidate-hybrid-plus-rerank",
        candidate_retrieve_fn=better,
        baseline_label="baseline-hybrid",
        baseline_retrieve_fn=baseline,
    )
    assert run.verdict == "pass"
    payload = json.loads(run.report_json)
    assert payload["candidate"]["mrr"] > payload["baseline"]["mrr"]


@pytest.mark.asyncio
async def test_runner_missing_benchmark_raises(test_db: None) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    with pytest.raises(RetrievalBenchmarkNotFoundError):
        await runner.run(
            key="knowledge/hybrid",
            benchmark_id=str(uuid4()),
            candidate_label="candidate",
            candidate_retrieve_fn=_make_retriever({}),
        )


@pytest.mark.asyncio
async def test_register_benchmark_rejects_empty_cases(test_db: None) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    with pytest.raises(EmptyRetrievalBenchmarkError):
        await runner.register_benchmark(
            key="knowledge/hybrid", name="empty", cases=[], k=3,
        )


@pytest.mark.asyncio
async def test_runner_first_eval_auto_passes_without_baseline(
    test_db: None,
) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    key = f"knowledge/hybrid-{uuid4().hex[:8]}"
    benchmark = await runner.register_benchmark(
        key=key, name="first-eval",
        cases=_make_cases(), k=3,
    )
    run = await runner.run(
        key=key, benchmark_id=benchmark.id,
        candidate_label="candidate-first",
        candidate_retrieve_fn=_make_retriever({
            "q1": ["a", "c"],
            "q2": ["b"],
            "q3": ["d", "e"],
        }),
        first_eval_auto_passes=True,
    )
    assert run.verdict == "pass"


@pytest.mark.asyncio
async def test_runner_baseline_only_verdict_when_opted_out(
    test_db: None,
) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    key = f"knowledge/hybrid-{uuid4().hex[:8]}"
    benchmark = await runner.register_benchmark(
        key=key, name="bootstrap",
        cases=_make_cases(), k=3,
    )
    run = await runner.run(
        key=key, benchmark_id=benchmark.id,
        candidate_label="candidate-bootstrap",
        candidate_retrieve_fn=_make_retriever({
            "q1": ["a"], "q2": ["b"], "q3": ["d"],
        }),
        first_eval_auto_passes=False,
    )
    assert run.verdict == "baseline_only"


@pytest.mark.asyncio
async def test_runner_accepts_async_retrieve_fn(test_db: None) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    key = f"knowledge/hybrid-{uuid4().hex[:8]}"
    benchmark = await runner.register_benchmark(
        key=key, name="async-retrieval",
        cases=_make_cases(), k=3,
    )

    async def _async_fn(query: str, k: int) -> Sequence[str]:
        del k
        table = {
            "sqli mitigation": ["a", "c"],
            "xss csp": ["b"],
            "auth bypass": ["d", "e"],
        }
        return table.get(query, [])

    run = await runner.run(
        key=key, benchmark_id=benchmark.id,
        candidate_label="candidate-async",
        candidate_retrieve_fn=_async_fn,
    )
    assert run.verdict == "pass"


@pytest.mark.asyncio
async def test_benchmark_row_round_trips_json(test_db: None) -> None:
    del test_db
    runner = RetrievalEvalRunner()
    key = f"knowledge/hybrid-{uuid4().hex[:8]}"
    record = await runner.register_benchmark(
        key=key, name="round-trip",
        cases=_make_cases(), k=5, created_by="tester",
    )
    assert isinstance(record, RetrievalBenchmarkRecord)
    assert record.k == 5
    parsed = json.loads(record.cases_json)
    assert len(parsed) == 3
    assert parsed[0]["query_id"] == "q1"
    assert parsed[0]["relevant_ids"] == ["a", "c"]
