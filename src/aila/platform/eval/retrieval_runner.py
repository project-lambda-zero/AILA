"""Retrieval eval runner: record-replay a benchmark and gate promotion.

RFC-12 criterion 7. The runner takes a ``retrieve_fn`` by injection so
it never imports a retrieval implementation. That keeps the harness
generic: today the candidate is ``KnowledgeService.retrieve`` bridged
through an adapter that returns ranked ids; tomorrow a hybrid or graph
retriever swaps in through the same injection point.

Runner flow
-----------
1. Load the benchmark row -- raise ``RetrievalBenchmarkNotFoundError``
   when absent.
2. Replay every recorded query through ``candidate_retrieve_fn`` at the
   benchmark's fixed ``k``; score each case; aggregate into a candidate
   ``RetrievalReport``.
3. When ``baseline_retrieve_fn`` is supplied, repeat the replay through
   it and aggregate a baseline ``RetrievalReport``. When it is None,
   the run has no comparison baseline for this event.
4. Verdict:
   - baseline supplied AND ``candidate.beats(baseline, tol)`` -> ``pass``
   - baseline supplied AND not-beats                          -> ``fail``
   - no baseline AND ``first_eval_auto_passes`` True          -> ``pass``
   - no baseline AND ``first_eval_auto_passes`` False         -> ``baseline_only``
5. Persist and return a ``RetrievalRunRecord`` with the serialized
   report bundle (candidate + baseline reports).

The runner never mutates a knowledge store; it only reads via the
injected retrieve function and writes its own audit rows.
"""
from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict

from sqlmodel import select

from aila.platform.eval.retrieval_metrics import (
    RetrievalCase,
    RetrievalCaseScore,
    RetrievalReport,
    aggregate_report,
    score_case,
)
from aila.platform.eval.retrieval_models import (
    RetrievalBenchmarkRecord,
    RetrievalRunRecord,
)
from aila.storage.database import async_session_scope

__all__ = [
    "EmptyRetrievalBenchmarkError",
    "RetrievalBenchmarkNotFoundError",
    "RetrievalEvalRunner",
    "RetrieveFn",
]

_log = logging.getLogger(__name__)

VERDICT_PASS = "pass"
VERDICT_FAIL = "fail"
VERDICT_BASELINE_ONLY = "baseline_only"

RetrieveFn = Callable[[str, int], Awaitable[Sequence[str]] | Sequence[str]]
"""Injection point for a retriever.

Takes a query string and ``k`` (fixed by the benchmark) and returns a
ranked sequence of knowledge entry ids -- the runner scores each id
against the recorded relevant set. Sync and async callables are both
accepted; the runner awaits the result when it is awaitable so the
production ``KnowledgeService.retrieve`` (async, ``list[dict]``) can be
adapted with a one-line lambda that maps dicts to ids.
"""


class RetrievalBenchmarkNotFoundError(LookupError):
    """Raised when a benchmark id resolves to no row."""


class EmptyRetrievalBenchmarkError(ValueError):
    """Raised when a benchmark has zero recorded cases (nothing to score)."""


def _parse_cases(cases_json: str) -> list[RetrievalCase]:
    """Deserialize ``cases_json`` into a list of ``RetrievalCase`` objects."""
    parsed = json.loads(cases_json)
    if not isinstance(parsed, list):
        raise ValueError("cases_json must decode to a JSON list")
    cases: list[RetrievalCase] = []
    for entry in parsed:
        if not isinstance(entry, dict):
            raise ValueError("each case entry must be a JSON object")
        raw_relevant = entry.get("relevant_ids", [])
        if not isinstance(raw_relevant, list):
            raise ValueError("relevant_ids must be a JSON list of strings")
        cases.append(RetrievalCase(
            query_id=str(entry["query_id"]),
            query=str(entry["query"]),
            relevant_ids=frozenset(str(r) for r in raw_relevant),
        ))
    return cases


def _report_to_dict(report: RetrievalReport) -> dict[str, object]:
    """Serialize a ``RetrievalReport`` to a JSON-safe dict.

    ``per_case`` frozenset fields become sorted lists so the resulting
    JSON is deterministic across runs; ranked_ids preserve retrieval
    order (it is meaningful for ranking metrics).
    """
    payload: dict[str, object] = {
        "k": report.k,
        "n_queries": report.n_queries,
        "precision_at_k": report.precision_at_k,
        "recall_at_k": report.recall_at_k,
        "mrr": report.mrr,
        "ndcg_at_k": report.ndcg_at_k,
        "map_score": report.map_score,
        "per_case": [asdict(s) for s in report.per_case],
    }
    return payload


async def _replay_case(
    case: RetrievalCase, retrieve_fn: RetrieveFn, k: int,
) -> RetrievalCaseScore:
    """Await the injected retriever for one case and score it."""
    raw = retrieve_fn(case.query, k)
    if inspect.isawaitable(raw):
        ranked = await raw
    else:
        ranked = raw
    ranked_seq: Sequence[str] = tuple(str(rid) for rid in ranked)
    return score_case(case, ranked_seq, k)


async def _replay_benchmark(
    cases: Sequence[RetrievalCase],
    retrieve_fn: RetrieveFn,
    k: int,
) -> RetrievalReport:
    """Replay every recorded case and aggregate a ``RetrievalReport``."""
    scores: list[RetrievalCaseScore] = []
    for case in cases:
        scores.append(await _replay_case(case, retrieve_fn, k))
    return aggregate_report(scores, k)


class RetrievalEvalRunner:
    """Register benchmarks and replay them through injected retrievers.

    Composed with a session factory via ``async_session_scope`` (same
    pattern as ``EvalRunner``); no shared unit-of-work handle is
    threaded through the runner. The runner owns the audit table and
    the promotion gate, not any retrieval implementation.
    """

    async def register_benchmark(
        self,
        *,
        key: str,
        name: str,
        cases: Sequence[dict[str, object]],
        k: int = 10,
        created_by: str = "",
    ) -> RetrievalBenchmarkRecord:
        """Persist a benchmark row from a list of case dicts.

        Each case is validated the same way ``run()`` will parse it, so
        a malformed entry fails at register time rather than at replay.
        Empty ``cases`` raises ``EmptyRetrievalBenchmarkError`` so a
        misconfigured benchmark never masquerades as a passing eval.
        """
        if k <= 0:
            raise ValueError("k must be positive")
        if not cases:
            raise EmptyRetrievalBenchmarkError(
                "cannot register a benchmark with zero cases",
            )
        normalized: list[dict[str, object]] = []
        for entry in cases:
            if not isinstance(entry, dict):
                raise TypeError("cases must be dict entries")
            raw_relevant = entry.get("relevant_ids", [])
            if not isinstance(raw_relevant, list):
                raise TypeError("relevant_ids must be a list of strings")
            normalized.append({
                "query_id": str(entry["query_id"]),
                "query": str(entry["query"]),
                "relevant_ids": [str(r) for r in raw_relevant],
            })
        record = RetrievalBenchmarkRecord(
            key=key, name=name, k=k,
            cases_json=json.dumps(normalized),
            created_by=created_by,
        )
        async with async_session_scope() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)
        return record

    async def _load_benchmark(self, benchmark_id: str) -> RetrievalBenchmarkRecord:
        """Fetch the benchmark row or raise the not-found error."""
        async with async_session_scope() as session:
            benchmark = (await session.exec(
                select(RetrievalBenchmarkRecord).where(
                    RetrievalBenchmarkRecord.id == benchmark_id,
                )
            )).first()
        if benchmark is None:
            raise RetrievalBenchmarkNotFoundError(
                f"no retrieval benchmark registered with id {benchmark_id!r}",
            )
        return benchmark

    async def run(
        self,
        *,
        key: str,
        benchmark_id: str,
        candidate_label: str,
        candidate_retrieve_fn: RetrieveFn,
        baseline_label: str | None = None,
        baseline_retrieve_fn: RetrieveFn | None = None,
        regression_tol: float = 0.02,
        first_eval_auto_passes: bool = True,
        actor: str = "",
    ) -> RetrievalRunRecord:
        """Replay ``benchmark_id`` through the candidate (and baseline).

        Raises ``RetrievalBenchmarkNotFoundError`` when the benchmark id
        does not exist. Raises ``EmptyRetrievalBenchmarkError`` when a
        persisted benchmark somehow has zero cases (defence in depth;
        ``register_benchmark`` blocks the empty case at intake).
        Returns the persisted ``RetrievalRunRecord``.
        """
        if not candidate_label:
            raise ValueError("candidate_label must be a non-empty string")
        benchmark = await self._load_benchmark(benchmark_id)
        cases = _parse_cases(benchmark.cases_json)
        if not cases:
            raise EmptyRetrievalBenchmarkError(
                f"benchmark {benchmark_id!r} has zero cases; nothing to score",
            )
        k = int(benchmark.k)

        candidate_report = await _replay_benchmark(
            cases, candidate_retrieve_fn, k,
        )

        baseline_report: RetrievalReport | None = None
        effective_baseline_label = baseline_label
        if baseline_retrieve_fn is not None:
            if not baseline_label:
                effective_baseline_label = "baseline"
            baseline_report = await _replay_benchmark(
                cases, baseline_retrieve_fn, k,
            )

        if baseline_report is not None:
            verdict = (
                VERDICT_PASS
                if candidate_report.beats(baseline_report, regression_tol)
                else VERDICT_FAIL
            )
        elif first_eval_auto_passes:
            _log.warning(
                "retrieval_eval.run first-ever eval for key=%s: no baseline "
                "retriever supplied, auto-passing candidate_label=%s",
                key, candidate_label,
            )
            verdict = VERDICT_PASS
        else:
            verdict = VERDICT_BASELINE_ONLY

        report_payload: dict[str, object] = {
            "candidate": _report_to_dict(candidate_report),
            "baseline": (
                _report_to_dict(baseline_report)
                if baseline_report is not None
                else None
            ),
            "regression_tol": regression_tol,
        }
        run_record = RetrievalRunRecord(
            key=key,
            benchmark_id=benchmark_id,
            candidate_label=candidate_label,
            baseline_label=effective_baseline_label,
            report_json=json.dumps(report_payload),
            verdict=verdict,
            actor=actor,
        )
        async with async_session_scope() as session:
            session.add(run_record)
            await session.commit()
            await session.refresh(run_record)
        return run_record

    async def list_runs(
        self, key: str, *, limit: int = 100,
    ) -> list[RetrievalRunRecord]:
        """List retrieval-eval runs for a key, newest first, bounded by limit."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        async with async_session_scope() as session:
            rows = (await session.exec(
                select(RetrievalRunRecord)
                .where(RetrievalRunRecord.key == key)
                .order_by(RetrievalRunRecord.created_at.desc())
                .limit(limit)
            )).all()
        return list(rows)
