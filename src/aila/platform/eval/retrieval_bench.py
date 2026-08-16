"""Retrieval-stack benchmark harness (issue #153).

Report-only measurement layer over the live routed retriever. Runs a
list of ``(query, positive)`` pairs through
:func:`aila.platform.eval.retrieval_live.make_retrieve_fn` /
:meth:`aila.platform.services.knowledge.KnowledgeService.retrieve_routed`
at a fixed ``k`` and prints an aggregate MAP@k / nDCG@k / cost-per-call
table so the current retrieval stack has a measurable baseline. No
promotion gate, no persisted rows, no schema change -- the runner in
``retrieval_runner`` is the gated path; this module is the eyeball
report.

Pair file shape (JSON)
----------------------

::

    {
      "k": 10,
      "namespace_patterns": ["*"],
      "route": "simple",
      "min_score": 0.0,
      "pairs": [
        {"query_id": "q1", "query": "how does foo work",
         "relevant_ids": ["kn-42", "kn-99"]},
        {"query_id": "q2", "query": "bar validation",
         "positive_snippet": "def validate_bar(x):"}
      ]
    }

A pair MUST carry either ``relevant_ids`` (list of knowledge entry
ids -- exact rank scoring) OR ``positive_snippet`` (a case-insensitive
substring searched in each hit's ``sanitized_content`` -- a hit counts
as relevant iff it contains the snippet). Both together are allowed;
the union is treated as the relevant set for that query. ``k``,
``namespace_patterns``, ``route``, and ``min_score`` are optional and
fall back to the module defaults documented on
:func:`run_benchmark`.

The metric definitions
----------------------

* ``MAP@k`` -- mean over queries of average precision computed on the
  full ranked list up to ``k``; every relevant hit at rank ``i``
  contributes ``P@i / |relevant|``.
* ``nDCG@k`` -- mean over queries of DCG@k / IDCG@k where the position
  discount is ``1 / log2(rank + 1)`` with binary relevance.
* ``cost_per_call`` -- wall-clock latency per query in milliseconds
  (mean + p50). The current shipped retriever is a local
  Model2Vec + BM25 + RRF stack with no external API calls, so the
  monetary cost is $0.00 per query; latency is the operator's cost
  proxy. When a future retriever adds a paid embedder / reranker,
  wire its USD-per-call through ``LLMCostRecord`` and add it here.
"""
from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import logging
import statistics
import sys
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aila.platform.eval.retrieval_live import make_retrieve_fn
from aila.platform.eval.retrieval_metrics import (
    RetrievalCase,
    RetrievalCaseScore,
    aggregate_report,
    score_case,
)

__all__ = [
    "BUNDLED_SAMPLE_PAIRS",
    "BenchPair",
    "BenchmarkResult",
    "DEFAULT_K",
    "DEFAULT_MIN_SCORE",
    "DEFAULT_NAMESPACE_PATTERNS",
    "DEFAULT_ROUTE",
    "format_report",
    "load_pairs",
    "main",
    "run_benchmark",
]

_log = logging.getLogger(__name__)

DEFAULT_K = 10
DEFAULT_NAMESPACE_PATTERNS: tuple[str, ...] = ("*",)
DEFAULT_ROUTE = "simple"
DEFAULT_MIN_SCORE = 0.0

# A tiny in-tree sample so ``python -m aila.platform.eval.retrieval_bench``
# is runnable with no operator-supplied file. The snippets target the
# retriever's substring path, so the harness has no dependency on any
# specific pre-seeded knowledge entry id. On a fresh dev database with
# no relevant content indexed the metrics ARE zero -- that is the
# correct baseline reading for an empty corpus.
BUNDLED_SAMPLE_PAIRS: tuple[dict[str, Any], ...] = (
    {
        "query_id": "sample-1",
        "query": "how does the retrieval gate sanitize hit content",
        "positive_snippet": "sanitized_content",
    },
    {
        "query_id": "sample-2",
        "query": "how are workflow states advanced",
        "positive_snippet": "advance",
    },
    {
        "query_id": "sample-3",
        "query": "config registry env override precedence",
        "positive_snippet": "ConfigRegistry",
    },
    {
        "query_id": "sample-4",
        "query": "personalized pagerank knowledge graph",
        "positive_snippet": "personalized_pagerank",
    },
)


@dataclass(frozen=True, slots=True)
class BenchPair:
    """One benchmark row.

    ``relevant_ids`` and ``positive_snippet`` describe the ground truth.
    At least one MUST be non-empty. When both are supplied the relevant
    set for that query is the union of the id set and the ids of any
    retrieved hits whose ``sanitized_content`` contains the snippet
    (case-insensitive substring), so a pair can express "these known
    ids PLUS anything whose content matches" in one row.
    """

    query_id: str
    query: str
    relevant_ids: frozenset[str] = frozenset()
    positive_snippet: str = ""


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    """Aggregate + per-case output of one benchmark run.

    ``per_case_ms`` retains one latency reading per query so a caller
    (or the printed table) can compute distribution stats without a
    second replay. ``retriever_label`` names the retrieval path that
    served the run so the table caption is self-describing.
    """

    k: int
    n_queries: int
    map_score: float
    ndcg_at_k: float
    recall_at_k: float
    precision_at_k: float
    mrr: float
    per_case_ms: tuple[float, ...] = field(default_factory=tuple)
    per_case: tuple[RetrievalCaseScore, ...] = field(default_factory=tuple)
    retriever_label: str = ""


def _parse_pair(entry: object) -> BenchPair:
    """Normalise one raw JSON pair entry into a :class:`BenchPair`."""
    if not isinstance(entry, dict):
        raise ValueError("each pair entry must be a JSON object")
    query_id = str(entry.get("query_id") or "").strip()
    query = str(entry.get("query") or "").strip()
    if not query_id or not query:
        raise ValueError("pair entries require non-empty query_id + query")
    raw_ids = entry.get("relevant_ids") or []
    if not isinstance(raw_ids, list):
        raise ValueError("relevant_ids must be a JSON list of strings")
    relevant = frozenset(str(r) for r in raw_ids)
    snippet = str(entry.get("positive_snippet") or "")
    if not relevant and not snippet:
        raise ValueError(
            f"pair {query_id!r} has neither relevant_ids nor positive_snippet",
        )
    return BenchPair(
        query_id=query_id,
        query=query,
        relevant_ids=relevant,
        positive_snippet=snippet,
    )


def load_pairs(path: str | Path) -> tuple[list[BenchPair], dict[str, Any]]:
    """Load benchmark pairs from a JSON file.

    Returns ``(pairs, meta)`` where ``meta`` is the top-level dict minus
    the ``pairs`` field, carrying the optional ``k``, ``route``,
    ``namespace_patterns``, and ``min_score`` overrides. A file whose
    top-level is a bare list is treated as ``{"pairs": [...]}``.
    """
    raw = Path(path).read_text(encoding="utf-8")
    parsed = json.loads(raw)
    if isinstance(parsed, list):
        parsed = {"pairs": parsed}
    if not isinstance(parsed, dict):
        raise ValueError("pair file must be a JSON list or object")
    raw_pairs = parsed.get("pairs")
    if not isinstance(raw_pairs, list) or not raw_pairs:
        raise ValueError("pair file must contain a non-empty 'pairs' list")
    pairs = [_parse_pair(entry) for entry in raw_pairs]
    meta = {k: v for k, v in parsed.items() if k != "pairs"}
    return pairs, meta


async def _retrieve_ids_with_latency(
    retrieve_fn: Callable[[str, int], Awaitable[Sequence[str]] | Sequence[str]],
    query: str,
    k: int,
) -> tuple[tuple[str, ...], float]:
    """Time one call to ``retrieve_fn`` and return ``(ranked_ids, ms)``."""
    start = time.perf_counter()
    raw = retrieve_fn(query, k)
    if inspect.isawaitable(raw):
        raw = await raw
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    ranked = tuple(str(rid) for rid in raw)
    return ranked, elapsed_ms


async def _retrieve_hits_with_latency(
    query: str,
    k: int,
    *,
    namespace_patterns: Sequence[str],
    route: str,
    min_score: float,
) -> tuple[list[dict[str, Any]], float]:
    """Snippet path: pull raw gated hits (with ``sanitized_content``).

    Bypasses ``make_retrieve_fn`` (which strips to ids) so the substring
    match can read the content field. Deferred import of
    ``KnowledgeService`` keeps the module importable in environments
    that never call the snippet path.
    """
    from aila.platform.services.knowledge import KnowledgeService

    start = time.perf_counter()
    routed = await KnowledgeService().retrieve_routed(
        query=query,
        route=route,
        limit=k,
        min_score=min_score,
        namespace_patterns=list(namespace_patterns),
    )
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    hits = [
        dict(hit)
        for hit in routed.get("results", [])
        if hit.get("id") is not None
    ]
    return hits, elapsed_ms


def _snippet_relevant_ids(
    hits: Sequence[dict[str, Any]], snippet: str,
) -> frozenset[str]:
    """Return the ids of hits whose gated content contains ``snippet``."""
    needle = snippet.strip().lower()
    if not needle:
        return frozenset()
    matched: set[str] = set()
    for hit in hits:
        content = str(hit.get("sanitized_content") or hit.get("content") or "")
        if needle in content.lower():
            matched.add(str(hit["id"]))
    return frozenset(matched)


async def _score_pair(
    pair: BenchPair,
    k: int,
    *,
    namespace_patterns: Sequence[str],
    route: str,
    min_score: float,
    id_only_retrieve_fn: Callable[
        [str, int], Awaitable[Sequence[str]] | Sequence[str],
    ],
) -> tuple[RetrievalCaseScore, float]:
    """Retrieve + score one pair, returning ``(case_score, latency_ms)``.

    Pairs with a ``positive_snippet`` need the hit content, so they go
    through the raw ``retrieve_routed`` path. Pure-id pairs use the
    shared ``make_retrieve_fn`` adapter unchanged, keeping this harness
    on the same live path the promotion runner replays.
    """
    if pair.positive_snippet:
        hits, elapsed_ms = await _retrieve_hits_with_latency(
            pair.query, k,
            namespace_patterns=namespace_patterns,
            route=route,
            min_score=min_score,
        )
        ranked_ids = tuple(str(hit["id"]) for hit in hits)
        derived_relevant = _snippet_relevant_ids(hits, pair.positive_snippet)
        relevant = pair.relevant_ids | derived_relevant
    else:
        ranked_ids, elapsed_ms = await _retrieve_ids_with_latency(
            id_only_retrieve_fn, pair.query, k,
        )
        relevant = pair.relevant_ids

    case = RetrievalCase(
        query_id=pair.query_id,
        query=pair.query,
        relevant_ids=relevant,
    )
    score = score_case(case, ranked_ids, k)
    return score, elapsed_ms


async def run_benchmark(
    pairs: Sequence[BenchPair],
    *,
    k: int = DEFAULT_K,
    namespace_patterns: Sequence[str] = DEFAULT_NAMESPACE_PATTERNS,
    route: str = DEFAULT_ROUTE,
    min_score: float = DEFAULT_MIN_SCORE,
    retriever_label: str = "",
) -> BenchmarkResult:
    """Score ``pairs`` against the live routed retriever at ``k``.

    Reuses :func:`make_retrieve_fn` for the id-only path so the metrics
    correspond to the identical adaptive retrieval the promotion runner
    replays. Snippet pairs read the same routed path directly to see
    hit content -- the two paths call
    ``KnowledgeService.retrieve_routed`` with the same parameters, so
    the latency reading is comparable across pair kinds.
    """
    if not pairs:
        raise ValueError("run_benchmark requires at least one pair")
    if k <= 0:
        raise ValueError("k must be positive")
    id_only_fn = make_retrieve_fn(
        namespace_patterns=list(namespace_patterns),
        min_score=min_score,
        route=route,
    )
    scores: list[RetrievalCaseScore] = []
    latencies: list[float] = []
    for pair in pairs:
        case_score, elapsed_ms = await _score_pair(
            pair, k,
            namespace_patterns=namespace_patterns,
            route=route,
            min_score=min_score,
            id_only_retrieve_fn=id_only_fn,
        )
        scores.append(case_score)
        latencies.append(elapsed_ms)

    report = aggregate_report(scores, k)
    label = retriever_label or (
        f"KnowledgeService.retrieve_routed(route={route!r}, "
        f"namespace_patterns={list(namespace_patterns)!r})"
    )
    return BenchmarkResult(
        k=report.k,
        n_queries=report.n_queries,
        map_score=report.map_score,
        ndcg_at_k=report.ndcg_at_k,
        recall_at_k=report.recall_at_k,
        precision_at_k=report.precision_at_k,
        mrr=report.mrr,
        per_case_ms=tuple(latencies),
        per_case=report.per_case,
        retriever_label=label,
    )


def _fmt_ms(values: Sequence[float]) -> str:
    """Return a compact ``mean / p50 / p95 ms`` string."""
    if not values:
        return "n/a"
    ordered = sorted(values)
    mean = statistics.fmean(values)
    p50 = ordered[len(ordered) // 2]
    p95_idx = max(0, int(round(0.95 * (len(ordered) - 1))))
    p95 = ordered[p95_idx]
    return f"mean={mean:7.2f}ms  p50={p50:7.2f}ms  p95={p95:7.2f}ms"


def format_report(result: BenchmarkResult) -> str:
    """Format ``result`` as a compact human-readable metrics table."""
    lines = [
        "Retrieval benchmark",
        "-" * 60,
        f"retriever   : {result.retriever_label}",
        f"queries     : {result.n_queries}",
        f"k           : {result.k}",
        "",
        f"MAP@{result.k:<3}      : {result.map_score:.4f}",
        f"nDCG@{result.k:<3}     : {result.ndcg_at_k:.4f}",
        f"Recall@{result.k:<3}   : {result.recall_at_k:.4f}",
        f"Precision@{result.k:<3}: {result.precision_at_k:.4f}",
        f"MRR         : {result.mrr:.4f}",
        "",
        f"latency     : {_fmt_ms(result.per_case_ms)}",
        "cost/call   : $0.0000  (local Model2Vec + BM25 + RRF; no paid API)",
        "-" * 60,
        "per-query breakdown:",
    ]
    for case, ms in zip(result.per_case, result.per_case_ms, strict=False):
        lines.append(
            f"  {case.query_id:<24}  "
            f"AP={case.average_precision:.3f}  "
            f"nDCG={case.ndcg_at_k:.3f}  "
            f"MRR={case.reciprocal_rank:.3f}  "
            f"lat={ms:7.2f}ms",
        )
    return "\n".join(lines)


def _parse_argv(argv: Sequence[str] | None) -> argparse.Namespace:
    """Parse CLI arguments for the ``__main__`` entrypoint."""
    parser = argparse.ArgumentParser(
        prog="python -m aila.platform.eval.retrieval_bench",
        description=(
            "Benchmark the live routed retriever against a JSON pair file "
            "and print MAP@k / nDCG@k / cost-per-call. With no positional "
            "argument the bundled sample runs so the module is smoke-runnable."
        ),
    )
    parser.add_argument(
        "pairs",
        nargs="?",
        default=None,
        help=(
            "Path to a JSON pair file (shape documented in the module "
            "docstring). Omit to use the bundled sample."
        ),
    )
    parser.add_argument(
        "--k",
        type=int,
        default=None,
        help=f"Retrieval depth k (default {DEFAULT_K}; file 'k' wins if set).",
    )
    parser.add_argument(
        "--route",
        type=str,
        default=None,
        help=f"Retrieval route (default {DEFAULT_ROUTE!r}).",
    )
    parser.add_argument(
        "--namespace-patterns",
        type=str,
        default=None,
        help=(
            "Comma-separated namespace glob(s) to scope retrieval to "
            f"(default {list(DEFAULT_NAMESPACE_PATTERNS)!r})."
        ),
    )
    parser.add_argument(
        "--min-score",
        type=float,
        default=None,
        help=f"Relevance floor (default {DEFAULT_MIN_SCORE}).",
    )
    return parser.parse_args(argv)


async def _main_async(args: argparse.Namespace) -> int:
    """CLI body: load pairs, run benchmark, print table."""
    if args.pairs is None:
        pairs = [_parse_pair(entry) for entry in BUNDLED_SAMPLE_PAIRS]
        meta: dict[str, Any] = {}
        source = "<bundled sample>"
    else:
        pairs, meta = load_pairs(args.pairs)
        source = str(args.pairs)

    k = args.k if args.k is not None else int(meta.get("k") or DEFAULT_K)
    route = args.route or str(meta.get("route") or DEFAULT_ROUTE)
    min_score = (
        args.min_score if args.min_score is not None
        else float(meta.get("min_score", DEFAULT_MIN_SCORE))
    )
    if args.namespace_patterns:
        namespace_patterns = tuple(
            p.strip() for p in args.namespace_patterns.split(",") if p.strip()
        )
    else:
        raw_ns = meta.get("namespace_patterns")
        if isinstance(raw_ns, list) and raw_ns:
            namespace_patterns = tuple(str(p) for p in raw_ns)
        else:
            namespace_patterns = DEFAULT_NAMESPACE_PATTERNS

    print(f"pairs source: {source}  ({len(pairs)} pairs)")
    result = await run_benchmark(
        pairs,
        k=k,
        namespace_patterns=namespace_patterns,
        route=route,
        min_score=min_score,
    )
    print(format_report(result))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Synchronous CLI entrypoint (thin wrapper over :func:`_main_async`)."""
    args = _parse_argv(argv)
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    sys.exit(main())
