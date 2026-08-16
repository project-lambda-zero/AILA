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
from typing import Any, Protocol

from aila.platform.eval.retrieval_live import make_retrieve_fn
from aila.platform.eval.retrieval_metrics import (
    RetrievalCase,
    RetrievalCaseScore,
    aggregate_report,
    score_case,
)

__all__ = [
    "BUNDLED_SAMPLE_PAIRS",
    "BackendAvailability",
    "BackendCall",
    "BackendCallError",
    "BackendReport",
    "BenchPair",
    "BenchmarkResult",
    "CompareRun",
    "DEFAULT_K",
    "DEFAULT_MIN_SCORE",
    "DEFAULT_NAMESPACE_PATTERNS",
    "DEFAULT_ROUTE",
    "DefaultLocalBackend",
    "JinaCodeBackend",
    "Qwen3RerankBackend",
    "RetrieverBackend",
    "VoyageCode3Backend",
    "format_compare_report",
    "format_report",
    "load_pairs",
    "main",
    "resolve_backends",
    "run_backend_benchmark",
    "run_benchmark",
    "run_compare",
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


# ---------------------------------------------------------------------------
# Pluggable retriever-backend interface (ENHANCEMENT #153 -- compare mode).
#
# The default local Model2Vec + BM25 + RRF stack is the always-available
# baseline (:class:`DefaultLocalBackend`, wraps ``retrieve_routed``). Alt
# backends (voyage-code-3, jina-code, Qwen3-Reranker) are OFF unless their
# API key / model / endpoint is configured via ``ConfigRegistry`` (schema
# keys ``retrieval_backend_voyage_api_key``,
# ``retrieval_backend_jina_api_key``, ``retrieval_backend_qwen_reranker_url``
# on :class:`aila.platform.config.PlatformConfigSchema`). Each alt backend
# fetches ``k * retrieval_backend_pool_multiplier`` candidates from the
# local retriever, sends them to its remote scorer, and returns the top-k
# reranked list -- so alt scores measure the alt scorer's ranking quality
# over the same candidate pool the local stack sees, with no requirement
# to re-embed the entire corpus.
#
# Every third-party HTTP call is guarded: a missing package, a network
# error, or a non-2xx response surfaces as a :class:`BackendCallError`
# and is reported as an ``error`` row in the compare table -- the CLI
# never crashes because one alt backend is unreachable.
# ---------------------------------------------------------------------------


class BackendCallError(RuntimeError):
    """Raised by an alt backend when a retrieval call cannot complete.

    The compare runner catches this per-backend and prints an ``error``
    line in the compare table rather than aborting the whole run.
    """


@dataclass(frozen=True, slots=True)
class BackendAvailability:
    """Result of :meth:`RetrieverBackend.availability`.

    ``available`` gates whether the compare runner calls the backend;
    ``reason`` is a short human-readable status ("always available",
    "unconfigured: set retrieval_backend_voyage_api_key", "voyageai
    package not installed") shown in the compare table.
    """

    available: bool
    reason: str


@dataclass(frozen=True, slots=True)
class BackendCall:
    """One retrieval call's ranked hits + timing + cost.

    ``hits`` is a list of dicts each carrying at minimum an ``id`` and a
    ``sanitized_content`` (or ``content``) field so the snippet-relevance
    path can score any backend uniformly. ``cost_usd`` is the estimated
    monetary cost of this specific call (0.0 for the local stack).
    """

    hits: tuple[dict[str, Any], ...]
    latency_ms: float
    cost_usd: float


class RetrieverBackend(Protocol):
    """Retriever backend contract for the compare harness.

    Two methods:

    * :meth:`availability` -- resolved once per run, tells the harness
      whether to invoke the backend and why not when skipped.
    * :meth:`retrieve_hits` -- called once per benchmark pair, returns
      the ranked hits + measured latency + cost estimate for the call.

    ``name`` is a short slug used to key the compare table row;
    ``label`` is the human-facing display string in the table caption.
    """

    name: str
    label: str

    async def availability(self) -> BackendAvailability: ...

    async def retrieve_hits(
        self,
        query: str,
        k: int,
        *,
        namespace_patterns: Sequence[str],
        route: str,
        min_score: float,
    ) -> BackendCall: ...


@dataclass(frozen=True, slots=True)
class BackendReport:
    """One backend's slot in the compare table.

    ``result`` is populated iff ``availability.available`` was True AND
    every retrieve call succeeded. ``error`` is populated iff a call
    raised :class:`BackendCallError`.
    """

    name: str
    label: str
    availability: BackendAvailability
    result: BenchmarkResult | None = None
    total_cost_usd: float = 0.0
    error: str = ""


@dataclass(frozen=True, slots=True)
class CompareRun:
    """Full compare-mode output: one :class:`BackendReport` per backend."""

    k: int
    n_queries: int
    reports: tuple[BackendReport, ...]


def _tokens_estimate(text: str) -> int:
    """Rough token count for cost estimation (~4 characters per token).

    Deliberate approximation: the cost column is an order-of-magnitude
    signal for the operator, not an accounting figure. Real spend is
    tracked through the LLM cost layer once a backend gets promoted
    from benchmark to live-serve.
    """
    return max(1, (len(text) + 3) // 4)


class DefaultLocalBackend:
    """Baseline backend -- the current live Model2Vec + BM25 + RRF stack.

    Always available; wraps :func:`_retrieve_hits_with_latency` so the
    compare-mode baseline row is byte-identical to the single-backend
    ``run_benchmark`` result.
    """

    name = "local_default"
    label = "local Model2Vec + BM25 + RRF (retrieve_routed)"

    async def availability(self) -> BackendAvailability:
        return BackendAvailability(True, "always available (local, no external calls)")

    async def retrieve_hits(
        self,
        query: str,
        k: int,
        *,
        namespace_patterns: Sequence[str],
        route: str,
        min_score: float,
    ) -> BackendCall:
        hits, elapsed_ms = await _retrieve_hits_with_latency(
            query, k,
            namespace_patterns=namespace_patterns,
            route=route,
            min_score=min_score,
        )
        return BackendCall(tuple(hits), elapsed_ms, 0.0)


async def _fetch_local_pool(
    query: str,
    k: int,
    *,
    pool_multiplier: int,
    namespace_patterns: Sequence[str],
    route: str,
    min_score: float,
) -> tuple[list[dict[str, Any]], float]:
    """Shared helper: pull the local candidate pool for an alt backend.

    Returns ``(hits, base_latency_ms)`` where ``hits`` is at least the
    top ``k * pool_multiplier`` results from the local routed retriever.
    An empty pool short-circuits the rerank -- there is nothing to score
    and the alt backend returns an empty result at the shared cost of
    the local call.
    """
    pool_size = max(k, k * max(1, int(pool_multiplier)))
    hits, elapsed_ms = await _retrieve_hits_with_latency(
        query, pool_size,
        namespace_patterns=namespace_patterns,
        route=route,
        min_score=min_score,
    )
    return hits, elapsed_ms


def _hit_content(hit: dict[str, Any]) -> str:
    """Best-effort content extraction from a routed hit for reranking."""
    return str(hit.get("sanitized_content") or hit.get("content") or "")


def _cosine(a: Sequence[float], b: Sequence[float]) -> float:
    """Cosine similarity of two equal-length vectors; 0.0 on degenerate input."""
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = 0.0
    norm_a = 0.0
    norm_b = 0.0
    for x, y in zip(a, b, strict=True):
        dot += x * y
        norm_a += x * x
        norm_b += y * y
    if norm_a <= 0.0 or norm_b <= 0.0:
        return 0.0
    import math

    return dot / (math.sqrt(norm_a) * math.sqrt(norm_b))


async def _post_json(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str],
    timeout: float,
    backend_name: str,
) -> dict[str, Any]:
    """POST JSON to ``url`` and return the parsed body.

    Import ``httpx`` at call time so importing the harness module does
    not force any network transport into memory on a base install (and
    keeps a hypothetical future ``[eval-retrieval]`` extra optional).
    Every failure mode (import, connect, HTTP status, JSON parse) is
    surfaced as :class:`BackendCallError` with the backend name in the
    message so the compare table can attribute the failure.
    """
    try:
        import httpx
    except ImportError as exc:  # pragma: no cover -- httpx is a base dep
        raise BackendCallError(f"{backend_name}: httpx unavailable ({exc})") from exc

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(url, json=payload, headers=headers)
    except (httpx.HTTPError, OSError) as exc:
        raise BackendCallError(f"{backend_name}: HTTP transport error ({exc})") from exc

    if response.status_code // 100 != 2:
        body = response.text[:200].replace("\n", " ")
        raise BackendCallError(
            f"{backend_name}: HTTP {response.status_code} -- {body}",
        )

    try:
        return response.json()
    except ValueError as exc:
        raise BackendCallError(f"{backend_name}: response was not JSON ({exc})") from exc


class _EmbeddingRerankBackend:
    """Shared base for embedding-based rerank backends (voyage, jina).

    Concrete subclasses supply :meth:`_embed`, which returns
    ``(query_vector, doc_vectors, cost_usd)`` for a batch of texts. The
    base handles pool fetching, cosine reranking, and result packaging.
    """

    name: str = "abstract"
    label: str = "abstract embedding rerank backend"
    pool_multiplier: int = 5

    async def _embed(
        self, query: str, docs: Sequence[str],
    ) -> tuple[list[float], list[list[float]], float]:
        raise NotImplementedError

    async def retrieve_hits(
        self,
        query: str,
        k: int,
        *,
        namespace_patterns: Sequence[str],
        route: str,
        min_score: float,
    ) -> BackendCall:
        pool, pool_ms = await _fetch_local_pool(
            query, k,
            pool_multiplier=self.pool_multiplier,
            namespace_patterns=namespace_patterns,
            route=route,
            min_score=min_score,
        )
        if not pool:
            return BackendCall(hits=(), latency_ms=pool_ms, cost_usd=0.0)

        docs = [_hit_content(h) for h in pool]
        start = time.perf_counter()
        query_vec, doc_vecs, cost_usd = await self._embed(query, docs)
        rerank_ms = (time.perf_counter() - start) * 1000.0
        if not doc_vecs or len(doc_vecs) != len(pool):
            raise BackendCallError(
                f"{self.name}: embedding count {len(doc_vecs)} != pool size {len(pool)}",
            )
        scored: list[tuple[float, dict[str, Any]]] = [
            (_cosine(query_vec, vec), hit)
            for hit, vec in zip(pool, doc_vecs, strict=True)
        ]
        scored.sort(key=lambda pair: pair[0], reverse=True)
        top = tuple(hit for _, hit in scored[:k])
        return BackendCall(hits=top, latency_ms=pool_ms + rerank_ms, cost_usd=cost_usd)


@dataclass(frozen=True, slots=True)
class VoyageCode3Backend(_EmbeddingRerankBackend):
    """voyage-code-3 embedding rerank over the local candidate pool.

    Activated when ``retrieval_backend_voyage_api_key`` is set. Calls
    the public v1 embeddings endpoint twice per query: once for the
    query (``input_type=query``), once for the candidate pool
    (``input_type=document``). Cost is estimated from the returned
    ``usage.total_tokens`` field at the public voyage-code-3 rate.
    """

    api_key: str = ""
    model: str = "voyage-code-3"
    base_url: str = "https://api.voyageai.com/v1"
    pool_multiplier: int = 5
    timeout_s: float = 30.0
    # Public voyage-code-3 price as of the field review cited in issue
    # #153 (2024-12 blog announcement + current pricing page): $0.18
    # per 1M tokens. If Voyage rolls a new price the operator can bump
    # this constant; the compare column is an order-of-magnitude signal.
    price_per_million_tokens: float = 0.18

    name = "voyage_code_3"
    label = "voyage-code-3 (rerank over local pool)"

    async def availability(self) -> BackendAvailability:
        if not self.api_key.strip():
            return BackendAvailability(
                False,
                "unconfigured: set retrieval_backend_voyage_api_key",
            )
        return BackendAvailability(
            True,
            f"configured (model={self.model!r}, base_url={self.base_url!r})",
        )

    async def _embed(
        self, query: str, docs: Sequence[str],
    ) -> tuple[list[float], list[list[float]], float]:
        url = f"{self.base_url.rstrip('/')}/embeddings"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        total_tokens = 0

        query_resp = await _post_json(
            url,
            {"model": self.model, "input": [query], "input_type": "query"},
            headers=headers, timeout=self.timeout_s, backend_name=self.name,
        )
        query_vec = _extract_voyage_vector(query_resp, 0, self.name)
        total_tokens += int((query_resp.get("usage") or {}).get("total_tokens") or 0)

        doc_resp = await _post_json(
            url,
            {"model": self.model, "input": list(docs), "input_type": "document"},
            headers=headers, timeout=self.timeout_s, backend_name=self.name,
        )
        doc_vecs = [_extract_voyage_vector(doc_resp, i, self.name) for i in range(len(docs))]
        total_tokens += int((doc_resp.get("usage") or {}).get("total_tokens") or 0)

        # Estimation fallback when the API omits usage: sum char-based
        # token estimates so a broken usage payload does not silently
        # zero out the cost column.
        if total_tokens <= 0:
            total_tokens = _tokens_estimate(query) + sum(_tokens_estimate(d) for d in docs)
        cost = (total_tokens / 1_000_000.0) * self.price_per_million_tokens
        return query_vec, doc_vecs, cost


def _extract_voyage_vector(
    payload: dict[str, Any], index: int, backend_name: str,
) -> list[float]:
    """Pull ``data[index].embedding`` from a Voyage-shaped embeddings response."""
    data = payload.get("data")
    if not isinstance(data, list) or len(data) <= index:
        raise BackendCallError(
            f"{backend_name}: embeddings response missing data[{index}]",
        )
    row = data[index]
    embedding = row.get("embedding") if isinstance(row, dict) else None
    if not isinstance(embedding, list):
        raise BackendCallError(
            f"{backend_name}: embeddings response entry {index} has no vector",
        )
    return [float(x) for x in embedding]


@dataclass(frozen=True, slots=True)
class JinaCodeBackend(_EmbeddingRerankBackend):
    """jina-code-embeddings-v2 rerank over the local candidate pool.

    Activated when ``retrieval_backend_jina_api_key`` is set. Uses the
    public v1 embeddings endpoint with the ``task=retrieval.query`` /
    ``retrieval.passage`` split. Cost is estimated from the returned
    ``usage.total_tokens`` at the public jina-code rate.
    """

    api_key: str = ""
    model: str = "jina-code-embeddings-v2"
    base_url: str = "https://api.jina.ai/v1"
    pool_multiplier: int = 5
    timeout_s: float = 30.0
    # Public jina embeddings price (v3 tier as of 2026-01): $0.02 per
    # 1M tokens. Same operator-tunable-via-constant story as voyage.
    price_per_million_tokens: float = 0.02

    name = "jina_code"
    label = "jina-code-embeddings-v2 (rerank over local pool)"

    async def availability(self) -> BackendAvailability:
        if not self.api_key.strip():
            return BackendAvailability(
                False,
                "unconfigured: set retrieval_backend_jina_api_key",
            )
        return BackendAvailability(
            True,
            f"configured (model={self.model!r}, base_url={self.base_url!r})",
        )

    async def _embed(
        self, query: str, docs: Sequence[str],
    ) -> tuple[list[float], list[list[float]], float]:
        url = f"{self.base_url.rstrip('/')}/embeddings"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        total_tokens = 0

        query_resp = await _post_json(
            url,
            {"model": self.model, "task": "retrieval.query", "input": [query]},
            headers=headers, timeout=self.timeout_s, backend_name=self.name,
        )
        query_vec = _extract_voyage_vector(query_resp, 0, self.name)
        total_tokens += int((query_resp.get("usage") or {}).get("total_tokens") or 0)

        doc_resp = await _post_json(
            url,
            {"model": self.model, "task": "retrieval.passage", "input": list(docs)},
            headers=headers, timeout=self.timeout_s, backend_name=self.name,
        )
        doc_vecs = [_extract_voyage_vector(doc_resp, i, self.name) for i in range(len(docs))]
        total_tokens += int((doc_resp.get("usage") or {}).get("total_tokens") or 0)

        if total_tokens <= 0:
            total_tokens = _tokens_estimate(query) + sum(_tokens_estimate(d) for d in docs)
        cost = (total_tokens / 1_000_000.0) * self.price_per_million_tokens
        return query_vec, doc_vecs, cost


@dataclass(frozen=True, slots=True)
class Qwen3RerankBackend:
    """Qwen3-Reranker cross-encoder rerank over the local candidate pool.

    Activated when ``retrieval_backend_qwen_reranker_url`` is set. Sends
    the candidate pool as one rerank request over a TEI-compatible
    endpoint (``POST {base_url}/rerank`` with
    ``{model, query, documents, top_n}``) and reorders the pool by the
    returned scores. The endpoint is expected to be either
    text-embeddings-inference (Hugging Face's serving stack) or a
    provider gateway that mimics it (SiliconFlow, together.ai). Cost
    is reported as 0 unless the endpoint returns a ``usage`` block --
    self-hosted Qwen3-Reranker is compute-only.
    """

    base_url: str = ""
    model: str = "Qwen/Qwen3-Reranker-4B"
    api_key: str = ""
    pool_multiplier: int = 5
    timeout_s: float = 30.0

    name = "qwen3_reranker"
    label = "Qwen3-Reranker (rerank over local pool)"

    async def availability(self) -> BackendAvailability:
        if not self.base_url.strip():
            return BackendAvailability(
                False,
                "unconfigured: set retrieval_backend_qwen_reranker_url",
            )
        return BackendAvailability(
            True,
            f"configured (model={self.model!r}, base_url={self.base_url!r})",
        )

    async def retrieve_hits(
        self,
        query: str,
        k: int,
        *,
        namespace_patterns: Sequence[str],
        route: str,
        min_score: float,
    ) -> BackendCall:
        pool, pool_ms = await _fetch_local_pool(
            query, k,
            pool_multiplier=self.pool_multiplier,
            namespace_patterns=namespace_patterns,
            route=route,
            min_score=min_score,
        )
        if not pool:
            return BackendCall(hits=(), latency_ms=pool_ms, cost_usd=0.0)

        docs = [_hit_content(h) for h in pool]
        url = f"{self.base_url.rstrip('/')}/rerank"
        headers = {"Content-Type": "application/json"}
        if self.api_key.strip():
            headers["Authorization"] = f"Bearer {self.api_key}"
        payload = {
            "model": self.model,
            "query": query,
            "documents": docs,
            "top_n": min(k, len(docs)),
            "return_documents": False,
        }
        start = time.perf_counter()
        response = await _post_json(
            url, payload, headers=headers, timeout=self.timeout_s, backend_name=self.name,
        )
        rerank_ms = (time.perf_counter() - start) * 1000.0

        results = response.get("results") if isinstance(response, dict) else None
        if not isinstance(results, list):
            raise BackendCallError(
                f"{self.name}: rerank response missing 'results' list",
            )
        ranked: list[dict[str, Any]] = []
        seen: set[int] = set()
        for entry in results:
            if not isinstance(entry, dict):
                continue
            raw_idx = entry.get("index")
            try:
                idx = int(raw_idx) if raw_idx is not None else -1
            except (TypeError, ValueError):
                continue
            if 0 <= idx < len(pool) and idx not in seen:
                ranked.append(pool[idx])
                seen.add(idx)
        # Fill the tail with any pool entries the endpoint did not
        # score, in original order, so the harness always sees at least
        # ``min(k, len(pool))`` ranked hits even if the endpoint
        # truncates to top_n on its side.
        for i, hit in enumerate(pool):
            if len(ranked) >= k:
                break
            if i not in seen:
                ranked.append(hit)

        usage = response.get("usage") if isinstance(response, dict) else None
        cost_usd = 0.0
        if isinstance(usage, dict):
            reported = usage.get("total_cost_usd") or usage.get("cost_usd")
            if reported is not None:
                try:
                    cost_usd = float(reported)
                except (TypeError, ValueError):
                    cost_usd = 0.0
        return BackendCall(hits=tuple(ranked[:k]), latency_ms=pool_ms + rerank_ms, cost_usd=cost_usd)


async def _read_str(key: str, default: str) -> str:
    """Read a platform-namespaced config string, fall back to ``default``.

    Broad-but-specific except tuple: ConfigRegistry can raise on DB
    outage / OS-level socket errors / bad cast; the compare CLI must
    keep running against the schema default rather than abort.
    Deferred import breaks the storage <-> eval cycle at module load.
    """
    from sqlalchemy.exc import SQLAlchemyError

    from aila.storage.registry import ConfigRegistry

    try:
        raw = await ConfigRegistry().get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    return str(raw)


async def _read_int(key: str, default: int) -> int:
    """Read a platform-namespaced config int, fall back to ``default``."""
    from sqlalchemy.exc import SQLAlchemyError

    from aila.storage.registry import ConfigRegistry

    try:
        raw = await ConfigRegistry().get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        return default


async def _read_float(key: str, default: float) -> float:
    """Read a platform-namespaced config float, fall back to ``default``."""
    from sqlalchemy.exc import SQLAlchemyError

    from aila.storage.registry import ConfigRegistry

    try:
        raw = await ConfigRegistry().get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    try:
        return float(raw)
    except (TypeError, ValueError):
        return default


async def resolve_backends() -> list[RetrieverBackend]:
    """Build every backend from :class:`ConfigRegistry`, gated or not.

    The default local backend is always first. Alt backends are
    constructed unconditionally so the compare table can render an
    ``unconfigured`` row for each one -- their :meth:`availability`
    check runs later inside the compare loop and decides whether the
    backend actually gets called.

    Deferred imports of :class:`PlatformConfigSchema` and
    :class:`ConfigRegistry` keep the module importable in environments
    that never call ``--compare``.
    """
    from aila.platform.config import PlatformConfigSchema

    schema = PlatformConfigSchema()
    pool_multiplier = await _read_int(
        "retrieval_backend_pool_multiplier",
        schema.retrieval_backend_pool_multiplier,
    )
    timeout_s = await _read_float(
        "retrieval_backend_http_timeout_s",
        schema.retrieval_backend_http_timeout_s,
    )

    voyage_key = await _read_str("retrieval_backend_voyage_api_key", "")
    voyage_model = await _read_str(
        "retrieval_backend_voyage_model", schema.retrieval_backend_voyage_model,
    )
    voyage_base = await _read_str(
        "retrieval_backend_voyage_base_url", schema.retrieval_backend_voyage_base_url,
    )

    jina_key = await _read_str("retrieval_backend_jina_api_key", "")
    jina_model = await _read_str(
        "retrieval_backend_jina_model", schema.retrieval_backend_jina_model,
    )
    jina_base = await _read_str(
        "retrieval_backend_jina_base_url", schema.retrieval_backend_jina_base_url,
    )

    qwen_url = await _read_str("retrieval_backend_qwen_reranker_url", "")
    qwen_model = await _read_str(
        "retrieval_backend_qwen_reranker_model",
        schema.retrieval_backend_qwen_reranker_model,
    )
    qwen_key = await _read_str("retrieval_backend_qwen_reranker_api_key", "")

    return [
        DefaultLocalBackend(),
        VoyageCode3Backend(
            api_key=voyage_key, model=voyage_model, base_url=voyage_base,
            pool_multiplier=pool_multiplier, timeout_s=timeout_s,
        ),
        JinaCodeBackend(
            api_key=jina_key, model=jina_model, base_url=jina_base,
            pool_multiplier=pool_multiplier, timeout_s=timeout_s,
        ),
        Qwen3RerankBackend(
            base_url=qwen_url, model=qwen_model, api_key=qwen_key,
            pool_multiplier=pool_multiplier, timeout_s=timeout_s,
        ),
    ]


async def run_backend_benchmark(
    backend: RetrieverBackend,
    pairs: Sequence[BenchPair],
    *,
    k: int = DEFAULT_K,
    namespace_patterns: Sequence[str] = DEFAULT_NAMESPACE_PATTERNS,
    route: str = DEFAULT_ROUTE,
    min_score: float = DEFAULT_MIN_SCORE,
) -> tuple[BenchmarkResult, float]:
    """Score ``pairs`` against ``backend`` at ``k``.

    Mirrors :func:`run_benchmark` but drives an arbitrary backend
    through the same snippet-relevance path (the snippet is matched in
    the backend's returned hit content, so a backend that reorders the
    pool is scored on the reordered hits' contents). Returns the
    aggregate result + the total estimated cost across all queries.
    """
    if not pairs:
        raise ValueError("run_backend_benchmark requires at least one pair")
    if k <= 0:
        raise ValueError("k must be positive")

    scores: list[RetrievalCaseScore] = []
    latencies: list[float] = []
    total_cost = 0.0
    for pair in pairs:
        call = await backend.retrieve_hits(
            pair.query, k,
            namespace_patterns=namespace_patterns,
            route=route,
            min_score=min_score,
        )
        ranked_ids = tuple(str(hit["id"]) for hit in call.hits if hit.get("id") is not None)
        if pair.positive_snippet:
            derived_relevant = _snippet_relevant_ids(call.hits, pair.positive_snippet)
            relevant = pair.relevant_ids | derived_relevant
        else:
            relevant = pair.relevant_ids
        case = RetrievalCase(
            query_id=pair.query_id,
            query=pair.query,
            relevant_ids=relevant,
        )
        scores.append(score_case(case, ranked_ids, k))
        latencies.append(call.latency_ms)
        total_cost += call.cost_usd

    report = aggregate_report(scores, k)
    result = BenchmarkResult(
        k=report.k,
        n_queries=report.n_queries,
        map_score=report.map_score,
        ndcg_at_k=report.ndcg_at_k,
        recall_at_k=report.recall_at_k,
        precision_at_k=report.precision_at_k,
        mrr=report.mrr,
        per_case_ms=tuple(latencies),
        per_case=report.per_case,
        retriever_label=backend.label,
    )
    return result, total_cost


async def run_compare(
    pairs: Sequence[BenchPair],
    *,
    k: int = DEFAULT_K,
    namespace_patterns: Sequence[str] = DEFAULT_NAMESPACE_PATTERNS,
    route: str = DEFAULT_ROUTE,
    min_score: float = DEFAULT_MIN_SCORE,
) -> CompareRun:
    """Run ``pairs`` through every resolved backend and gather reports.

    A backend whose :meth:`availability` returns ``available=False`` is
    reported with an empty ``result`` + the availability reason. A
    backend that raises :class:`BackendCallError` mid-run is reported
    with an empty ``result`` + the error message. Any other exception
    escapes -- that is a bug in the harness, not a backend degradation.
    """
    backends = await resolve_backends()
    reports: list[BackendReport] = []
    for backend in backends:
        availability = await backend.availability()
        if not availability.available:
            reports.append(BackendReport(
                name=backend.name, label=backend.label,
                availability=availability,
            ))
            continue
        try:
            result, total_cost = await run_backend_benchmark(
                backend, pairs,
                k=k, namespace_patterns=namespace_patterns,
                route=route, min_score=min_score,
            )
        except BackendCallError as exc:
            reports.append(BackendReport(
                name=backend.name, label=backend.label,
                availability=availability,
                error=str(exc),
            ))
            continue
        reports.append(BackendReport(
            name=backend.name, label=backend.label,
            availability=availability,
            result=result,
            total_cost_usd=total_cost,
        ))
    return CompareRun(k=k, n_queries=len(pairs), reports=tuple(reports))


def format_compare_report(run: CompareRun) -> str:
    """Format ``run`` as a side-by-side backend comparison table.

    Shape: one header + one row per backend. Configured backends show
    MAP@k / nDCG@k / Recall@k / cost-per-call / latency stats.
    Unconfigured or errored backends show the reason in a wide column
    so the operator can see exactly what to set to enable them.
    """
    lines = [
        f"Retrieval backend compare (k={run.k}, {run.n_queries} pairs)",
        "=" * 92,
        f"{'backend':<22} {'MAP@k':>8} {'nDCG@k':>8} {'Recall@k':>9} "
        f"{'cost/call':>11}  latency (mean / p50 / p95)",
        "-" * 92,
    ]
    for report in run.reports:
        if report.error:
            lines.append(f"{report.name:<22} error: {report.error}")
            continue
        if report.result is None:
            lines.append(f"{report.name:<22} {report.availability.reason}")
            continue
        result = report.result
        avg_cost = (
            report.total_cost_usd / result.n_queries
            if result.n_queries > 0 else 0.0
        )
        latency = _fmt_ms(result.per_case_ms)
        lines.append(
            f"{report.name:<22} "
            f"{result.map_score:>8.4f} "
            f"{result.ndcg_at_k:>8.4f} "
            f"{result.recall_at_k:>9.4f} "
            f"${avg_cost:>10.6f}  {latency}",
        )
    lines.append("=" * 92)
    lines.append("legend:")
    lines.append("  backend         -- ConfigRegistry key gating the backend (see retrieval_bench docstring)")
    lines.append("  cost/call       -- estimated USD per query (0 for local; API-usage-derived for alts)")
    lines.append("  latency         -- wall-clock ms per query (mean / p50 / p95)")
    lines.append("  unconfigured    -- backend skipped; set the named config key to activate")
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
    parser.add_argument(
        "--compare",
        action="store_true",
        help=(
            "Run every configured retriever backend (local default + any "
            "alt whose API key/model/endpoint is set in ConfigRegistry) "
            "over the same pairs and print a side-by-side "
            "MAP@k / nDCG@k / Recall@k / cost-per-call / latency table. "
            "Unconfigured alt backends appear as skipped rows with the "
            "config key needed to activate them."
        ),
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
    if args.compare:
        run = await run_compare(
            pairs,
            k=k,
            namespace_patterns=namespace_patterns,
            route=route,
            min_score=min_score,
        )
        print(format_compare_report(run))
        return 0
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
