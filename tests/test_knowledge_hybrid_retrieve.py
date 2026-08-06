"""Real Postgres coverage for KnowledgeRetrieveTool's hybrid retrieval path.

Ported from the SQLite-era version whose whole file was skipped after the
D-48/D-49 SQLite purge -- the four false-skips leaving hybrid retrieval with
zero automated coverage were called out in #62. The tool now writes and reads
against pgvector + tsvector on aila_test through the shared ``test_db``
fixture and exercises ``KnowledgeRetrieveTool.forward(..., route="simple")``,
which is the router pick that produces the hybrid retrieval leg used in
production.

Every test seeds real ``KnowledgeEntryRecord`` rows via
``KnowledgeStoreTool.forward`` (async, dedup-aware) and asserts the retrieval
dict shape callers rely on: ``hybrid`` flag, per-hit ``score`` / ``vec_score``
/ ``fts_score`` / ``source`` fields, sort order, namespace isolation, and
the removal of the pre-hybrid ``distance`` column. A module-scoped stub
embedding provider is installed on the KnowledgeService singleton so the
tests do not pull a real BGE-M3 checkpoint at collection time.
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest
import pytest_asyncio

from aila.platform.services import knowledge as knowledge_mod
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.knowledge_router import Route
from aila.platform.tools import knowledge as knowledge_tool_mod


# A non-zero constant vector so pgvector's cosine_distance stays well-defined
# (a zero-vector query normalises to NaN and destabilises hybrid ranking).
_STUB_EMBEDDING: list[float] = [1.0] * 1024


class _StubEmbeddingProvider:
    """Deterministic embedding provider so the tests don't download a model.

    The KnowledgeService singleton is swapped for one built around this
    provider inside the fixture below; both the store path and the retrieve
    path see the same 1024-dim vector, which keeps the hybrid retrieval leg
    exercisable without a live embedder.
    """

    def __init__(self) -> None:
        self.encode_calls: list[str] = []

    @property
    def dimension(self) -> int:
        return 1024

    @property
    def model_name(self) -> str:
        return "stub-hybrid-provider"

    def encode(self, text: str) -> list[float]:
        self.encode_calls.append(text)
        return list(_STUB_EMBEDDING)

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


@pytest_asyncio.fixture()
async def populated_store(test_db) -> Any:
    """Seed two entries in a unique namespace and hand back the tool trio.

    Returns ``(store_tool, retrieve_tool, namespace)``. The namespace is
    scoped to the test invocation so nothing bleeds across parallel runs, and
    the stub-backed KnowledgeService is installed as the module singleton so
    both the store and retrieve calls resolve to it.
    """
    del test_db  # activates the aila_test bootstrap; no direct consumption

    from aila.config import get_settings

    stub_service = KnowledgeService(provider=_StubEmbeddingProvider())
    prior_service = knowledge_tool_mod._KNOWLEDGE_SERVICE
    knowledge_tool_mod._KNOWLEDGE_SERVICE = stub_service
    knowledge_mod._STABLE_CORE_CACHE.invalidate()

    namespace = f"SecAgentHybrid_{uuid.uuid4().hex[:8]}"
    settings = get_settings()

    store = knowledge_tool_mod.KnowledgeStoreTool(
        namespace=namespace, settings=settings,
    )
    retrieve = knowledge_tool_mod.KnowledgeRetrieveTool(
        namespace=namespace, settings=settings,
    )

    await store.forward(
        "CVE-2024-1234 heap overflow in libfoo allows remote code execution",
        {"source": "nvd"},
    )
    await store.forward(
        "unrelated document about network topology and routing protocols",
        {"source": "other"},
    )

    try:
        yield store, retrieve, namespace
    finally:
        knowledge_tool_mod._KNOWLEDGE_SERVICE = prior_service


async def test_retrieve_returns_hybrid_flag(populated_store) -> None:
    """When the router picks the simple (hybrid) path, ``hybrid=True``.

    ``KnowledgeRetrieveTool.forward`` sets ``hybrid`` iff the routed pick was
    ``Route.SIMPLE``; forcing ``route="simple"`` proves the flag flips on the
    hybrid leg the way the pre-port tests intended.
    """
    _, retrieve, _ = populated_store
    results = await retrieve.forward(
        "heap overflow remote code execution", limit=5, route=Route.SIMPLE.value,
    )
    assert results["status"] == "retrieved"
    assert results["route"] == Route.SIMPLE.value
    assert results["hybrid"] is True


async def test_retrieve_returns_score_fields(populated_store) -> None:
    """Every hit carries the four numeric score fields the ranker exposes."""
    _, retrieve, _ = populated_store
    results = await retrieve.forward(
        "heap overflow remote code execution", limit=5, route=Route.SIMPLE.value,
    )
    assert results["count"] >= 1, f"expected at least one hit, got {results}"
    top = results["results"][0]
    for key in ("score", "vec_score", "fts_score", "source"):
        assert key in top, f"hit missing {key!r}: {sorted(top.keys())}"


async def test_retrieve_source_values(populated_store) -> None:
    """The ``source`` label is drawn from the ranker's three-value enum."""
    _, retrieve, _ = populated_store
    results = await retrieve.forward(
        "heap overflow remote code execution", limit=5, route=Route.SIMPLE.value,
    )
    for r in results["results"]:
        assert r["source"] in ("hybrid", "fts_only", "vec_only"), (
            f"unexpected source value on hit: {r['source']!r}"
        )


async def test_retrieve_score_in_range(populated_store) -> None:
    """Combined score is a normalised 0..1 blend (0.6*vec + 0.4*fts)."""
    _, retrieve, _ = populated_store
    results = await retrieve.forward(
        "heap overflow remote code execution", limit=5, route=Route.SIMPLE.value,
    )
    for r in results["results"]:
        assert 0.0 <= r["score"] <= 1.0, f"score out of range: {r['score']}"


async def test_retrieve_sorted_by_score_descending(populated_store) -> None:
    """Ranker output is sorted by combined score, descending."""
    _, retrieve, _ = populated_store
    results = await retrieve.forward(
        "heap overflow remote code execution", limit=5, route=Route.SIMPLE.value,
    )
    scores = [r["score"] for r in results["results"]]
    assert scores == sorted(scores, reverse=True), (
        f"hybrid results not sorted descending: {scores}"
    )


async def test_namespace_isolation(populated_store) -> None:
    """A retrieve rooted at a different namespace returns zero seeded hits."""
    _, _, namespace = populated_store
    from aila.config import get_settings

    other_ns = f"OtherAgent_{uuid.uuid4().hex[:8]}"
    other = knowledge_tool_mod.KnowledgeRetrieveTool(
        namespace=other_ns, settings=get_settings(),
    )
    result = await other.forward(
        "heap overflow", limit=5, route=Route.SIMPLE.value,
    )

    # None of the hits (if any) may belong to the seeded namespace.
    hit_namespaces = {r.get("namespace") for r in result["results"]}
    assert namespace not in hit_namespaces, (
        f"namespace leak: {other_ns} retrieved from {namespace}"
    )


async def test_retrieve_no_distance_field(populated_store) -> None:
    """The pre-hybrid ``distance`` column was replaced by ``score`` fields.

    Guards against a regression that reintroduces the raw pgvector cosine
    distance on hits, which callers had learned to ignore because it was
    unbounded across the vec/fts split.
    """
    _, retrieve, _ = populated_store
    results = await retrieve.forward(
        "heap overflow remote code execution", limit=5, route=Route.SIMPLE.value,
    )
    for r in results["results"]:
        assert "distance" not in r, (
            f"'distance' column resurfaced on hit: {sorted(r.keys())}"
        )


@pytest.mark.asyncio
async def test_default_route_classification_is_simple(populated_store) -> None:
    """A generic security query with no stable-core or graph markers classifies
    as the simple (hybrid) route.

    Confirms the port is not silently masking the router pick by only asserting
    the ``route="simple"`` override path -- the same generic query also lands
    on the hybrid leg without any explicit override.
    """
    _, retrieve, _ = populated_store
    results = await retrieve.forward("heap overflow in libfoo", limit=5)
    assert results["route"] == Route.SIMPLE.value
    assert results["hybrid"] is True
