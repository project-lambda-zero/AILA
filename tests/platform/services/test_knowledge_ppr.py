"""RFC-14 -- Personalized-PageRank graph retrieval + shares_entity populator.

Covers the platform-owned graph route once it is ranked by PPR (the RFC-14
default, no on/off switch) instead of BFS:

* ``KnowledgeService.link_entity_neighbors`` writes bidirectional
  ``shares_entity`` edges between same-namespace entries whose extracted
  security-identifier lists intersect, upserts on re-call (idempotent),
  and writes no edges when the entity lists are disjoint.
* ``retrieve_routed(route="graph")`` seeds the walk with a dense hybrid
  retrieval, propagates via ``KnowledgeGraph.personalized_pagerank``, and
  hands PPR-ranked gated hits to the caller with full provenance.
* The graph route does not double-apply ``knowledge_target_derived_weight``:
  the PPR propagation already down-weights target-derived nodes, and the
  post-branch ``_apply_trust_decay`` runs with an identity overlay so a
  target-derived hit's final score equals its raw PPR mass (temporal
  decay set to identity for the assertion).

Runs against the PostgreSQL test database (pgvector-enabled) via the
shared ``test_db`` fixture. Pulls the edge and PPR classes at import time
so the ``knowledge_entry_edges`` table is registered with SQLModel's
metadata before the session-scoped engine's ``create_all`` runs.
"""
from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from unittest.mock import patch

import pytest
import pytest_asyncio
from sqlmodel import select

import aila.platform.services.knowledge_graph  # noqa: F401
from aila.platform.services import knowledge as knowledge_mod
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.knowledge_graph import KnowledgeEntryEdge, KnowledgeGraph
from aila.platform.services.knowledge_router import Route
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

_DIM = 1024
_STUB_EMBEDDING: list[float] = [1.0] * _DIM


class _StubProvider:
    """Minimal EmbeddingProvider that returns a constant non-zero vector."""

    def __init__(self) -> None:
        self.encode_calls: list[str] = []

    @property
    def dimension(self) -> int:
        return _DIM

    @property
    def model_name(self) -> str:
        return "stub-provider"

    def encode(self, text: str) -> list[float]:
        self.encode_calls.append(text)
        return list(_STUB_EMBEDDING)

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


@pytest_asyncio.fixture(scope="function")
async def ppr_service(test_db) -> tuple[KnowledgeService, _StubProvider]:
    """A KnowledgeService bound to the stub embedding provider."""
    del test_db
    stub = _StubProvider()
    service = KnowledgeService(provider=stub)
    knowledge_mod._STABLE_CORE_CACHE.invalidate()
    return service, stub


async def _shares_entity_edges(ids: list[int]) -> list[KnowledgeEntryEdge]:
    async with async_session_scope() as session:
        return list(
            (
                await session.exec(
                    select(KnowledgeEntryEdge).where(
                        KnowledgeEntryEdge.relation == "shares_entity",
                        KnowledgeEntryEdge.src_id.in_(ids),  # type: ignore[attr-defined]
                    )
                )
            ).all()
        )


async def _insert_ppr_entry(
    namespace: str,
    content: str,
    provenance: dict[str, Any] | None = None,
) -> int:
    prov = provenance or {}
    stamp = prov.get("updated_at") or datetime.now(UTC)
    record = KnowledgeEntryRecord(
        namespace=namespace,
        content=content,
        embedding=list(_STUB_EMBEDDING),
        entry_metadata=prov.get("entry_metadata", "{}"),
        model_id=prov.get("model_id", "stub-provider"),
        content_hash=prov.get("content_hash", "hash-" + content[:8]),
        source_type=prov.get("source_type", "document"),
        created_at=stamp,
        updated_at=stamp,
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return int(record.id)


# ---------------------------------------------------------------------------
# link_entity_neighbors: shares_entity edge populator
# ---------------------------------------------------------------------------


async def test_link_entity_neighbors_writes_shares_entity_edges(ppr_service) -> None:
    """Two entries sharing a CVE are joined by a bidirectional shares_entity edge."""
    service, _ = ppr_service
    ns = "agent:EntityShare"
    first = await service.store(
        namespace=ns,
        content="alpha touches CVE-2024-1000",
        link_neighbors=True,
        extract_entities=True,
    )
    assert first["entity_edge_count"] == 0  # no prior neighbours
    second = await service.store(
        namespace=ns,
        content="bravo also references CVE-2024-1000",
        link_neighbors=True,
        extract_entities=True,
    )
    assert second["entity_edge_count"] == 2  # bidirectional edge to first

    edges = await _shares_entity_edges([first["entry_id"], second["entry_id"]])
    pairs = {(e.src_id, e.dst_id) for e in edges}
    assert (first["entry_id"], second["entry_id"]) in pairs
    assert (second["entry_id"], first["entry_id"]) in pairs
    # Weight defaults to knowledge_graph_entity_edge_weight (0.8 in
    # PlatformConfigSchema).
    assert all(e.weight == pytest.approx(0.8) for e in edges)


async def test_link_entity_neighbors_disjoint_writes_no_edges(ppr_service) -> None:
    """Entries with disjoint entity sets do not get a shares_entity edge."""
    service, _ = ppr_service
    ns = "agent:EntityDisjoint"
    a = await service.store(
        namespace=ns,
        content="alpha touches CVE-2024-1000",
        link_neighbors=True,
        extract_entities=True,
    )
    b = await service.store(
        namespace=ns,
        content="bravo touches CVE-2024-9999",
        link_neighbors=True,
        extract_entities=True,
    )
    assert b["entity_edge_count"] == 0
    assert await _shares_entity_edges([a["entry_id"], b["entry_id"]]) == []


async def test_link_entity_neighbors_idempotent_on_recall(ppr_service) -> None:
    """A repeat call over the same pair does not proliferate rows.

    :meth:`KnowledgeGraph.add_edge` upserts on ``(src, dst, relation)``,
    so calling :meth:`link_entity_neighbors` a second time with the same
    entity list rewrites the same edge instead of duplicating it.
    """
    service, _ = ppr_service
    ns = "agent:EntityIdem"
    a = await service.store(
        namespace=ns,
        content="alpha references CVE-2024-1000",
        link_neighbors=True,
        extract_entities=True,
    )
    b = await service.store(
        namespace=ns,
        content="bravo also references CVE-2024-1000",
        link_neighbors=True,
        extract_entities=True,
    )
    before = await _shares_entity_edges([a["entry_id"], b["entry_id"]])
    assert len(before) == 2
    # Re-call explicitly with the same entity list.
    again = await service.link_entity_neighbors(
        b["entry_id"], ["CVE-2024-1000"], ns, None,
    )
    assert again == 2
    after = await _shares_entity_edges([a["entry_id"], b["entry_id"]])
    assert len(after) == 2


# ---------------------------------------------------------------------------
# retrieve_routed graph route via Personalized-PageRank
# ---------------------------------------------------------------------------


async def _seed_graph_corpus() -> list[int]:
    """Insert three same-namespace entries; link two by a related edge.

    The seed retrieval will land on ``ids[0]`` via FTS ("alpha marker"
    is the distinctive lexeme); PPR then propagates mass across the
    ``related`` edge to ``ids[1]``. ``ids[2]`` has no incoming edge so
    its PPR mass stays at the personalization floor.
    """
    ns = "agent:PPRChain"
    a = await _insert_ppr_entry(namespace=ns, content="alpha marker seed node")
    b = await _insert_ppr_entry(namespace=ns, content="beta neighbour node")
    c = await _insert_ppr_entry(namespace=ns, content="gamma isolated node")
    graph = KnowledgeGraph()
    await graph.add_edge(src_id=a, dst_id=b, relation="related", weight=0.9)
    await graph.add_edge(src_id=b, dst_id=a, relation="related", weight=0.9)
    return [a, b, c]


async def test_routed_graph_returns_ppr_ranked_gated_hits(ppr_service) -> None:
    """The graph route returns PPR-ranked hits carrying gate + provenance."""
    service, _ = ppr_service
    ids = await _seed_graph_corpus()
    routed = await service.retrieve_routed(
        query="alpha marker seed",
        namespaces=["agent:PPRChain"],
        route=Route.GRAPH,
        limit=10,
    )
    assert routed["route"] == Route.GRAPH.value
    assert routed["hop_bound"] is not None  # reporting knob preserved
    results = routed["results"]
    assert results, "graph route must return at least the seed"
    hit_ids = {int(r["id"]) for r in results}
    # Seed lands via FTS; propagation reaches the linked neighbour.
    assert ids[0] in hit_ids
    assert ids[1] in hit_ids
    # Every hit carries the PPR mass and the graph provenance stamps.
    for hit in results:
        assert hit["source"] == "graph"
        assert hit["ppr"] is not None
        assert "provenance" in hit
        assert hit["provenance"]["model_id"] == "stub-provider"
    # Scores are the PPR mass and are already sorted descending.
    scores = [float(r["score"]) for r in results]
    assert scores == sorted(scores, reverse=True)


async def test_routed_graph_ppr_ranks_seed_above_isolated(ppr_service) -> None:
    """A connected seed accumulates more PPR mass than an isolated node."""
    service, _ = ppr_service
    ids = await _seed_graph_corpus()
    routed = await service.retrieve_routed(
        query="alpha marker seed",
        namespaces=["agent:PPRChain"],
        route=Route.GRAPH,
        limit=10,
    )
    by_id = {int(r["id"]): float(r["ppr"]) for r in routed["results"]}
    # The connected seed (ids[0]) accumulates the linked neighbour's
    # propagated mass on top of its restart weight; the isolated node
    # (ids[2]) only gets its personalization share, so it ranks strictly
    # below either connected node.
    assert by_id[ids[0]] > 0.0
    assert by_id[ids[2]] < by_id[ids[0]]
    assert by_id[ids[2]] < by_id[ids[1]]


async def test_routed_graph_survives_nonzero_relevance_floor(ppr_service) -> None:
    """A nonzero ``min_score`` gates only the seed cosine stage, never the
    PPR-mass hits.

    Regression for the floor being re-applied to PPR mass inside
    ``retrieve_routed``: the post-gate ``_apply_trust_decay`` was called
    with ``floor=min_score``, but a graph hit's score is stationary PPR
    mass (~1/N across the reachable subgraph, so ~0.1 for a small graph),
    not the cosine-scale hybrid figure the floor is calibrated on. Under
    the 0.3 production pattern floor that dropped EVERY graph hit, leaving
    the caller with the structured fallback only and the RFC-14 graph
    route dormant. The seed stage still honours the floor at cosine scale
    (``self.retrieve(min_score=...)``); the PPR hits must not be re-cut.

    Forces the ``_apply_trust_decay`` loop to actually run (half-life > 0,
    so it is not the identity early-return) and passes a floor far above
    the PPR mass. Fresh entries have age ~0 so temporal decay is identity
    and the only variable under test is the floor.
    """
    service, _ = ppr_service
    ids = await _seed_graph_corpus()

    async def _fake_resolve(self):  # noqa: ANN001 -- bound method stub
        del self
        return (0.5, 2160.0)

    with patch.object(
        KnowledgeService, "_resolve_trust_decay_config", _fake_resolve,
    ):
        routed = await service.retrieve_routed(
            query="alpha marker seed",
            namespaces=["agent:PPRChain"],
            route=Route.GRAPH,
            limit=10,
            min_score=0.5,  # >> PPR mass; must NOT drop graph hits
        )

    results = routed["results"]
    assert results, "a nonzero floor wiped the PPR-mass graph hits (RFC-14 regression)"
    hit_ids = {int(r["id"]) for r in results}
    assert ids[0] in hit_ids, "the seed must survive the seed-stage cosine floor"
    # At least one surviving hit carries a score below the cosine floor,
    # which is only possible because the floor was NOT applied to the
    # PPR-mass hits (a re-applied 0.5 floor would have dropped it).
    assert any(float(r["score"]) < 0.5 for r in results)
    assert all(r["ppr"] is not None for r in results)


# ---------------------------------------------------------------------------
# No double trust-weight on the graph route
# ---------------------------------------------------------------------------


async def test_graph_route_does_not_double_apply_target_derived_weight(
    ppr_service,
) -> None:
    """A target-derived hit's final score matches its PPR mass, not PPR * overlay.

    The PPR propagation already scales edge weights into target-derived
    nodes by ``knowledge_target_derived_weight``; the post-branch
    ``_apply_trust_decay`` overlay must skip the second application on
    the graph route (identity weight 1.0) so ranking is not squared.
    Temporal decay is zeroed out via the config so the comparison isolates
    the target-derived path.
    """
    service, _ = ppr_service
    ns = "vr.observation.samples"  # matches trust_tier_from_namespace() target_derived
    a = await _insert_ppr_entry(namespace=ns, content="alpha observation seed")
    b = await _insert_ppr_entry(namespace=ns, content="beta observation neighbour")
    graph = KnowledgeGraph()
    await graph.add_edge(src_id=a, dst_id=b, relation="related", weight=0.9)
    await graph.add_edge(src_id=b, dst_id=a, relation="related", weight=0.9)

    # Force an aggressive down-weight (0.25) + zero half-life so any
    # accidental second application on the overlay is easy to spot.
    orig_resolve = KnowledgeService._resolve_trust_decay_config

    async def _fake_resolve(self):  # noqa: ANN001 -- bound method stub
        del self
        return (0.25, 0.0)

    with patch.object(
        KnowledgeService, "_resolve_trust_decay_config", _fake_resolve,
    ):
        routed = await service.retrieve_routed(
            query="alpha observation seed",
            namespaces=[ns],
            route=Route.GRAPH,
            limit=10,
        )

    del orig_resolve
    by_id = {int(r["id"]): r for r in routed["results"]}
    assert a in by_id, "seed must appear on the graph route"
    seed_hit = by_id[a]
    # Under identity overlay: final score == PPR mass on graph route.
    assert float(seed_hit["score"]) == pytest.approx(
        float(seed_hit["ppr"]), rel=1e-6,
    )
