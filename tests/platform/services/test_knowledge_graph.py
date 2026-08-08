"""RFC-14: Personalized PageRank over ``knowledge_entry_edges``.

Exercises :func:`_ppr_iterate` (pure math, no DB) and
:meth:`KnowledgeGraph.personalized_pagerank` (BFS induction + hydration +
PPR). The DB-facing tests use the ``test_db`` fixture and a zero-vector
stub embedding provider so no real model is loaded -- the graph route
scores by relations, not by cosine similarity.
"""
from __future__ import annotations

from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.knowledge_graph import KnowledgeGraph, _ppr_iterate


class _StubProvider:
    """Zero-vector EmbeddingProvider -- store path skips any real model."""

    def __init__(self, dim: int = 1024) -> None:
        self._dim = dim

    @property
    def dimension(self) -> int:
        return self._dim

    @property
    def model_name(self) -> str:
        return "test-provider/vX"

    def encode(self, text: str) -> list[float]:
        del text
        return [0.0] * self._dim

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


# ---------------------------------------------------------------------------
# (a) pure _ppr_iterate: hub outranks leaves
# ---------------------------------------------------------------------------

def test_ppr_iterate_hub_outranks_leaf() -> None:
    """A node with many inbound edges gets more mass than a leaf.

    Classical inbound-authority PPR: nodes 2, 3, 4, 5 each point at hub 1
    with weight 1.0; the hub has no outgoing edges (so its mass
    redistributes via the personalization vector rather than pumping a
    single successor). Uniform personalization -- the only asymmetry is
    inbound degree, so the hub must dominate every leaf.
    """
    node_ids = [1, 2, 3, 4, 5]
    out_edges: dict[int, list[tuple[int, float]]] = {
        1: [],
        2: [(1, 1.0)],
        3: [(1, 1.0)],
        4: [(1, 1.0)],
        5: [(1, 1.0)],
    }
    personalization = dict.fromkeys(node_ids, 1.0 / len(node_ids))
    mass = _ppr_iterate(
        node_ids=node_ids,
        out_edges=out_edges,
        personalization=personalization,
        damping=0.85,
        max_iter=100,
        tol=1e-8,
    )
    assert set(mass) == set(node_ids)
    # Mass is conserved (probability distribution).
    assert abs(sum(mass.values()) - 1.0) < 1e-6
    # Hub with four inbound edges outranks every leaf.
    for leaf in (2, 3, 4, 5):
        assert mass[1] > mass[leaf], f"hub 1 must outrank leaf {leaf}"
    # Leaves are symmetric: equal inbound (zero) + equal personalization.
    assert abs(mass[2] - mass[3]) < 1e-6
    assert abs(mass[3] - mass[4]) < 1e-6


def test_ppr_iterate_empty_returns_empty() -> None:
    assert _ppr_iterate([], {}, {}, damping=0.5, max_iter=10, tol=1e-4) == {}


def test_ppr_iterate_dangling_conserves_mass() -> None:
    """A pure-dangling seed graph stays normalized via personalization."""
    node_ids = [10, 20]
    mass = _ppr_iterate(
        node_ids=node_ids,
        out_edges={10: [], 20: []},
        personalization={10: 0.7, 20: 0.3},
        damping=0.5,
        max_iter=30,
        tol=1e-6,
    )
    assert abs(sum(mass.values()) - 1.0) < 1e-6
    assert abs(mass[10] - 0.7) < 1e-6
    assert abs(mass[20] - 0.3) < 1e-6


# ---------------------------------------------------------------------------
# (c) empty seeds -> []
# ---------------------------------------------------------------------------

async def test_personalized_pagerank_empty_seeds_returns_empty(test_db) -> None:
    del test_db
    graph = KnowledgeGraph()
    assert await graph.personalized_pagerank(seeds={}) == []


# ---------------------------------------------------------------------------
# (d) seeds with no outgoing edges -> exactly the seeds, ranked by weight
# ---------------------------------------------------------------------------

async def test_personalized_pagerank_seeds_only_no_edges(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    a = await svc.store(namespace="agent:PPR_Iso", content="alpha isolated")
    b = await svc.store(namespace="agent:PPR_Iso", content="beta isolated")

    graph = KnowledgeGraph()
    hits = await graph.personalized_pagerank(
        seeds={int(a["entry_id"]): 0.75, int(b["entry_id"]): 0.25},
        damping=0.5,
        max_iter=30,
    )
    assert [h["id"] for h in hits] == [int(a["entry_id"]), int(b["entry_id"])]
    assert hits[0]["ppr"] > hits[1]["ppr"]
    # Every hit carries a hop and the ppr field.
    assert all(h["hop"] == 0 for h in hits)
    assert all("ppr" in h and h["ppr"] > 0.0 for h in hits)
    # Normalized restart mass survives dangling redistribution.
    assert abs(sum(h["ppr"] for h in hits) - 1.0) < 1e-6


# ---------------------------------------------------------------------------
# (e) 2-hop chain surfaces the far node with positive PPR
# ---------------------------------------------------------------------------

async def test_personalized_pagerank_two_hop_chain(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    seed = await svc.store(namespace="agent:PPR_Chain", content="seed root")
    mid = await svc.store(namespace="agent:PPR_Chain", content="mid hop")
    far = await svc.store(namespace="agent:PPR_Chain", content="far hop")

    graph = KnowledgeGraph()
    await graph.add_edge(int(seed["entry_id"]), int(mid["entry_id"]),
                         relation="related", weight=1.0)
    await graph.add_edge(int(mid["entry_id"]), int(far["entry_id"]),
                         relation="shares_entity", weight=1.0)

    hits = await graph.personalized_pagerank(
        seeds={int(seed["entry_id"]): 1.0},
        damping=0.85,
        max_iter=100,
        tol=1e-8,
    )
    by_id = {h["id"]: h for h in hits}
    assert int(seed["entry_id"]) in by_id
    assert int(mid["entry_id"]) in by_id
    assert int(far["entry_id"]) in by_id
    # Every reachable node gets positive mass, including the 2-hop far end.
    assert by_id[int(seed["entry_id"])]["ppr"] > 0.0
    assert by_id[int(mid["entry_id"])]["ppr"] > 0.0
    assert by_id[int(far["entry_id"])]["ppr"] > 0.0
    # Path preserved from BFS induction (first reaching edge).
    assert by_id[int(mid["entry_id"])]["incoming_relation"] == "related"
    assert by_id[int(far["entry_id"])]["incoming_relation"] == "shares_entity"
    assert by_id[int(far["entry_id"])]["path"] == [
        int(seed["entry_id"]), int(mid["entry_id"]), int(far["entry_id"]),
    ]
    # Sorted by ppr desc.
    ppr_values = [h["ppr"] for h in hits]
    assert ppr_values == sorted(ppr_values, reverse=True)


# ---------------------------------------------------------------------------
# (b) trust down-weight: target-derived tier drops below verified tier
# ---------------------------------------------------------------------------

async def test_personalized_pagerank_target_derived_downweight(test_db) -> None:
    """Two seed-neighbour rows with identical in-connectivity but different
    trust tiers. ``target_derived_weight=0.5`` scales the target-derived
    node's inbound edge weight in half, so its stationary mass is strictly
    lower than the verified node's.
    """
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    # Namespace kind segments drive trust_tier_from_namespace: any namespace
    # containing ".observation." is target-derived; anything else is verified.
    seed = await svc.store(
        namespace="agent:PPR_Trust.verified.root", content="seed",
    )
    verified = await svc.store(
        namespace="agent:PPR_Trust.verified.neighbour", content="verified target",
    )
    tainted = await svc.store(
        namespace="agent:PPR_Trust.observation.neighbour", content="target-derived",
    )

    graph = KnowledgeGraph()
    await graph.add_edge(int(seed["entry_id"]), int(verified["entry_id"]),
                         relation="related", weight=1.0)
    await graph.add_edge(int(seed["entry_id"]), int(tainted["entry_id"]),
                         relation="related", weight=1.0)

    hits = await graph.personalized_pagerank(
        seeds={int(seed["entry_id"]): 1.0},
        damping=0.85,
        max_iter=100,
        tol=1e-8,
        target_derived_weight=0.5,
    )
    by_id = {h["id"]: h for h in hits}
    assert by_id[int(verified["entry_id"])]["ppr"] > by_id[int(tainted["entry_id"])]["ppr"]

    # Baseline sanity: at target_derived_weight=1.0 the two neighbours end
    # with equal mass (the trust factor is the only asymmetry).
    hits_flat = await graph.personalized_pagerank(
        seeds={int(seed["entry_id"]): 1.0},
        damping=0.85,
        max_iter=100,
        tol=1e-8,
        target_derived_weight=1.0,
    )
    flat_by_id = {h["id"]: h for h in hits_flat}
    assert abs(
        flat_by_id[int(verified["entry_id"])]["ppr"]
        - flat_by_id[int(tainted["entry_id"])]["ppr"]
    ) < 1e-6
