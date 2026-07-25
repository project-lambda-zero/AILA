"""RFC-12 criterion 5: semantic-neighbor edges + source_type retrieval filter.

``KnowledgeService.store(link_neighbors=True)`` joins a stored entry to its
nearest same-namespace neighbours above the similarity floor with weighted
``related`` edges, so the graph route can hop across documents by meaning.
``retrieve(source_types=[...])`` scopes the hybrid search to entries of a
given shape via the indexed ``source_type`` column.

The embedding provider is a controllable one-hot stub so cosine similarity
is deterministic (identical direction -> similarity 1.0; orthogonal -> 0.0).
"""
from __future__ import annotations

from sqlmodel import select

from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.knowledge_graph import KnowledgeEntryEdge
from aila.storage.database import async_session_scope

_DIM = 1024


def _onehot(index: int) -> list[float]:
    vec = [0.0] * _DIM
    vec[index] = 1.0
    return vec


class _VecProvider:
    """Embedding provider returning a caller-set vector (deterministic cosine)."""

    def __init__(self) -> None:
        self.vec: list[float] = _onehot(0)

    @property
    def dimension(self) -> int:
        return _DIM

    @property
    def model_name(self) -> str:
        return "test-provider/vX"

    def encode(self, text: str) -> list[float]:
        del text
        return list(self.vec)

    async def encode_async(self, text: str) -> list[float]:
        return self.encode(text)


async def _related_edges(ids: list[int]) -> list[KnowledgeEntryEdge]:
    async with async_session_scope() as session:
        return list((await session.exec(
            select(KnowledgeEntryEdge).where(
                KnowledgeEntryEdge.relation == "related",
                KnowledgeEntryEdge.src_id.in_(ids),  # type: ignore[attr-defined]
            )
        )).all())


async def test_link_neighbors_writes_related_edges(test_db) -> None:
    del test_db
    prov = _VecProvider()
    svc = KnowledgeService(provider=prov)
    prov.vec = _onehot(0)
    a = await svc.store(namespace="agent:Nbr", content="alpha doc", link_neighbors=True)
    assert a["neighbor_edge_count"] == 0  # first entry: no neighbours yet
    prov.vec = _onehot(0)  # identical direction -> similarity 1.0
    b = await svc.store(namespace="agent:Nbr", content="beta doc", link_neighbors=True)
    assert b["neighbor_edge_count"] == 2  # bidirectional edge to a

    edges = await _related_edges([a["entry_id"], b["entry_id"]])
    pairs = {(e.src_id, e.dst_id) for e in edges}
    assert (b["entry_id"], a["entry_id"]) in pairs
    assert (a["entry_id"], b["entry_id"]) in pairs
    # Weight is the cosine similarity (identical vectors -> ~1.0).
    assert all(e.weight > 0.9 for e in edges)


async def test_link_neighbors_respects_floor(test_db) -> None:
    del test_db
    prov = _VecProvider()
    svc = KnowledgeService(provider=prov)
    prov.vec = _onehot(0)
    a = await svc.store(namespace="agent:NbrFloor", content="alpha", link_neighbors=True)
    prov.vec = _onehot(1)  # orthogonal -> similarity 0.0 < floor
    b = await svc.store(namespace="agent:NbrFloor", content="beta", link_neighbors=True)
    assert b["neighbor_edge_count"] == 0
    assert await _related_edges([a["entry_id"], b["entry_id"]]) == []


async def test_no_link_neighbors_writes_no_related_edges(test_db) -> None:
    del test_db
    prov = _VecProvider()
    svc = KnowledgeService(provider=prov)
    prov.vec = _onehot(0)
    a = await svc.store(namespace="agent:NbrOff", content="alpha", link_neighbors=False)
    b = await svc.store(namespace="agent:NbrOff", content="beta", link_neighbors=False)
    assert b["neighbor_edge_count"] == 0
    assert await _related_edges([a["entry_id"], b["entry_id"]]) == []


async def test_retrieve_source_types_filters_shape(test_db) -> None:
    del test_db
    prov = _VecProvider()
    svc = KnowledgeService(provider=prov)
    prov.vec = _onehot(0)
    await svc.store(namespace="agent:St", content="code entry one", kind="code")
    await svc.store(namespace="agent:St", content="doc entry two", kind="document")

    scoped = await svc.retrieve(
        "entry", namespaces=["agent:St"], source_types=["code"], limit=10,
    )
    scoped_contents = [h["content"] for h in scoped]
    assert any("code entry one" in c for c in scoped_contents)
    assert not any("doc entry two" in c for c in scoped_contents)

    unscoped = await svc.retrieve("entry", namespaces=["agent:St"], limit=10)
    unscoped_contents = [h["content"] for h in unscoped]
    assert any("code entry one" in c for c in unscoped_contents)
    assert any("doc entry two" in c for c in unscoped_contents)
