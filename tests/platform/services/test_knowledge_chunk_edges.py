"""RFC-12 criterion 5 graph populator: adjacent-chunk edges at ingest.

``KnowledgeService.store(chunked=True, link_chunks=True)`` joins each pair
of adjacent same-document chunks with a bidirectional ``adjacent_chunk``
edge, so the graph retrieval route reaches a hit's surrounding context
instead of degrading to seed-only. The default (link_chunks=False) writes
no edges.

The embedding provider is stubbed so the tests never load a real model;
edges are a relational concern independent of the vector content.
"""
from __future__ import annotations

from sqlmodel import select

from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.knowledge_graph import KnowledgeEntryEdge, KnowledgeGraph
from aila.storage.database import async_session_scope

_DOC = "# Alpha\nalpha body text\n\n# Beta\nbeta body text\n\n# Gamma\ngamma body text"


class _StubProvider:
    """Zero-vector EmbeddingProvider so the store path skips a real model."""

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


async def _edges_for(src_ids: list[int]) -> list[KnowledgeEntryEdge]:
    async with async_session_scope() as session:
        return list((await session.exec(
            select(KnowledgeEntryEdge).where(
                KnowledgeEntryEdge.relation == "adjacent_chunk",
                KnowledgeEntryEdge.src_id.in_(src_ids),  # type: ignore[attr-defined]
            )
        )).all())


async def test_link_chunks_writes_adjacent_edges(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    result = await svc.store(
        namespace="agent:ChunkEdges", content=_DOC,
        chunked=True, kind="document", link_chunks=True,
    )
    assert result["operation"] == "chunked"
    assert result["chunk_count"] >= 2
    # Bidirectional edge per adjacent pair.
    assert result["edge_count"] == 2 * (result["chunk_count"] - 1)

    ids = [c["entry_id"] for c in result["chunks"]]
    edges = await _edges_for(ids)
    pairs = {(e.src_id, e.dst_id) for e in edges}
    for left, right in zip(ids, ids[1:], strict=False):
        assert (left, right) in pairs
        assert (right, left) in pairs


async def test_no_link_chunks_writes_no_edges(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    result = await svc.store(
        namespace="agent:ChunkEdgesOff", content=_DOC,
        chunked=True, kind="document", link_chunks=False,
    )
    assert result["edge_count"] == 0
    ids = [c["entry_id"] for c in result["chunks"]]
    assert await _edges_for(ids) == []


async def test_traverse_reaches_adjacent_chunk(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    result = await svc.store(
        namespace="agent:ChunkTraverse", content=_DOC,
        chunked=True, kind="document", link_chunks=True,
    )
    ids = [c["entry_id"] for c in result["chunks"]]
    hits = await KnowledgeGraph().traverse(seeds=[ids[0]], max_hops=1)
    reached = {h["id"] for h in hits}
    assert ids[0] in reached
    assert ids[1] in reached


async def test_link_chunks_idempotent_on_reingest(test_db) -> None:
    del test_db
    svc = KnowledgeService(provider=_StubProvider())
    kw = dict(
        namespace="agent:ChunkIdem", content=_DOC, dedup_key="doc-1",
        chunked=True, kind="document", link_chunks=True,
    )
    first = await svc.store(**kw)
    ids = [c["entry_id"] for c in first["chunks"]]
    before = await _edges_for(ids)
    second = await svc.store(**kw)
    ids2 = [c["entry_id"] for c in second["chunks"]]
    assert ids2 == ids  # same rows on re-ingest (dedup_key stable)
    after = await _edges_for(ids)
    assert len(after) == len(before)  # upsert, not proliferation
