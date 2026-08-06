"""Knowledge-entry relational graph -- RFC-12 criterion 5 (graph multi-hop).

Adds a real relation between :class:`KnowledgeEntryRecord` rows so multi-hop
questions ("how does X relate to Y") can be answered by traversing edges
rather than by embedding a compound query and hoping cosine-similarity
returns every hop as its own top-k row. The naive-RAG failure mode the
RFC names -- facts that live in relationships, not in any one chunk -- is
exactly the class this table handles.

Two things ship here:

* :class:`KnowledgeEntryEdge` -- the SQLModel/table for edges. src -> dst
  labelled by ``relation`` with a scalar ``weight``. A UNIQUE constraint on
  ``(src_id, dst_id, relation)`` prevents duplicate edges under the same
  label so ``add_edge`` is idempotent per (src, dst, relation).
* :class:`KnowledgeGraph` -- the service. ``add_edge`` writes; ``traverse``
  runs a bounded BFS from a seed set, returning every reachable
  ``KnowledgeEntryRecord`` row along with its hop depth and the edge that
  reached it. Traversal is capped by ``max_hops`` (hop 0 = the seed itself,
  hop 1 = direct neighbours, ...) and by ``max_nodes`` so a pathological
  fan-out cannot exhaust the process.

The table is defined in this module (not ``storage/db_models.py``) so the
retrieval slice owns its schema end-to-end. It is registered with
``SQLModel.metadata`` on import; the orchestrator wires the Alembic
migration and adds an ``import aila.platform.services.knowledge_graph`` to
``db_models`` so ``create_all`` picks the table up on fresh installs / in
tests.
"""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable
from datetime import datetime
from typing import Any

from sqlalchemy import Column, Float, ForeignKey, Index, Integer, String, UniqueConstraint
from sqlalchemy import DateTime as SA_DateTime
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel, select

from ...platform.contracts._common import utc_now
from ...storage.db_models import KnowledgeEntryRecord
from .knowledge import _session_or_new

__all__ = [
    "DEFAULT_MAX_HOPS",
    "DEFAULT_MAX_NODES",
    "KnowledgeEntryEdge",
    "KnowledgeGraph",
    "TraversalHit",
]

# BFS defaults sized to real multi-hop retrieval use, not degenerate fan-out.
# A hop bound of 2 covers the "seed -> direct neighbour -> next-hop
# neighbour" pattern the RFC calls out, and 128 total nodes keeps a badly
# connected corpus from stalling a single query.
DEFAULT_MAX_HOPS: int = 2
DEFAULT_MAX_NODES: int = 128


class KnowledgeEntryEdge(SQLModel, table=True):
    """Directed labelled edge between two :class:`KnowledgeEntryRecord` rows.

    ``src_id`` -> ``dst_id`` under ``relation`` with a scalar ``weight``
    (0.0 - 1.0 by convention, but any float is stored). ``ON DELETE
    CASCADE`` on both foreign keys so deleting an entry never leaves
    dangling edges. The unique constraint on ``(src_id, dst_id,
    relation)`` makes :meth:`KnowledgeGraph.add_edge` idempotent per
    labelled edge; a repeat call updates the weight in place instead of
    proliferating rows.
    """

    __tablename__ = "knowledge_entry_edges"
    __table_args__ = (
        UniqueConstraint(
            "src_id",
            "dst_id",
            "relation",
            name="uq_knowledge_entry_edges_src_dst_relation",
        ),
        Index("ix_knowledge_entry_edges_src_id", "src_id"),
        Index("ix_knowledge_entry_edges_dst_id", "dst_id"),
        Index("ix_knowledge_entry_edges_relation", "relation"),
    )

    id: int | None = Field(default=None, primary_key=True)
    src_id: int = Field(
        sa_column=Column(
            "src_id",
            Integer,
            ForeignKey("knowledgeentryrecord.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    dst_id: int = Field(
        sa_column=Column(
            "dst_id",
            Integer,
            ForeignKey("knowledgeentryrecord.id", ondelete="CASCADE"),
            nullable=False,
        ),
    )
    relation: str = Field(
        sa_column=Column("relation", String(64), nullable=False),
    )
    weight: float = Field(
        sa_column=Column("weight", Float, nullable=False, default=1.0),
        default=1.0,
    )
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_column=Column(
            "created_at",
            SA_DateTime(timezone=True),
            nullable=False,
        ),
    )


class TraversalHit(dict):
    """BFS traversal result for one visited entry.

    A thin ``dict`` subclass so callers can treat a hit as a plain mapping
    (the shape :meth:`KnowledgeService.retrieve` returns) while the class
    itself makes the traversal-specific fields (``hop``, ``path``,
    ``incoming_relation``, ``incoming_weight``) discoverable. Keys:

    * ``id`` -- knowledge entry id
    * ``namespace`` / ``content`` / ``entry_metadata`` -- entry row fields
    * ``model_id`` / ``content_hash`` / ``source_type`` -- provenance
    * ``created_at`` / ``updated_at`` -- provenance timestamps
    * ``hop`` -- 0 for seeds, N for entries reached in N BFS hops
    * ``path`` -- list of entry ids from the seed to this hit (inclusive)
    * ``incoming_relation`` / ``incoming_weight`` -- edge that reached
      this hit; ``None`` when ``hop == 0`` (seed).
    """


class KnowledgeGraph:
    """Service over :class:`KnowledgeEntryEdge`.

    Two operations: ``add_edge`` writes/upserts a labelled edge;
    ``traverse`` runs a bounded BFS from a seed set. Both accept an
    optional external :class:`AsyncSession` so callers already inside a
    unit of work can enroll the graph write/read in the same transaction;
    passing ``None`` opens a short-lived session via
    :func:`_session_or_new`.
    """

    async def add_edge(
        self,
        src_id: int,
        dst_id: int,
        relation: str,
        weight: float = 1.0,
        session: AsyncSession | None = None,
    ) -> dict[str, Any]:
        """Insert or update a labelled edge from ``src_id`` to ``dst_id``.

        Idempotent on ``(src_id, dst_id, relation)`` via the
        Postgres ``ON CONFLICT DO UPDATE`` upsert -- a repeat call updates
        the weight in place. Rejects self-loops (``src_id == dst_id``)
        because they are always noise in a knowledge graph: a hit is
        already returned by the seed lookup so a self-edge only doubles
        it.

        Returns the persisted edge as ``{src_id, dst_id, relation,
        weight, created_at}``. The ``created_at`` stamp is the original
        insert time when the row already existed; a fresh row gets the
        current UTC time.
        """
        if src_id == dst_id:
            raise ValueError(
                f"KnowledgeEntryEdge: src_id ({src_id}) == dst_id -- "
                "self-loops are rejected; a seed is already returned as hop 0",
            )
        if not relation or not relation.strip():
            raise ValueError("KnowledgeEntryEdge: relation must be non-empty")
        stamp = utc_now()
        async with _session_or_new(session) as (sess, owns):
            stmt = pg_insert(KnowledgeEntryEdge).values(
                src_id=src_id,
                dst_id=dst_id,
                relation=relation,
                weight=float(weight),
                created_at=stamp,
            )
            stmt = stmt.on_conflict_do_update(
                constraint="uq_knowledge_entry_edges_src_dst_relation",
                set_={"weight": float(weight)},
            )
            await sess.exec(stmt)
            if owns:
                await sess.commit()
        return {
            "src_id": src_id,
            "dst_id": dst_id,
            "relation": relation,
            "weight": float(weight),
            "created_at": stamp,
        }

    async def traverse(
        self,
        seeds: Iterable[int],
        max_hops: int = DEFAULT_MAX_HOPS,
        session: AsyncSession | None = None,
        relations: list[str] | None = None,
        max_nodes: int = DEFAULT_MAX_NODES,
    ) -> list[TraversalHit]:
        """Breadth-first traverse the graph from ``seeds`` up to ``max_hops``.

        Real BFS -- a ``seen`` set, a FIFO queue of ``(entry_id, hop,
        path)`` triples, and per-hop edge lookups. Each visited entry
        row is materialised once (seed rows and neighbours alike) so
        the caller sees the same fields regardless of which hop reached
        the row.

        ``max_hops == 0`` returns only the seed entries. ``max_hops ==
        1`` returns seeds + their direct neighbours. Traversal stops as
        soon as either the hop bound is reached or ``max_nodes`` have
        been visited, whichever comes first. ``relations``, when
        supplied, restricts expansion to edges carrying one of the
        named labels.

        Returns the visited rows in BFS order -- seeds first, then all
        hop-1 hits, then hop-2, and so on -- so a downstream caller can
        rank/drop by hop trivially.
        """
        if max_hops < 0:
            raise ValueError(f"max_hops must be >= 0, got {max_hops}")
        seen_ids: set[int] = set()
        queue: deque[tuple[int, int, list[int], str | None, float | None]] = deque()
        for seed in seeds:
            if seed in seen_ids:
                continue
            seen_ids.add(seed)
            queue.append((seed, 0, [seed], None, None))

        # Order-preserving accumulator so BFS output stays in visit
        # order regardless of the SELECT ordering used to hydrate rows.
        ordered_ids: list[tuple[int, int, list[int], str | None, float | None]] = list(queue)

        async with _session_or_new(session) as (sess, owns):
            # Expand one hop at a time so the entire frontier at hop N
            # is materialised before any hop-N+1 lookup happens.
            while queue and len(seen_ids) < max_nodes:
                entry_id, hop, path, in_rel, in_weight = queue.popleft()
                if hop >= max_hops:
                    continue
                edge_stmt = select(
                    KnowledgeEntryEdge.dst_id,
                    KnowledgeEntryEdge.relation,
                    KnowledgeEntryEdge.weight,
                ).where(KnowledgeEntryEdge.src_id == entry_id)
                if relations:
                    edge_stmt = edge_stmt.where(
                        KnowledgeEntryEdge.relation.in_(relations),
                    )
                edge_rows = (await sess.exec(edge_stmt)).all()
                for edge in edge_rows:
                    nxt = int(edge.dst_id)
                    if nxt in seen_ids:
                        continue
                    if len(seen_ids) >= max_nodes:
                        break
                    seen_ids.add(nxt)
                    new_hop = hop + 1
                    new_path = path + [nxt]
                    triple = (nxt, new_hop, new_path, str(edge.relation), float(edge.weight))
                    queue.append(triple)
                    ordered_ids.append(triple)

            if not ordered_ids:
                return []

            row_stmt = select(
                KnowledgeEntryRecord.id,
                KnowledgeEntryRecord.namespace,
                KnowledgeEntryRecord.content,
                KnowledgeEntryRecord.entry_metadata,
                KnowledgeEntryRecord.model_id,
                KnowledgeEntryRecord.content_hash,
                KnowledgeEntryRecord.source_type,
                KnowledgeEntryRecord.created_at,
                KnowledgeEntryRecord.updated_at,
            ).where(
                KnowledgeEntryRecord.id.in_([t[0] for t in ordered_ids]),
            )
            row_hits = (await sess.exec(row_stmt)).all()

        rows_by_id: dict[int, Any] = {int(r.id): r for r in row_hits}
        results: list[TraversalHit] = []
        for entry_id, hop, path, in_rel, in_weight in ordered_ids:
            row = rows_by_id.get(entry_id)
            if row is None:
                # Row was deleted after we captured its id from the edge
                # table; skip silently rather than emit a hit with no
                # content. Edge cascade cleans up the edge itself on the
                # next write.
                continue
            hit = TraversalHit(
                id=int(row.id),
                namespace=row.namespace,
                content=row.content,
                entry_metadata=row.entry_metadata,
                model_id=row.model_id,
                content_hash=row.content_hash,
                source_type=row.source_type,
                created_at=row.created_at,
                updated_at=row.updated_at,
                hop=hop,
                path=list(path),
                incoming_relation=in_rel,
                incoming_weight=in_weight,
            )
            results.append(hit)
        return results
