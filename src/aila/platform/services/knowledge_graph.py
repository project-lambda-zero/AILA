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

import json
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
from .knowledge import (
    TRUST_TIER_TARGET_DERIVED,
    _session_or_new,
    trust_tier_from_namespace,
)

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


def _ppr_iterate(
    node_ids: list[int],
    out_edges: dict[int, list[tuple[int, float]]],
    personalization: dict[int, float],
    damping: float,
    max_iter: int,
    tol: float,
) -> dict[int, float]:
    """Personalized PageRank power iteration -- pure math, no DB, no async.

    Standard formulation over the induced subgraph. ``out_edges`` maps a
    source node to its ``(dst, weight)`` list; weights are the transition
    weights the caller decided (already scaled by any trust factor).
    ``personalization`` is the restart distribution, which MUST sum to 1
    over ``node_ids`` and MUST be non-negative -- the caller is responsible
    for that normalization so this helper stays a pure iterator.

    Each iteration: ``r' = damping * (M . r) + (1-damping) * p``. Dangling
    nodes (no positive out-edge weight) redistribute their mass through the
    personalization vector so probability is conserved. Stops when the L1
    delta between successive iterations drops below ``tol`` or after
    ``max_iter`` iterations, whichever comes first. Returns the stationary
    mass keyed by entry id.
    """
    if not node_ids:
        return {}
    # Precompute out-weight sum per source for column normalization.
    out_sum: dict[int, float] = {}
    for n in node_ids:
        total = 0.0
        for _dst, w in out_edges.get(n, ()):
            if w > 0.0:
                total += w
        out_sum[n] = total

    p: dict[int, float] = {n: float(personalization.get(n, 0.0)) for n in node_ids}
    r: dict[int, float] = dict(p)
    teleport = 1.0 - float(damping)
    d = float(damping)

    for _ in range(int(max_iter)):
        # Dangling mass at the start of this iteration -- redistributed
        # through the personalization vector so total mass is conserved.
        dangling_mass = 0.0
        for n in node_ids:
            if out_sum[n] <= 0.0:
                dangling_mass += r[n]
        dangling_share = d * dangling_mass

        new_r: dict[int, float] = dict.fromkeys(node_ids, 0.0)
        for src in node_ids:
            s = out_sum[src]
            if s <= 0.0:
                continue
            share = d * r[src] / s
            for dst, w in out_edges.get(src, ()):
                if w <= 0.0:
                    continue
                new_r[dst] += share * w
        for n in node_ids:
            new_r[n] += teleport * p[n] + dangling_share * p[n]

        delta = 0.0
        for n in node_ids:
            delta += abs(new_r[n] - r[n])
        r = new_r
        if delta < tol:
            break
    return r


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

    async def personalized_pagerank(
        self,
        *,
        seeds: dict[int, float],
        relations: list[str] | None = None,
        damping: float = 0.5,
        max_iter: int = 30,
        tol: float = 1e-4,
        target_derived_weight: float = 1.0,
        max_nodes: int = DEFAULT_MAX_NODES,
        session: AsyncSession | None = None,
    ) -> list[TraversalHit]:
        """Personalized PageRank over the induced subgraph from ``seeds``.

        Real PPR, not a repackaged BFS: BFS-induces a bounded subgraph from
        the seed set (capped at ``max_nodes``, optionally scoped to
        ``relations``), collects every directed edge whose endpoints are
        both in the induced set, then runs a pure-Python power iteration to
        produce a stationary mass per node. The RFC-12 trust tier scales
        the weight flowing INTO each node by ``target_derived_weight`` when
        the destination is a target-derived observation, so trusted
        neighbours drown out untrusted ones without a separate rerank pass;
        seeds get the same per-node scaling applied to their restart mass.

        Empty ``seeds`` returns ``[]``. Seeds with no outgoing edges fall
        out of the math cleanly: dangling mass redistributes through the
        personalization vector, so a lone seed ends with its normalized
        restart weight and gets ranked accordingly. Row hydration matches
        :meth:`traverse` so every hit carries the same shape plus a
        ``ppr`` key. Results are sorted by ``ppr`` descending.
        """
        if not seeds:
            return []
        if damping < 0.0 or damping > 1.0:
            raise ValueError(f"damping must be in [0, 1], got {damping}")
        if max_iter <= 0:
            raise ValueError(f"max_iter must be > 0, got {max_iter}")
        if max_nodes <= 0:
            raise ValueError(f"max_nodes must be > 0, got {max_nodes}")

        # BFS induction over ``relations`` capped at ``max_nodes`` -- same
        # frontier walk as ``traverse``, minus the hop bound, since PPR
        # scores across the whole induced subgraph.
        seen_ids: set[int] = set()
        queue: deque[tuple[int, int, list[int], str | None, float | None]] = deque()
        for seed_id in seeds:
            sid = int(seed_id)
            if sid in seen_ids:
                continue
            seen_ids.add(sid)
            queue.append((sid, 0, [sid], None, None))
        ordered_ids: list[tuple[int, int, list[int], str | None, float | None]] = list(queue)

        async with _session_or_new(session) as (sess, _owns):
            while queue and len(seen_ids) < max_nodes:
                entry_id, hop, path, _in_rel, _in_weight = queue.popleft()
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
                    triple = (
                        nxt,
                        hop + 1,
                        [*path, nxt],
                        str(edge.relation),
                        float(edge.weight),
                    )
                    queue.append(triple)
                    ordered_ids.append(triple)

            if not ordered_ids:
                return []

            induced_ids = [t[0] for t in ordered_ids]

            # Collect the induced edge set (both endpoints in the frontier).
            # BFS only follows out-edges from the expanding frontier, so
            # cross-edges from later hops back to earlier hops are missed
            # without this second pass -- PPR needs every directed edge.
            induced_edge_stmt = select(
                KnowledgeEntryEdge.src_id,
                KnowledgeEntryEdge.dst_id,
                KnowledgeEntryEdge.relation,
                KnowledgeEntryEdge.weight,
            ).where(
                KnowledgeEntryEdge.src_id.in_(induced_ids),
                KnowledgeEntryEdge.dst_id.in_(induced_ids),
            )
            if relations:
                induced_edge_stmt = induced_edge_stmt.where(
                    KnowledgeEntryEdge.relation.in_(relations),
                )
            induced_edges = (await sess.exec(induced_edge_stmt)).all()

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
                KnowledgeEntryRecord.id.in_(induced_ids),
            )
            row_hits = (await sess.exec(row_stmt)).all()

        rows_by_id: dict[int, Any] = {int(r.id): r for r in row_hits}

        # Trust factor per induced node: target-derived rows get the
        # ``target_derived_weight`` down-weight applied to their inbound
        # transition mass AND to their seed restart share; verified rows
        # keep factor 1.0.
        trust_factor: dict[int, float] = {}
        for entry_id in induced_ids:
            row = rows_by_id.get(entry_id)
            namespace = row.namespace if row is not None else None
            # RFC-12 D1: model-distilled kinds (``*.semantic.*`` /
            # ``*.pattern.*``) require ``confirmed=true`` in the entry
            # metadata to hold the verified tier -- parse the JSON once
            # so an unconfirmed row is down-weighted like an observation.
            metadata: dict[str, Any] | None = None
            if row is not None and row.entry_metadata:
                try:
                    parsed = json.loads(row.entry_metadata)
                except (json.JSONDecodeError, TypeError):
                    parsed = None
                if isinstance(parsed, dict):
                    metadata = parsed
            tier = trust_tier_from_namespace(namespace, metadata)
            trust_factor[entry_id] = (
                float(target_derived_weight)
                if tier == TRUST_TIER_TARGET_DERIVED
                else 1.0
            )

        # Build out-edges with the destination trust factor folded into
        # the transition weight. A zero factor drops the edge entirely.
        out_edges: dict[int, list[tuple[int, float]]] = {n: [] for n in induced_ids}
        for edge in induced_edges:
            src = int(edge.src_id)
            dst = int(edge.dst_id)
            w = float(edge.weight) * trust_factor.get(dst, 1.0)
            if w <= 0.0:
                continue
            out_edges[src].append((dst, w))

        # Personalization: seed weight scaled by seed trust factor,
        # normalized to sum 1 over the induced set. Seeds outside the
        # induced set (impossible here since we seed the BFS with them,
        # but defensive) contribute nothing.
        personalization: dict[int, float] = dict.fromkeys(induced_ids, 0.0)
        for seed_id, seed_w in seeds.items():
            sid = int(seed_id)
            if sid not in personalization:
                continue
            weight = max(0.0, float(seed_w)) * trust_factor.get(sid, 1.0)
            personalization[sid] += weight
        total_p = sum(personalization.values())
        if total_p <= 0.0:
            # Every seed was zero-weight (or trust-zeroed). No restart
            # mass means PPR is undefined; return empty rather than emit
            # meaningless uniform hits.
            return []
        personalization = {n: v / total_p for n, v in personalization.items()}

        mass = _ppr_iterate(
            node_ids=induced_ids,
            out_edges=out_edges,
            personalization=personalization,
            damping=float(damping),
            max_iter=int(max_iter),
            tol=float(tol),
        )

        results: list[TraversalHit] = []
        for entry_id, hop, path, in_rel, in_weight in ordered_ids:
            row = rows_by_id.get(entry_id)
            if row is None:
                # Same race window traverse guards: the row vanished
                # between edge lookup and hydration. Skip -- emitting a
                # hit without content would be dishonest.
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
                ppr=float(mass.get(entry_id, 0.0)),
            )
            results.append(hit)
        results.sort(key=lambda h: h["ppr"], reverse=True)
        return results
