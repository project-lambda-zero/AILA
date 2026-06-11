"""KnowledgeService -- agent knowledge store, RAG retrieval, memory operations per D-02.

Per D-08: embed() delegates to a swappable EmbeddingProvider. Default is
BGE-M3 (1024-dim). Config key: knowledge.embedding_model.

Per D-09: supports three namespace categories:
  - agent:{name} -- auto-populated by agents (existing)
  - user:{team_id}:{category} -- per-team user uploads (future upload API)
  - platform:{category} -- shared admin data (future)
Retrieval methods accept namespace patterns (e.g. "agent:*") for
cross-namespace queries.

Each method accepts an optional external session (from UoW) for atomicity.
When session is None, creates a short-lived session via async_session_scope (SDA-06).
"""

from __future__ import annotations

import json
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, update

from ...platform.contracts._common import utc_now
from ...storage.database import async_session_scope
from ...storage.db_models import KnowledgeEntryRecord
from .embedding import EmbeddingProvider, resolve_provider


@asynccontextmanager
async def _session_or_new(session: AsyncSession | None) -> AsyncGenerator[tuple[AsyncSession, bool], None]:
    """Yield (session, owns_session). If session is None, create a short-lived one."""
    if session is not None:
        yield session, False
    else:
        async with async_session_scope() as new_session:
            yield new_session, True


# --- Namespace helpers per D-09 ---

NAMESPACE_AGENT_PREFIX = "agent:"
NAMESPACE_USER_PREFIX = "user:"
NAMESPACE_PLATFORM_PREFIX = "platform:"


def make_agent_namespace(agent_name: str) -> str:
    """Build agent namespace: agent:{name}."""
    return f"{NAMESPACE_AGENT_PREFIX}{agent_name}"


def make_user_namespace(team_id: str, category: str) -> str:
    """Build user namespace: user:{team_id}:{category}."""
    return f"{NAMESPACE_USER_PREFIX}{team_id}:{category}"


def make_platform_namespace(category: str) -> str:
    """Build platform namespace: platform:{category}."""
    return f"{NAMESPACE_PLATFORM_PREFIX}{category}"


class KnowledgeService:
    """Agent knowledge store, RAG retrieval, memory operations per D-02.

    Per D-08: embed() delegates to a swappable EmbeddingProvider. Default is
    BGE-M3 (1024-dim). Config key: knowledge.embedding_model.

    Per D-09: supports three namespace categories:
      - agent:{name} -- auto-populated by agents (existing)
      - user:{team_id}:{category} -- per-team user uploads (future upload API)
      - platform:{category} -- shared admin data (future)
    Retrieval methods accept namespace patterns (e.g. "agent:*") for
    cross-namespace queries.
    """

    def __init__(
        self,
        provider: EmbeddingProvider | None = None,
    ) -> None:
        self._provider = provider or resolve_provider()

    @property
    def provider(self) -> EmbeddingProvider:
        """Current embedding provider."""
        return self._provider

    # DB column dimension (KnowledgeEntryRecord.embedding is Vector(384)).
    # Set explicitly so embed() truncates from BGE-M3's 1024 down to fit
    # without requiring a DB introspection round-trip per service init.
    _db_dim: int | None = 384

    def embed(self, text: str) -> list[float]:
        """Generate embedding vector using the configured provider.

        Adapts to whatever dimension the provider returns. If the DB column
        has a different dimension, pads or truncates to match. Reads the
        target dimension from the DB on first call.
        """
        vec = self._provider.encode(text)
        if KnowledgeService._db_dim is not None and len(vec) != KnowledgeService._db_dim:
            if len(vec) < KnowledgeService._db_dim:
                vec = vec + [0.0] * (KnowledgeService._db_dim - len(vec))
            else:
                vec = vec[:KnowledgeService._db_dim]
        return vec

    async def store(
        self,
        namespace: str,
        content: str,
        metadata: dict | None = None,
        dedup_key: str | None = None,
        session: AsyncSession | None = None,
    ) -> dict:
        """Store a knowledge entry with embedding per D-02/D-08.

        Embedding is computed OUTSIDE the DB transaction to keep lock hold time short.
        Uses dedup_key for idempotent upsert within a namespace.

        Args:
            namespace: Full namespace string (use make_agent_namespace etc.)
            content: Text to embed and store.
            metadata: Optional JSON-serializable metadata dict.
            dedup_key: Optional dedup sentinel for idempotent upsert.
            session: Optional external session (from UoW).

        Returns:
            Dict with status, operation (inserted/updated), entry_id, namespace, embedding_dim.
        """
        meta_json = json.dumps(metadata or {})
        embedding_list = self.embed(content)

        async with _session_or_new(session) as (sess, owns):
            existing_id: int | None = None
            if dedup_key is not None:
                stmt = select(KnowledgeEntryRecord.id).where(
                    KnowledgeEntryRecord.namespace == namespace,
                    KnowledgeEntryRecord.dedup_key == dedup_key,
                )
                row = (await sess.exec(stmt)).first()
                if row is not None:
                    existing_id = row[0] if isinstance(row, tuple) else row

            if existing_id is not None:
                update_stmt = (
                    update(KnowledgeEntryRecord)
                    .where(KnowledgeEntryRecord.id == existing_id)
                    .values(
                        content=content,
                        embedding=embedding_list,
                        entry_metadata=meta_json,
                        dedup_key=dedup_key,
                    )
                )
                await sess.exec(update_stmt)
                if owns:
                    await sess.commit()
                entry_id = existing_id
                operation = "updated"
            else:
                record = KnowledgeEntryRecord(
                    namespace=namespace,
                    content=content,
                    embedding=embedding_list,
                    entry_metadata=meta_json,
                    dedup_key=dedup_key,
                    created_at=utc_now(),
                )
                sess.add(record)
                # fix §204 — flush unconditionally so `record.id` is
                # populated even when the caller owns the session (UoW
                # pattern). Previously only the `owns` branch refreshed,
                # which left `entry_id = None` on the external-session
                # path and forced pattern_store.create to fall back to a
                # separate KnowledgeService transaction. Flushing here
                # lets callers do a single-UoW atomic create.
                await sess.flush()
                if owns:
                    await sess.commit()
                    await sess.refresh(record)
                entry_id = record.id
                operation = "inserted"

        return {
            "status": "stored",
            "operation": operation,
            "entry_id": entry_id,
            "namespace": namespace,
            "embedding_dim": self._provider.dimension,
            "content_length": len(content),
        }

    async def retrieve(
        self,
        query: str,
        namespaces: list[str] | None = None,
        namespace_patterns: list[str] | None = None,
        limit: int = 10,
        session: AsyncSession | None = None,
    ) -> list[dict]:
        """Retrieve knowledge entries by hybrid pgvector + tsvector search per D-09.

        Supports cross-namespace queries via namespace_patterns (e.g. ["agent:*",
        "user:team123:*"]) or exact namespace list.

        Args:
            query: Text to embed and search for.
            namespaces: Exact namespace strings to search within.
            namespace_patterns: Namespace prefix patterns (e.g. "agent:*").
                Patterns ending in "*" match via LIKE 'prefix%'.
            limit: Maximum results to return (default 10).
            session: Optional external session.

        Returns:
            List of dicts with id, content, metadata, score, vec_score, fts_score, source, namespace.
        """
        query_embedding = self.embed(query)
        candidate_limit = limit * 10

        async with _session_or_new(session) as (sess, owns):
            # Build namespace filter
            ns_filters = self._build_namespace_filters(namespaces, namespace_patterns)

            # --- Vector leg: pgvector cosine distance ---
            vec_stmt = (
                select(
                    KnowledgeEntryRecord.id,
                    KnowledgeEntryRecord.content,
                    KnowledgeEntryRecord.entry_metadata,
                    KnowledgeEntryRecord.namespace,
                    KnowledgeEntryRecord.embedding.cosine_distance(query_embedding).label("distance"),
                )
                .order_by(KnowledgeEntryRecord.embedding.cosine_distance(query_embedding))
                .limit(candidate_limit)
            )
            if ns_filters is not None:
                vec_stmt = vec_stmt.where(ns_filters)
            vec_rows = (await sess.exec(vec_stmt)).all()

            # --- FTS leg: PostgreSQL tsvector + plainto_tsquery ---
            ts_query = func.plainto_tsquery("english", query)
            fts_stmt = (
                select(
                    KnowledgeEntryRecord.id,
                    func.ts_rank(KnowledgeEntryRecord.search_vector, ts_query).label("rank"),
                )
                .where(KnowledgeEntryRecord.search_vector.op("@@")(ts_query))
                .order_by(func.ts_rank(KnowledgeEntryRecord.search_vector, ts_query).desc())
                .limit(candidate_limit)
            )
            if ns_filters is not None:
                fts_stmt = fts_stmt.where(ns_filters)
            fts_rows = (await sess.exec(fts_stmt)).all()

            # Build lookup maps
            vec_map: dict[int, dict] = {
                row.id: {
                    "content": row.content,
                    "entry_metadata": row.entry_metadata,
                    "namespace": row.namespace,
                    "distance": float(row.distance),
                }
                for row in vec_rows
            }
            fts_map: dict[int, float] = {row.id: float(row.rank) for row in fts_rows}

            # Fetch content for FTS-only results
            fts_only_ids = set(fts_map) - set(vec_map)
            fts_content_map: dict[int, dict] = {}
            if fts_only_ids:
                content_stmt = select(
                    KnowledgeEntryRecord.id,
                    KnowledgeEntryRecord.content,
                    KnowledgeEntryRecord.entry_metadata,
                    KnowledgeEntryRecord.namespace,
                ).where(KnowledgeEntryRecord.id.in_(list(fts_only_ids)))
                content_rows = (await sess.exec(content_stmt)).all()
                fts_content_map = {
                    r.id: {"content": r.content, "entry_metadata": r.entry_metadata, "namespace": r.namespace}
                    for r in content_rows
                }

        # Merge by record ID (outside transaction)
        all_ids = set(vec_map) | set(fts_map)
        merged: list[dict] = []
        for entry_id in all_ids:
            vec_info = vec_map.get(entry_id)
            fts_rank = fts_map.get(entry_id)

            vec_score = 1.0 - (vec_info["distance"] / 2.0) if vec_info is not None else 0.0
            fts_score = min(float(fts_rank), 1.0) if fts_rank is not None else 0.0
            combined = 0.6 * vec_score + 0.4 * fts_score

            if vec_info is not None and fts_rank is not None:
                source = "hybrid"
            elif vec_info is not None:
                source = "vec_only"
            else:
                source = "fts_only"

            if vec_info is not None:
                content = vec_info["content"]
                entry_metadata = vec_info["entry_metadata"]
                ns = vec_info["namespace"]
            elif entry_id in fts_content_map:
                content = fts_content_map[entry_id]["content"]
                entry_metadata = fts_content_map[entry_id]["entry_metadata"]
                ns = fts_content_map[entry_id]["namespace"]
            else:
                content = ""
                entry_metadata = "{}"
                ns = ""

            merged.append({
                "id": entry_id,
                "content": content,
                "metadata": json.loads(entry_metadata or "{}"),
                "score": round(combined, 6),
                "vec_score": round(vec_score, 6),
                "fts_score": round(fts_score, 6),
                "source": source,
                "namespace": ns,
            })

        merged.sort(key=lambda r: r["score"], reverse=True)
        return merged[:limit]

    async def delete(
        self,
        namespace: str,
        entry_id: int | None = None,
        dedup_key: str | None = None,
        session: AsyncSession | None = None,
    ) -> int:
        """Delete knowledge entries by namespace + optional entry_id or dedup_key.

        Returns number of records deleted.
        """
        from sqlalchemy import delete as sa_delete

        async with _session_or_new(session) as (sess, owns):
            conditions = [KnowledgeEntryRecord.namespace == namespace]
            if entry_id is not None:
                conditions.append(KnowledgeEntryRecord.id == entry_id)
            if dedup_key is not None:
                conditions.append(KnowledgeEntryRecord.dedup_key == dedup_key)
            stmt = sa_delete(KnowledgeEntryRecord).where(*conditions)
            result = await sess.exec(stmt)
            if owns:
                await sess.commit()
            return result.rowcount

    @staticmethod
    def _build_namespace_filters(
        namespaces: list[str] | None,
        namespace_patterns: list[str] | None,
    ) -> Any | None:
        """Build SQLAlchemy filter for namespace matching per D-09.

        Exact namespaces use IN(). Patterns ending in '*' use LIKE 'prefix%'.
        Returns None if no filtering needed (all namespaces).
        """
        clauses = []
        if namespaces:
            clauses.append(KnowledgeEntryRecord.namespace.in_(namespaces))
        if namespace_patterns:
            for pattern in namespace_patterns:
                if pattern.endswith("*"):
                    prefix = pattern[:-1]
                    clauses.append(KnowledgeEntryRecord.namespace.like(f"{prefix}%"))
                else:
                    clauses.append(KnowledgeEntryRecord.namespace == pattern)
        if not clauses:
            return None
        return or_(*clauses) if len(clauses) > 1 else clauses[0]
