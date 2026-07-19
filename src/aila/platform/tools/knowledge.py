from __future__ import annotations

import json
import threading

from sqlalchemy import func
from sqlmodel import select, update

from ...platform.contracts._common import utc_now
from ...storage.database import async_session_scope
from ...storage.db_models import KnowledgeEntryRecord
from ..config import PlatformSettings
from ..services.runtime import run_blocking_io
from ._common import Tool, normalize_limit, require_text

__all__ = [
    "KnowledgeRetrieveTool",
    "KnowledgeStoreTool",
]

# Module-level lazy singleton -- never loaded unless a knowledge tool is actually used (per D-08).
_EMBEDDING_MODEL = None
_EMBEDDING_LOCK = threading.Lock()


def _get_embedding_model() -> object:
    """Return the cached SentenceTransformer, loading on first call."""
    global _EMBEDDING_MODEL
    if _EMBEDDING_MODEL is None:
        with _EMBEDDING_LOCK:
            if _EMBEDDING_MODEL is None:
                from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]
                _EMBEDDING_MODEL = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
    return _EMBEDDING_MODEL


class KnowledgeStoreTool(Tool):
    """Platform tool for storing text with semantic embeddings in a namespace-scoped knowledge store.

    The namespace isolates each agent's knowledge from others at the SQL level
    (WHERE namespace = ?). The embedding is computed outside the write transaction
    to keep lock hold time short. Deduplication via _dedup_key prevents
    re-storing identical content across multiple runs.

    The SentenceTransformer model is loaded lazily on first use to avoid import
    overhead when the knowledge store is not needed.
    """

    name = "knowledge_store"
    description = "Store text content with a semantic embedding in the agent's knowledge namespace."
    inputs = {
        "content": {
            "type": "string",
            "description": "Text to embed and store.",
        },
        "metadata": {
            "type": "object",
            "description": "Optional JSON metadata (e.g. source, tags).",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, namespace: str, settings: PlatformSettings):
        # namespace = agent.__class__.__name__ per D-04; validated at construction, not per call
        self.namespace = require_text(namespace, tool_name="KnowledgeStoreTool", field_name="namespace")
        self.settings = settings

    async def forward(self, content: str, metadata: dict | None = None) -> dict:
        content = require_text(content, tool_name="KnowledgeStoreTool", field_name="content")
        meta = dict(metadata or {})
        # Extract dedup sentinel before storing -- do not persist _dedup_key inside entry_metadata (per D-06)
        dedup_key: str | None = meta.pop("_dedup_key", None)

        model = _get_embedding_model()
        # Embedding computed outside transaction -- keep write lock short (per research pitfall 2)
        # pgvector accepts list[float], not raw bytes (Pitfall 3)
        embedding_list = (await run_blocking_io(model.encode, content)).tolist()
        meta_json = json.dumps(meta)

        async with async_session_scope(self.settings) as session:
            existing_id: int | None = None
            if dedup_key is not None:
                stmt = select(KnowledgeEntryRecord.id).where(
                    KnowledgeEntryRecord.namespace == self.namespace,
                    KnowledgeEntryRecord.dedup_key == dedup_key,
                )
                row = (await session.exec(stmt)).first()
                if row is not None:
                    existing_id = row[0]

            if existing_id is not None:
                # UPDATE path -- search_vector auto-maintained by PostgreSQL generated column
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
                await session.exec(update_stmt)
                await session.commit()
                entry_id = existing_id
                operation = "updated"
            else:
                # INSERT path (dedup_key may be None for unconstrained inserts)
                record = KnowledgeEntryRecord(
                    namespace=self.namespace,
                    content=content,
                    embedding=embedding_list,
                    entry_metadata=meta_json,
                    dedup_key=dedup_key,
                    created_at=utc_now(),
                )
                session.add(record)
                await session.commit()
                await session.refresh(record)
                entry_id = record.id
                operation = "inserted"

        return {
            "status": "stored",
            "operation": operation,
            "entry_id": entry_id,
            "namespace": self.namespace,
            "embedding_dim": 384,
            "content_length": len(content),
        }


class KnowledgeRetrieveTool(Tool):
    """Platform tool for pgvector + tsvector hybrid retrieval from the knowledge store.

    Runs two queries -- a pgvector cosine distance KNN query and a PostgreSQL
    tsvector full-text search -- then merges results by scoring each entry on a
    weighted sum: 0.6 * vector_similarity + 0.4 * FTS_rank. Results are
    namespace-scoped so each agent only retrieves its own stored knowledge.

    The SentenceTransformer model is loaded lazily and shared with KnowledgeStoreTool
    via the module-level singleton.
    """

    name = "knowledge_retrieve"
    description = "Retrieve knowledge entries semantically similar to a query, scoped to the agent's namespace."
    inputs = {
        "query": {
            "type": "string",
            "description": "Query text to embed and search for similar knowledge.",
        },
        "limit": {
            "type": "integer",
            "description": "Maximum results to return (default: 10, max: 50).",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, namespace: str, settings: PlatformSettings):
        self.namespace = require_text(namespace, tool_name="KnowledgeRetrieveTool", field_name="namespace")
        self.settings = settings

    async def forward(self, query: str, limit: int | None = None) -> dict:
        query = require_text(query, tool_name="KnowledgeRetrieveTool", field_name="query")
        limit = normalize_limit(limit, default=10, maximum=50)
        model = _get_embedding_model()
        # pgvector accepts list[float], not raw bytes (Pitfall 3)
        query_embedding = (await run_blocking_io(model.encode, query)).tolist()
        candidate_limit = limit * 10

        async with async_session_scope(self.settings) as session:
            # --- Vector leg: pgvector cosine distance ---
            vec_stmt = (
                select(
                    KnowledgeEntryRecord.id,
                    KnowledgeEntryRecord.content,
                    KnowledgeEntryRecord.entry_metadata,
                    KnowledgeEntryRecord.embedding.cosine_distance(query_embedding).label("distance"),
                )
                .where(KnowledgeEntryRecord.namespace == self.namespace)
                .order_by(KnowledgeEntryRecord.embedding.cosine_distance(query_embedding))
                .limit(candidate_limit)
            )
            vec_result = await session.exec(vec_stmt)
            vec_rows = vec_result.all()

            # --- FTS leg: PostgreSQL tsvector + plainto_tsquery ---
            ts_query = func.plainto_tsquery("english", query)
            fts_stmt = (
                select(
                    KnowledgeEntryRecord.id,
                    func.ts_rank(KnowledgeEntryRecord.search_vector, ts_query).label("rank"),
                )
                .where(
                    KnowledgeEntryRecord.namespace == self.namespace,
                    KnowledgeEntryRecord.search_vector.op("@@")(ts_query),
                )
                .order_by(func.ts_rank(KnowledgeEntryRecord.search_vector, ts_query).desc())
                .limit(candidate_limit)
            )
            fts_result = await session.exec(fts_stmt)
            fts_rows = fts_result.all()

            # --- Build lookup maps ---
            vec_map: dict[int, dict] = {
                row.id: {
                    "content": row.content,
                    "entry_metadata": row.entry_metadata,
                    "distance": float(row.distance),
                }
                for row in vec_rows
            }
            fts_map: dict[int, float] = {row.id: float(row.rank) for row in fts_rows}

            # For FTS-only results, fetch content via secondary query since
            # the FTS query only returns id and rank
            fts_only_ids = set(fts_map) - set(vec_map)
            if fts_only_ids:
                content_stmt = select(
                    KnowledgeEntryRecord.id,
                    KnowledgeEntryRecord.content,
                    KnowledgeEntryRecord.entry_metadata,
                ).where(KnowledgeEntryRecord.id.in_(list(fts_only_ids)))
                content_result = await session.exec(content_stmt)
                content_rows = content_result.all()
                fts_content_map: dict[int, dict] = {
                    r.id: {"content": r.content, "entry_metadata": r.entry_metadata}
                    for r in content_rows
                }
            else:
                fts_content_map = {}

        # --- Merge by record ID ---
        all_ids = set(vec_map) | set(fts_map)

        merged: list[dict] = []
        for entry_id in all_ids:
            vec_info = vec_map.get(entry_id)
            fts_rank = fts_map.get(entry_id)

            # Normalise scores -- missing leg contributes 0.0
            # pgvector cosine_distance: 0.0 (identical) to 2.0 (opposite)
            vec_score = 1.0 - (vec_info["distance"] / 2.0) if vec_info is not None else 0.0
            # ts_rank: positive values, typically 0.0-1.0, can exceed 1.0
            fts_score = min(float(fts_rank), 1.0) if fts_rank is not None else 0.0
            combined = 0.6 * vec_score + 0.4 * fts_score

            # Determine result source
            if vec_info is not None and fts_rank is not None:
                source = "hybrid"
            elif vec_info is not None:
                source = "vec_only"
            else:
                source = "fts_only"

            # Use content/metadata from whichever leg has it
            if vec_info is not None:
                content = vec_info["content"]
                entry_metadata = vec_info["entry_metadata"]
            elif entry_id in fts_content_map:
                content = fts_content_map[entry_id]["content"]
                entry_metadata = fts_content_map[entry_id]["entry_metadata"]
            else:
                content = ""
                entry_metadata = "{}"

            merged.append({
                "id": entry_id,
                "content": content,
                "metadata": json.loads(entry_metadata or "{}"),
                "score": round(combined, 6),
                "vec_score": round(vec_score, 6),
                "fts_score": round(fts_score, 6),
                "source": source,
            })

        merged.sort(key=lambda r: r["score"], reverse=True)
        results = merged[:limit]

        return {
            "status": "retrieved",
            "namespace": self.namespace,
            "query": query,
            "count": len(results),
            "hybrid": True,
            "results": results,
        }
