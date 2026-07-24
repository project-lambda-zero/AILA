"""KnowledgeService -- agent knowledge store, RAG retrieval, memory operations per D-02.

Per D-08: embed() delegates to a swappable EmbeddingProvider. Default is
BGE-M3 (1024-dim), selected by the platform config key
``knowledge_embedding_model`` (read once per process at construction).

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

import hashlib
import json
import re
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy import func, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select, update

from ...platform.contracts._common import utc_now
from ...storage.database import async_session_scope
from ...storage.db_models import KnowledgeEntryRecord
from ...storage.registry import ConfigRegistry
from .embedding import EmbeddingProvider, resolve_provider
from .ingestor import DEFAULT_MAX_CHARS, Kind, KnowledgeIngestor

# ``enrich_chunk`` is imported at call time inside ``store`` to break a
# repo-wide import cycle: knowledge -> knowledge_enrichment ->
# platform.agents -> claim_verifier -> platform.mcp.bridges ->
# platform.tools -> storage.memory, which is still initialising via
# storage.__init__ -> memory -> platform.contracts._common the first
# time any test loads ``import aila``. Keeping the enrichment code
# lazy fires the cycle only when a caller actually opts into RFC-12
# enrichment (``store(..., enrich=True)``), by which point the modules
# above are fully initialised.

__all__ = [
    "KnowledgeService",
    "NAMESPACE_AGENT_PREFIX",
    "NAMESPACE_PLATFORM_PREFIX",
    "NAMESPACE_USER_PREFIX",
    "make_agent_namespace",
    "make_platform_namespace",
    "make_user_namespace",
]

# RFC-12 default source_type stamped on the non-chunked store path when the
# caller does not pass a ``kind`` hint. Prose is the dominant knowledge shape
# in the platform today (rubrics, prior findings, patterns rendered as text)
# so it is the safest default; callers ingesting code MUST pass kind="code".
_DEFAULT_SOURCE_TYPE: str = "document"


def _content_hash(text: str) -> str:
    """sha256 hexdigest of the UTF-8 bytes of ``text``.

    Stamped on every knowledge write so drift between the stored content and
    its embedding is detectable without re-embedding. Pure -- unit-testable
    without a DB or a model.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

_UNSET = object()
_configured_model_cache: object = _UNSET


def _configured_embedding_model() -> str | None:
    """Return the operator-configured embedding model name (platform config key
    ``knowledge_embedding_model``), or None to use the provider default.

    Memoized process-wide: the config is read once, so per-access service
    construction pays no repeated DB cost and a change takes effect on the next
    worker/service restart (an embedding-model change requires a re-embed
    anyway).
    """
    global _configured_model_cache
    if _configured_model_cache is _UNSET:
        try:
            _configured_model_cache = ConfigRegistry().get_sync(
                "platform", "knowledge_embedding_model"
            )
        except (OSError, RuntimeError, ValueError):
            _configured_model_cache = None
    return _configured_model_cache  # type: ignore[return-value]


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


# Module-level CAG cache instance so every KnowledgeService in the process
# shares one preload of the stable core. Test-scope isolation uses
# :meth:`StableCoreCache.invalidate` (via ``mod._STABLE_CORE_CACHE.invalidate()``)
# to drop the cached rows between tests.
def _build_stable_core_cache() -> Any:
    """Import and instantiate the process-shared CAG cache.

    Deferred to a helper so the module-level assignment does not trip
    a circular import: :mod:`knowledge_stable_core` imports
    :func:`_session_or_new` from THIS module, so we can only reach
    into it once THIS module has finished defining its top-level
    names.
    """
    from .knowledge_stable_core import StableCoreCache
    return StableCoreCache()


_STABLE_CORE_CACHE: Any = _build_stable_core_cache()


def _stable_core_match(
    query: str,
    entries: list[dict[str, Any]],
    limit: int,
) -> list[dict[str, Any]]:
    """Rank stable-core entries against ``query`` by cheap token overlap.

    Deterministic, no vector or FTS work: tokenise the query, count how
    many query tokens appear as substrings inside each entry's content
    or namespace (case-insensitive), and return the top-``limit``
    matches. Entries that share zero tokens with the query still appear
    at the tail of the list; the CAG contract is that the whole stable
    core is available to the caller, and a token-agnostic query (for
    example ``\"stable-core:\"`` alone) is deliberately handled as
    \"return the entire core, capped at ``limit``\".
    """
    if not entries:
        return []
    lowered = (query or "").lower()
    tokens = [t for t in re.findall(r"[a-z0-9][a-z0-9_-]*", lowered) if len(t) > 1]
    if not tokens:
        return list(entries[:limit])
    scored: list[tuple[int, int, dict[str, Any]]] = []
    for index, entry in enumerate(entries):
        haystack_parts = [str(entry.get("content") or ""), str(entry.get("namespace") or "")]
        haystack = " ".join(haystack_parts).lower()
        overlap = sum(1 for tok in tokens if tok in haystack)
        scored.append((overlap, -index, entry))
    scored.sort(reverse=True)
    return [entry for overlap, _neg_index, entry in scored[:limit] if overlap > 0] or list(entries[:limit])


def _stable_core_hit(entry: dict[str, Any], index: int) -> dict[str, Any]:
    """Adapt a cached stable-core row into the hit shape callers expect.

    Score is a synthetic monotonic decreasing sentinel (1.0, 0.99, ...)
    so the tool caller can rank stable-core hits alongside regular hits
    without a special case, and ``source == \"stable_core\"`` names the
    route the row came from. ``entry_metadata`` is the raw JSON string
    on the row; the caller decodes it exactly as it does for the hybrid
    path.
    """
    score = round(max(0.0, 1.0 - 0.01 * index), 6)
    return {
        "id": int(entry["id"]),
        "content": entry.get("content") or "",
        "metadata": json.loads(entry.get("entry_metadata") or "{}"),
        "score": score,
        "vec_score": 0.0,
        "fts_score": 0.0,
        "source": "stable_core",
        "namespace": entry.get("namespace") or "",
    }


def _graph_hit(node: dict[str, Any]) -> dict[str, Any]:
    """Adapt a :class:`TraversalHit` mapping into the hit shape callers expect.

    Score decays with hop distance (1.0 at the seed, 0.5 at hop 1, and
    so on) so the caller can still sort by relevance. The hop, path,
    and incoming edge label are preserved so a UI can render the
    traversal chain that reached the row.
    """
    hop = int(node.get("hop") or 0)
    score = round(1.0 / float(1 + hop), 6)
    return {
        "id": int(node["id"]),
        "content": node.get("content") or "",
        "metadata": json.loads(node.get("entry_metadata") or "{}"),
        "score": score,
        "vec_score": 0.0,
        "fts_score": 0.0,
        "source": "graph",
        "namespace": node.get("namespace") or "",
        "hop": hop,
        "path": list(node.get("path") or []),
        "incoming_relation": node.get("incoming_relation"),
        "incoming_weight": node.get("incoming_weight"),
    }


def _merge_and_rank(
    vec_map: dict[int, dict],
    fts_map: dict[int, float],
    fts_content_map: dict[int, dict],
    limit: int,
    min_score: float,
) -> list[dict]:
    """Merge the vector and FTS legs into one ranked, floored result list.

    combined = 0.6*vec_score + 0.4*fts_score, where vec_score = 1 - distance/2
    and fts_score = min(rank, 1). Candidates scoring below min_score are dropped
    (the relevance floor, #37). Pure function -- no DB or embedding work -- so
    the ranking and floor are unit-testable without a live model.
    """
    all_ids = set(vec_map) | set(fts_map)
    merged: list[dict] = []
    for entry_id in all_ids:
        vec_info = vec_map.get(entry_id)
        fts_rank = fts_map.get(entry_id)

        vec_score = 1.0 - (vec_info["distance"] / 2.0) if vec_info is not None else 0.0
        fts_score = min(float(fts_rank), 1.0) if fts_rank is not None else 0.0
        combined = 0.6 * vec_score + 0.4 * fts_score
        if combined < min_score:
            continue

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


class KnowledgeService:
    """Agent knowledge store, RAG retrieval, memory operations per D-02.

    Per D-08: embed() delegates to a swappable EmbeddingProvider. Default is
    BGE-M3 (1024-dim), selected by the platform config key
    ``knowledge_embedding_model``.

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
        *,
        llm_client: Any | None = None,
    ) -> None:
        self._provider = provider or resolve_provider(_configured_embedding_model())
        # Optional platform LLM client used only when a caller opts into
        # RFC-12 contextual enrichment on ingest (``store(..., enrich=True)``).
        # The default None keeps the pre-enrichment constructor signature
        # backward-compatible for the many callers that only ever store
        # non-chunked or non-enriched entries.
        self._llm_client = llm_client

    @property
    def provider(self) -> EmbeddingProvider:
        """Current embedding provider."""
        return self._provider

    # DB column dimension (KnowledgeEntryRecord.embedding is Vector(1024)).
    # BGE-M3 (the default provider) emits 1024-dim vectors that pass through
    # unchanged; the 384-dim MiniLM fallback is zero-padded up to 1024 so both
    # providers write the same column width.
    _db_dim: int | None = 1024

    def embed(self, text: str) -> list[float]:
        """Generate embedding vector using the configured provider.

        Returns the provider's native vector. When it is shorter than the DB
        column width (:data:`_db_dim`) the vector is zero-padded; a longer
        vector is truncated. BGE-M3 at 1024 dims matches the column exactly, so
        no adjustment happens on the default path.
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
        *,
        chunked: bool = False,
        kind: Kind | None = None,
        chunk_max_chars: int = DEFAULT_MAX_CHARS,
        enrich: bool = False,
        team_id: str | None = None,
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
            chunked: RFC-12 opt-in. When True, ``content`` is split by
                :class:`KnowledgeIngestor` into boundary-aligned chunks and
                each chunk is written as its own row (one embedding per
                chunk). The default False path is byte-identical to the
                pre-RFC-12 behaviour so existing callers are unaffected.
            kind: Chunking hint used only when ``chunked=True``. ``"code"``
                splits on function/class boundaries; ``"document"`` (the
                default when unset) splits on markdown heading rows.
            chunk_max_chars: Per-chunk character ceiling used only when
                ``chunked=True``. Oversize units are hard-split so no
                emitted chunk violates the ceiling.
            enrich: RFC-12 criterion 2 contextual enrichment opt-in. Only
                effective when ``chunked=True`` and the service was built
                with an ``llm_client``. When enabled, each chunk gets a
                50 to 100 token LLM-written blurb prepended before
                embedding so the vector carries document-level context.
                Default False; enabling costs one LLM completion per chunk.
            team_id: Optional team scoping for the enrichment LLM call's
                cost attribution. Ignored on the non-enriched path.

        Returns:
            Non-chunked path: dict with status, operation (inserted/updated),
            entry_id, namespace, embedding_dim, content_length.
            Chunked path: dict with status, operation='chunked', chunks (list
            of per-chunk result dicts), chunk_count, namespace, embedding_dim,
            content_length.
        """
        if chunked:
            return await self._store_chunked(
                namespace=namespace,
                content=content,
                metadata=metadata,
                dedup_key=dedup_key,
                session=session,
                kind=kind or "document",
                chunk_max_chars=chunk_max_chars,
                enrich=enrich,
                team_id=team_id,
            )

        meta_json = json.dumps(metadata or {})
        embedding_list = self.embed(content)
        # RFC-12 provenance: model_id + content_hash + source_type + updated_at
        # are stamped on every store path (insert AND upsert-update). Read
        # once here so both branches share the same values without diverging.
        model_id = self._provider.model_name
        content_hash = _content_hash(content)
        source_type = str(kind) if kind is not None else _DEFAULT_SOURCE_TYPE
        stamped_at = utc_now()

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
                        model_id=model_id,
                        content_hash=content_hash,
                        source_type=source_type,
                        updated_at=stamped_at,
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
                    model_id=model_id,
                    content_hash=content_hash,
                    source_type=source_type,
                    created_at=stamped_at,
                    updated_at=stamped_at,
                )
                sess.add(record)
                # fix §204 -- flush unconditionally so `record.id` is
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

    async def _store_chunked(
        self,
        *,
        namespace: str,
        content: str,
        metadata: dict | None,
        dedup_key: str | None,
        session: AsyncSession | None,
        kind: Kind,
        chunk_max_chars: int,
        enrich: bool = False,
        team_id: str | None = None,
    ) -> dict:
        """Boundary-aligned multi-row ingestion path (RFC-12).

        Delegates splitting to :class:`KnowledgeIngestor` and writes one
        row per chunk through the standard :meth:`store` path so dedup
        upsert, session ownership, and metadata merging all reuse the
        same code as the single-row path. Each chunk carries its
        ``chunk_index`` / ``chunk_count`` / ``chunk_kind`` in metadata;
        when the caller supplies a ``dedup_key``, per-chunk keys derive
        as ``"{dedup_key}#chunk={index}"`` so a later re-ingest updates
        each chunk in place instead of proliferating rows.

        RFC-12 criterion 2 contextual enrichment: when ``enrich`` is True
        and the service was built with an ``llm_client``, each chunk gets
        a short LLM-written situating blurb prepended before embedding.
        The blurb is captured in ``entry_metadata['context_blurb']`` and
        the original unenriched chunk stays recoverable via
        ``entry_metadata['chunk_original']``; ``entry_metadata['enriched']``
        is set to True on every enriched row. On an empty blurb (LLM
        disabled / empty response) the chunk is stored verbatim and
        ``enriched`` is False -- the enrichment failure never blocks the
        write.
        """
        chunks = KnowledgeIngestor().chunk(
            content, kind=kind, max_chars=chunk_max_chars,
        )
        if not chunks:
            return {
                "status": "empty",
                "operation": "noop",
                "chunks": [],
                "chunk_count": 0,
                "namespace": namespace,
                "embedding_dim": self._provider.dimension,
                "content_length": 0,
            }
        enrichment_active = enrich and self._llm_client is not None
        base_meta: dict = dict(metadata or {})
        chunk_records: list[dict] = []
        total_length = 0
        for index, chunk_text in enumerate(chunks):
            chunk_dedup: str | None = None
            if dedup_key is not None:
                chunk_dedup = f"{dedup_key}#chunk={index}"
            chunk_meta = dict(base_meta)
            chunk_meta["chunk_index"] = index
            chunk_meta["chunk_count"] = len(chunks)
            chunk_meta["chunk_kind"] = kind
            stored_content = chunk_text
            if enrichment_active:
                # Deferred: keeps the import cycle broken (see top of
                # file). PLC0415 is already ignored for knowledge.py in
                # pyproject.toml per-file-ignores.
                from .knowledge_enrichment import enrich_chunk
                blurb = await enrich_chunk(
                    self._llm_client,
                    document=content,
                    chunk=chunk_text,
                    namespace=namespace,
                    team_id=team_id,
                )
                if blurb:
                    stored_content = f"{blurb}\n\n{chunk_text}"
                    chunk_meta["enriched"] = True
                    chunk_meta["context_blurb"] = blurb
                    chunk_meta["chunk_original"] = chunk_text
                else:
                    chunk_meta["enriched"] = False
            single = await self.store(
                namespace=namespace,
                content=stored_content,
                metadata=chunk_meta,
                dedup_key=chunk_dedup,
                session=session,
                kind=kind,
            )
            chunk_records.append(single)
            total_length += len(chunk_text)
        return {
            "status": "stored",
            "operation": "chunked",
            "chunks": chunk_records,
            "chunk_count": len(chunk_records),
            "namespace": namespace,
            "embedding_dim": self._provider.dimension,
            "content_length": total_length,
        }

    async def retrieve(
        self,
        query: str,
        namespaces: list[str] | None = None,
        namespace_patterns: list[str] | None = None,
        limit: int = 10,
        min_score: float = 0.0,
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
            min_score: Relevance floor (#37). Results whose combined
                0.6*vec + 0.4*fts score is below this value are dropped. The
                default 0.0 keeps every candidate (backward-compatible); raise
                it to filter weakly-related hits, since the hybrid search would
                otherwise return the top-k by score even when every candidate
                is only loosely related.
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
                .where(KnowledgeEntryRecord.embedding.is_not(None))
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

        # Merge, floor, and rank outside the transaction (pure, unit-testable).
        return _merge_and_rank(vec_map, fts_map, fts_content_map, limit, min_score)

    async def retrieve_routed(
        self,
        query: str,
        *,
        route: Any | None = None,
        limit: int = 10,
        min_score: float = 0.0,
        namespaces: list[str] | None = None,
        namespace_patterns: list[str] | None = None,
        max_hops: int | None = None,
        graph_seed_limit: int = 1,
        session: AsyncSession | None = None,
    ) -> dict[str, Any]:
        """Adaptive RFC-12 retrieval entrypoint.

        Classifies the query (or accepts an explicit ``route`` override)
        and dispatches to one of three paths -- stable-core CAG, the
        existing hybrid ``retrieve``, or the graph traversal. Every hit
        the caller sees passes through :func:`apply_gate` so the
        ``sanitized_content`` / ``classification`` / ``provenance``
        fields are guaranteed on the result regardless of which path
        served the request. The wrapping dict names the chosen ``route``
        and (for the graph path) the ``hop_bound`` that shaped the
        traversal so the tool caller can surface both in its own return
        payload.

        The ``simple`` path calls :meth:`retrieve` unchanged and only
        overlays the gate + provenance fields; a caller that goes
        through the raw :meth:`retrieve` API keeps its byte-identical
        result shape.
        """
        from .knowledge_gate import apply_gate, apply_gate_many
        from .knowledge_graph import DEFAULT_MAX_HOPS, KnowledgeGraph
        from .knowledge_router import KnowledgeRouter, Route
        from .knowledge_stable_core import STABLE_CORE_TOKEN_PREFIX

        chosen: Route
        if route is None:
            chosen = KnowledgeRouter().classify(query)
        elif isinstance(route, Route):
            chosen = route
        else:
            chosen = Route(str(route))

        hop_bound: int | None = None

        if chosen is Route.STABLE_CORE:
            entries = await _STABLE_CORE_CACHE.entries(session=session)
            matched = _stable_core_match(query, entries, limit)
            hits = [
                _stable_core_hit(entry, index)
                for index, entry in enumerate(matched)
            ]
            gated = [
                apply_gate(hit, entry_row=entry)
                for hit, entry in zip(hits, matched, strict=False)
            ]
        elif chosen is Route.GRAPH:
            hop_bound = int(max_hops) if max_hops is not None else DEFAULT_MAX_HOPS
            # Seed the traversal with a focused hybrid lookup so the
            # BFS entrypoints stay small; the RFC's graph path is
            # \"given a seed match, follow edges N hops\", singular,
            # not a wide fan-out. A caller wanting a broader entry
            # set passes an explicit ``graph_seed_limit`` value.
            seed_limit = max(1, min(int(graph_seed_limit), limit))
            seed_hits = await self.retrieve(
                query=query,
                namespaces=namespaces,
                namespace_patterns=namespace_patterns,
                limit=seed_limit,
                min_score=min_score,
                session=session,
            )
            seed_ids = [int(h["id"]) for h in seed_hits if h.get("id") is not None]
            traversal: list[dict[str, Any]] = []
            if seed_ids:
                traversal = list(
                    await KnowledgeGraph().traverse(
                        seeds=seed_ids,
                        max_hops=hop_bound,
                        session=session,
                    ),
                )
            gated = [
                apply_gate(_graph_hit(node), entry_row=node)
                for node in traversal[:limit]
            ]
        else:
            hits = await self.retrieve(
                query=query,
                namespaces=namespaces,
                namespace_patterns=namespace_patterns,
                limit=limit,
                min_score=min_score,
                session=session,
            )
            rows_by_id = await self._hydrate_provenance_rows(
                [int(h["id"]) for h in hits],
                session=session,
            )
            gated = apply_gate_many(hits, entry_rows=rows_by_id)

        return {
            "status": "retrieved",
            "route": chosen.value,
            "query": query.replace(STABLE_CORE_TOKEN_PREFIX, "", 1).strip()
                if query.lower().startswith(STABLE_CORE_TOKEN_PREFIX)
                else query,
            "count": len(gated),
            "results": gated,
            "hop_bound": hop_bound,
        }

    async def _hydrate_provenance_rows(
        self,
        ids: list[int],
        session: AsyncSession | None = None,
    ) -> dict[int, dict[str, Any]]:
        """Return an ``id -> row-fields`` map for the hits fed to the gate.

        The plain :meth:`retrieve` result carries content + namespace
        + score, not the provenance columns; the gate needs
        ``model_id`` / ``content_hash`` / ``source_type`` / timestamps
        to stamp its ``provenance`` sub-dict. Loading them in a single
        WHERE-IN keeps the overlay cost bounded regardless of the
        result limit.
        """
        if not ids:
            return {}
        async with _session_or_new(session) as (sess, _owns):
            stmt = select(
                KnowledgeEntryRecord.id,
                KnowledgeEntryRecord.namespace,
                KnowledgeEntryRecord.model_id,
                KnowledgeEntryRecord.content_hash,
                KnowledgeEntryRecord.source_type,
                KnowledgeEntryRecord.created_at,
                KnowledgeEntryRecord.updated_at,
            ).where(KnowledgeEntryRecord.id.in_(ids))
            rows = (await sess.exec(stmt)).all()
        return {
            int(r.id): {
                "namespace": r.namespace,
                "model_id": r.model_id,
                "content_hash": r.content_hash,
                "source_type": r.source_type,
                "created_at": r.created_at,
                "updated_at": r.updated_at,
            }
            for r in rows
        }

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
