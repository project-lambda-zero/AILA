"""Admin RAG knowledge-store router.

Three god-tier-admin endpoints that surface the ``KnowledgeEntryRecord``
corpus + ``KnowledgeEntryEdge`` graph and let an operator run an ad-hoc
retrieval against the same routed path the agent tools use:

* ``GET /platform/knowledge/stats`` -- total counts + top-N ``GROUP BY``
  breakdown across ``namespace`` / ``source_type`` / ``model_id`` plus
  the edge table row count.
* ``GET /platform/knowledge/entries`` -- paged entry list with
  optional ``namespace`` (exact or ``prefix*``), ``source_type``, and
  ``q`` filters. ``q`` reuses ``plainto_tsquery('english', q)`` against
  the same ``search_vector`` clause :meth:`KnowledgeService.retrieve`
  uses, so operator search matches what the retrieval path sees. The
  returned ``total`` is the filtered row count, not the page size.
* ``POST /platform/knowledge/search`` -- routes through
  :meth:`KnowledgeService.retrieve_routed` with the same no-arg
  construction the agent tools do, so the operator sees the same
  ranking + trust/decay + gate the agent would.

The knowledge store is a platform-wide singleton (no team scoping on
the row) so this router mirrors the god-tier admin gate in
:mod:`aila.api.routers.platform_corpus` -- ``team_id`` MUST be ``None``.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.knowledge import (
    KnowledgeEntriesPage,
    KnowledgeEntryView,
    KnowledgeHit,
    KnowledgeStats,
    KnowledgeStatsBucket,
)
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.services.knowledge_graph import KnowledgeEntryEdge
from aila.storage.database import async_session_scope
from aila.storage.db_models import KnowledgeEntryRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

# Cap on how many buckets each ``GROUP BY`` breakdown returns. Kept in
# double-digits so an operator sees the long tail without the response
# growing linearly with a corpus of thousands of distinct namespaces.
_STATS_BUCKET_LIMIT = 50


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """God-tier admin gate.

    The knowledge store has no ``team_id`` column: rows are shared
    across every module + team. A team-scoped admin has no business
    browsing another team's ingested content, so ``team_id`` MUST be
    ``None`` (same rule as :mod:`aila.api.routers.platform_corpus`).
    """
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Knowledge-store admin is restricted to god-tier administrators."
            ),
        )
    return ctx


router = APIRouter(
    prefix="/platform/knowledge",
    tags=["admin-knowledge"],
    dependencies=[Depends(_require_admin)],
)


class KnowledgeSearchRequest(BaseModel):
    """Ad-hoc retrieval body -- mirrors ``retrieve_routed`` arguments."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(..., min_length=1, max_length=2000)
    namespace_prefix: str | None = Field(
        default=None,
        max_length=256,
        description=(
            "Optional namespace scoping. Trailing '*' or plain prefix "
            "is expanded to a namespace_patterns entry; an exact string "
            "without '*' matches only that namespace."
        ),
    )
    top_k: int = Field(default=10, ge=1, le=50)


def _bucket_rows(rows: list[Any]) -> list[KnowledgeStatsBucket]:
    """Convert ``(key, count)`` row tuples to schema buckets."""
    return [KnowledgeStatsBucket(key=key, count=int(count)) for key, count in rows]


def _parse_entry_metadata(raw: str | None) -> dict[str, Any]:
    """Parse a stored ``entry_metadata`` JSON text blob.

    Every write path serializes a JSON object; a malformed row is
    logged and treated as empty rather than blowing up the whole page.
    """
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError) as exc:
        _log.warning("knowledge entry_metadata unparseable: %s", exc)
        return {}
    if not isinstance(parsed, dict):
        _log.warning(
            "knowledge entry_metadata not a JSON object: %s", type(parsed).__name__,
        )
        return {}
    return parsed


@router.get(
    "/stats",
    response_model=DataEnvelope[KnowledgeStats],
    summary="Knowledge store totals + top-N grouped breakdowns",
)
@limiter.limit("60/minute")
async def read_knowledge_stats(
    request: Request,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[KnowledgeStats]:
    """Return corpus + graph totals plus top-N breakdowns.

    Every count is a live SQL aggregate against the underlying tables
    -- there is no cache. ``by_namespace`` / ``by_source_type`` /
    ``by_model`` are capped at :data:`_STATS_BUCKET_LIMIT` buckets
    ordered by descending count so the response size is bounded even
    when the corpus has thousands of distinct values.
    """
    del ctx
    async with async_session_scope() as session:
        total = int(
            (
                await session.exec(
                    select(func.count()).select_from(KnowledgeEntryRecord)
                )
            ).one()
        )
        edge_count = int(
            (
                await session.exec(
                    select(func.count()).select_from(KnowledgeEntryEdge)
                )
            ).one()
        )

        ns_rows = list(
            (
                await session.exec(
                    select(
                        KnowledgeEntryRecord.namespace,
                        func.count().label("cnt"),
                    )
                    .group_by(KnowledgeEntryRecord.namespace)
                    .order_by(func.count().desc())
                    .limit(_STATS_BUCKET_LIMIT)
                )
            ).all()
        )
        src_rows = list(
            (
                await session.exec(
                    select(
                        KnowledgeEntryRecord.source_type,
                        func.count().label("cnt"),
                    )
                    .group_by(KnowledgeEntryRecord.source_type)
                    .order_by(func.count().desc())
                    .limit(_STATS_BUCKET_LIMIT)
                )
            ).all()
        )
        model_rows = list(
            (
                await session.exec(
                    select(
                        KnowledgeEntryRecord.model_id,
                        func.count().label("cnt"),
                    )
                    .group_by(KnowledgeEntryRecord.model_id)
                    .order_by(func.count().desc())
                    .limit(_STATS_BUCKET_LIMIT)
                )
            ).all()
        )

    return DataEnvelope(
        data=KnowledgeStats(
            total_entries=total,
            edge_count=edge_count,
            by_namespace=_bucket_rows(ns_rows),
            by_source_type=_bucket_rows(src_rows),
            by_model=_bucket_rows(model_rows),
        ),
        meta={},
    )


@router.get(
    "/entries",
    response_model=DataEnvelope[KnowledgeEntriesPage],
    summary="Paged knowledge entries with optional namespace / source_type / FTS filters",
)
@limiter.limit("60/minute")
async def list_knowledge_entries(
    request: Request,
    namespace: str | None = Query(
        default=None,
        max_length=256,
        description=(
            "Exact match, or trailing '*' for prefix (e.g. 'agent:*'). "
            "Omit to search every namespace."
        ),
    ),
    source_type: str | None = Query(
        default=None,
        max_length=64,
        description="Exact match on the source_type column.",
    ),
    q: str | None = Query(
        default=None,
        min_length=1,
        max_length=500,
        description=(
            "Full-text query -- routed through plainto_tsquery('english', q) "
            "against the same search_vector clause the retrieval path uses."
        ),
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[KnowledgeEntriesPage]:
    """List entries with optional filters.

    ``namespace`` accepts either an exact string or a trailing-``*``
    prefix; without ``*`` the filter is exact equality so an operator
    can page a single namespace deterministically.

    ``q`` reuses the ``@@ plainto_tsquery('english', q)`` clause
    :meth:`KnowledgeService.retrieve` runs, so an admin FTS query
    matches the same rows the agent retrieval path would consider
    (subject to the vector leg's cosine ranking, which is not
    reproduced here -- this endpoint is a lister, not a retriever).
    """
    del ctx

    filters: list[Any] = []
    if namespace is not None and namespace != "":
        if namespace.endswith("*"):
            prefix = namespace[:-1]
            # LIKE with escaped prefix -- pattern chars other than '*' are
            # already fine because ConfigDict-style callers pass literal
            # namespaces; escape the LIKE wildcards defensively so a
            # namespace containing an underscore does not widen the match.
            escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            filters.append(
                KnowledgeEntryRecord.namespace.like(f"{escaped}%", escape="\\")  # type: ignore[attr-defined]
            )
        else:
            filters.append(KnowledgeEntryRecord.namespace == namespace)
    if source_type is not None and source_type != "":
        filters.append(KnowledgeEntryRecord.source_type == source_type)
    if q:
        ts_query = func.plainto_tsquery("english", q)
        filters.append(KnowledgeEntryRecord.search_vector.op("@@")(ts_query))  # type: ignore[attr-defined]

    async with async_session_scope() as session:
        total = int(
            (
                await session.exec(
                    select(func.count())
                    .select_from(KnowledgeEntryRecord)
                    .where(*filters)
                )
            ).one()
        )
        page_rows = list(
            (
                await session.exec(
                    select(
                        KnowledgeEntryRecord.id,
                        KnowledgeEntryRecord.namespace,
                        KnowledgeEntryRecord.content,
                        KnowledgeEntryRecord.source_type,
                        KnowledgeEntryRecord.model_id,
                        KnowledgeEntryRecord.created_at,
                        KnowledgeEntryRecord.entry_metadata,
                    )
                    .where(*filters)
                    .order_by(KnowledgeEntryRecord.created_at.desc())  # type: ignore[attr-defined]
                    .offset(offset)
                    .limit(limit)
                )
            ).all()
        )

    items = [
        KnowledgeEntryView(
            id=int(row.id),
            namespace=row.namespace,
            content=row.content,
            source_type=row.source_type,
            model_id=row.model_id,
            created_at=row.created_at,
            entry_metadata=_parse_entry_metadata(row.entry_metadata),
        )
        for row in page_rows
    ]
    return DataEnvelope(
        data=KnowledgeEntriesPage(items=items, total=total),
        meta={"total": total, "offset": offset, "limit": limit},
    )


@router.post(
    "/search",
    response_model=DataEnvelope[list[KnowledgeHit]],
    summary="Routed retrieval against the knowledge store",
)
@limiter.limit("30/minute")
async def knowledge_search(
    request: Request,
    body: KnowledgeSearchRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[KnowledgeHit]]:
    """Run an ad-hoc retrieval.

    The service is constructed the same way the agent tools construct
    it (``KnowledgeService()``, no arguments -- see
    ``aila.platform.services.factory``, ``aila.modules.vr.agents``,
    ``aila.platform.mcp.bridges.knowledge``): default embedding
    provider, no LLM enrichment, no ambient team context. That keeps
    the operator's view of retrieval identical to what an agent turn
    would see.

    ``namespace_prefix`` is mapped to ``namespace_patterns`` when it
    contains a trailing ``*`` and to ``namespaces`` when it is an exact
    string; omitting it searches every namespace.

    ``(ValueError, RuntimeError, OSError)`` bubble up as ``502`` so the
    operator sees a real failure mode (bad query, provider outage,
    pgvector unavailable) instead of a generic 500.
    """
    del ctx

    namespaces: list[str] | None = None
    namespace_patterns: list[str] | None = None
    prefix = (body.namespace_prefix or "").strip()
    if prefix:
        if prefix.endswith("*"):
            namespace_patterns = [prefix]
        else:
            namespaces = [prefix]

    service = KnowledgeService()
    try:
        routed = await service.retrieve_routed(
            query=body.query,
            route="simple",
            limit=body.top_k,
            namespaces=namespaces,
            namespace_patterns=namespace_patterns,
        )
    except (ValueError, RuntimeError, OSError) as exc:
        _log.warning(
            "knowledge_search failed for query=%r prefix=%r: %s",
            body.query,
            body.namespace_prefix,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"knowledge retrieval failed: {type(exc).__name__}",
        ) from exc

    results = routed.get("results") or []
    hits: list[KnowledgeHit] = []
    for hit in results:
        entry_id = hit.get("id")
        if entry_id is None:
            # A hit missing an id cannot be linked back to a row -- drop
            # it rather than surface a synthetic zero.
            continue
        provenance = hit.get("provenance") or {}
        hits.append(
            KnowledgeHit(
                id=int(entry_id),
                namespace=str(hit.get("namespace") or provenance.get("namespace") or ""),
                content=str(hit.get("content") or ""),
                score=float(hit.get("score") or 0.0),
                source_type=provenance.get("source_type") or hit.get("source_type"),
                model_id=provenance.get("model_id") or hit.get("model_id"),
            )
        )

    return DataEnvelope(
        data=hits,
        meta={
            "route": routed.get("route"),
            "count": len(hits),
            "hop_bound": routed.get("hop_bound"),
        },
    )
