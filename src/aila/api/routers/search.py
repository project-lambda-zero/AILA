"""Global search router for AILA REST API.

Provides GET /search?q=term: searches across systems, findings, sessions,
and module-registered entities.

Per BE-06 / D-28: reader+ role, parameterized ILIKE queries (T-138-15).
Per D-27: DataEnvelope response.
Per D-26: offset/limit pagination.
Per D-31: slowapi rate limiting (T-138-24).
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Query, Request

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import SearchResult
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord, SessionRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/search", tags=["search"], dependencies=[Depends(require_user_or_api_key)])

_MAX_PER_TYPE = 50  # T-138-24: limit results per entity type


@router.get("", response_model=DataEnvelope[list[SearchResult]], summary="Global search across platform entities")
@limiter.limit("60/minute")
async def global_search(
    request: Request,
    q: str = Query(min_length=1, max_length=200, description="Search query"),
    entity_types: str | None = Query(default=None, description="Comma-separated entity types to filter"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[SearchResult]]:
    """Search across systems, findings, sessions, and module entities.

    Per T-138-15: uses parameterized ILIKE queries -- never string concatenation.
    Per T-138-24: max 50 results per entity type before pagination slice.
    """
    requested_types: set[str] | None = None
    if entity_types:
        requested_types = {t.strip() for t in entity_types.split(",") if t.strip()}

    results: list[SearchResult] = []
    pattern = f"%{q}%"

    async with async_session_scope() as session:
        # Search systems by name or host (parameterized -- no SQL injection)
        if requested_types is None or "system" in requested_types:
            from sqlalchemy import or_
            from sqlmodel import select

            stmt = (
                select(ManagedSystemRecord)
                .where(
                    or_(
                        ManagedSystemRecord.name.ilike(pattern),  # type: ignore[attr-defined]
                        ManagedSystemRecord.host.ilike(pattern),  # type: ignore[attr-defined]
                        ManagedSystemRecord.description.ilike(pattern),  # type: ignore[attr-defined]
                    )
                )
                .limit(_MAX_PER_TYPE)
            )
            rows = (await session.exec(stmt)).all()
            for row in rows:
                results.append(
                    SearchResult(
                        entity_type="system",
                        entity_id=str(row.id),
                        title=row.name,
                        snippet=f"Host: {row.host} -- {row.description}",
                    )
                )

        # Search sessions by title
        if requested_types is None or "session" in requested_types:
            from sqlmodel import select

            stmt = (
                select(SessionRecord)
                .where(SessionRecord.title.ilike(pattern))  # type: ignore[attr-defined]
                .where(SessionRecord.user_id == auth.user_id)
                .limit(_MAX_PER_TYPE)
            )
            rows = (await session.exec(stmt)).all()
            for row in rows:
                results.append(
                    SearchResult(
                        entity_type="session",
                        entity_id=row.id,
                        title=row.title,
                        snippet=f"Session created {row.created_at.date()}",
                    )
                )

        # Search findings through the vulnerability module's public search surface
        if requested_types is None or "finding" in requested_types or "module" in requested_types:
            platform = getattr(request.app.state, "platform", None)
            if platform is not None:
                try:
                    module = platform.runtime.module_registry.require("vulnerability")
                    if hasattr(module, "search_entities"):
                        entities = module.search_entities(q, limit=_MAX_PER_TYPE)
                        if asyncio_iscoroutinefunction(module.search_entities):
                            entities = await entities
                        for entity in entities:
                            results.append(
                                SearchResult(
                                    entity_type=str(entity.get("entity_type", "module")),
                                    entity_id=str(entity.get("entity_id", "")),
                                    title=str(entity.get("title", "")),
                                    snippet=str(entity.get("snippet", "")),
                                    module_id="vulnerability",
                                )
                            )
                except Exception:
                    _log.debug("vulnerability search_entities failed", exc_info=True)


    total = len(results)
    page_results = results[offset : offset + limit]
    meta = PaginatedMeta(total=total, offset=offset, limit=limit).model_dump()
    return DataEnvelope(data=page_results, meta=meta)


def asyncio_iscoroutinefunction(fn: object) -> bool:
    import asyncio
    return asyncio.iscoroutinefunction(fn)
