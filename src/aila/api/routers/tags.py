"""Tags router for AILA REST API.

Provides tag vocabulary management (admin) and tag assignment to systems (operator+).

Per BE-07 / D-40: admin-managed vocabulary, operator+ for assignment (T-138-23).
Per D-27: DataEnvelope response.
Per D-31: slowapi rate limiting.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN, ROLE_OPERATOR
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import TagAssignRequest, TagResponse, TagVocabCreate, TagVocabResponse
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.storage.database import async_session_scope
from aila.storage.db_models import AssetTagVocabRecord, ManagedSystemRecord

__all__ = ["router"]


router = APIRouter(prefix="/tags", tags=["tags"], dependencies=[Depends(require_user_or_api_key)])

_ROLE_LEVELS: dict[str, int] = {"reader": 0, "operator": 1, "admin": 2}


def _require_admin(auth: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    if _ROLE_LEVELS.get(auth.role, -1) < _ROLE_LEVELS[ROLE_ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{auth.role}'",
        )
    return auth


def _require_operator(auth: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    if _ROLE_LEVELS.get(auth.role, -1) < _ROLE_LEVELS[ROLE_OPERATOR]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_OPERATOR}' role or higher; current role: '{auth.role}'",
        )
    return auth


# ---------------------------------------------------------------------------
# Vocabulary management (admin only) -- T-138-23
# ---------------------------------------------------------------------------


@router.get(
    "/vocabulary",
    response_model=DataEnvelope[list[TagVocabResponse]],
    summary="List tag key vocabulary",
)
@limiter.limit("120/minute")
async def list_vocabulary(
    request: Request,
    limit: int = 100,
    offset: int = 0,
    auth: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[TagVocabResponse]]:
    """List all admin-managed tag key vocabulary entries."""
    async with async_session_scope() as session:
        stmt = select(AssetTagVocabRecord).order_by(AssetTagVocabRecord.tag_key).offset(offset).limit(limit)
        rows = (await session.exec(stmt)).all()
        total_stmt = select(AssetTagVocabRecord)
        total = len((await session.exec(total_stmt)).all())

    items = [
        TagVocabResponse(
            id=r.id,
            tag_key=r.tag_key,
            description=r.description,
            is_system_default=r.is_system_default,
            created_at=r.created_at,
        )
        for r in rows
    ]
    meta = PaginatedMeta(total=total, offset=offset, limit=limit).model_dump()
    return DataEnvelope(data=items, meta=meta)


@router.post(
    "/vocabulary",
    response_model=DataEnvelope[TagVocabResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create tag key in vocabulary",
)
@limiter.limit("30/minute")
async def create_vocabulary_entry(
    request: Request,
    body: TagVocabCreate,
    auth: AuthContext = Depends(_require_admin),
) -> DataEnvelope[TagVocabResponse]:
    """Create a new tag key in the admin-managed vocabulary."""
    async with async_session_scope() as session:
        record = AssetTagVocabRecord(
            tag_key=body.tag_key,
            description=body.description,
        )
        session.add(record)
        try:
            await session.commit()
        except IntegrityError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Tag key '{body.tag_key}' already exists in vocabulary",
            )
        await session.refresh(record)

    return DataEnvelope(
        data=TagVocabResponse(
            id=record.id,
            tag_key=record.tag_key,
            description=record.description,
            is_system_default=record.is_system_default,
            created_at=record.created_at,
        )
    )


@router.delete(
    "/vocabulary/{tag_key}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete tag key from vocabulary",
)
@limiter.limit("30/minute")
async def delete_vocabulary_entry(
    request: Request,
    tag_key: str,
    auth: AuthContext = Depends(_require_admin),
) -> None:
    """Remove a tag key from the vocabulary. System defaults cannot be deleted."""
    async with async_session_scope() as session:
        stmt = select(AssetTagVocabRecord).where(AssetTagVocabRecord.tag_key == tag_key)
        record = (await session.exec(stmt)).first()
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Tag key '{tag_key}' not found in vocabulary",
            )
        if record.is_system_default:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Tag key '{tag_key}' is a system default and cannot be deleted",
            )
        await session.delete(record)
        await session.commit()


# ---------------------------------------------------------------------------
# Tag assignment on systems (operator+) -- T-138-23
# ---------------------------------------------------------------------------


@router.get(
    "/systems/{system_id}",
    response_model=DataEnvelope[list[TagResponse]],
    summary="List tags on a system",
)
@limiter.limit("120/minute")
async def list_system_tags(
    request: Request,
    system_id: int,
    auth: AuthContext = Depends(_require_operator),
) -> DataEnvelope[list[TagResponse]]:
    """List all tags assigned to a system."""
    platform = getattr(request.app.state, "platform", None)
    if platform is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- vulnerability module unavailable",
        )
    module = platform.runtime.module_registry.require("vulnerability")
    async with async_session_scope() as session:
        sys_record = await session.get(ManagedSystemRecord, system_id)
        if sys_record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"System {system_id} not found",
            )
        rows = await module.list_system_tags(system_id, session)
    items = [
        TagResponse(
            id=row.get("id"),
            system_id=row.get("system_id"),
            tag_key=str(row.get("tag_key") or ""),
            tag_value=str(row.get("tag_value") or ""),
            created_at=row.get("created_at"),
        )
        for row in rows
    ]
    return DataEnvelope(data=items, meta={"total": len(items)})


@router.post(
    "/systems/{system_id}",
    response_model=DataEnvelope[TagResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Assign tag to a system",
)
@limiter.limit("60/minute")
async def assign_system_tag(
    request: Request,
    system_id: int,
    body: TagAssignRequest,
    auth: AuthContext = Depends(_require_operator),
) -> DataEnvelope[TagResponse]:
    """Attach a vocabulary tag to the system, creating the row if absent."""
    async with async_session_scope() as session:
        sys_record = await session.get(ManagedSystemRecord, system_id)
        if sys_record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"System {system_id} not found",
            )

        vocab_stmt = select(AssetTagVocabRecord).where(AssetTagVocabRecord.tag_key == body.tag_key)
        vocab_entry = (await session.exec(vocab_stmt)).first()
        if vocab_entry is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Tag key '{body.tag_key}' is not in vocabulary. Add it via POST /tags/vocabulary first.",
            )

        platform = getattr(request.app.state, "platform", None)
        if platform is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Platform not initialized -- vulnerability module unavailable",
            )
        module = platform.runtime.module_registry.require("vulnerability")
        try:
            row = await module.assign_system_tag(system_id, body.tag_key, body.tag_value, session)
        except IntegrityError:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Tag key '{body.tag_key}' already assigned to system {system_id}",
            )

    return DataEnvelope(
        data=TagResponse(
            id=row.get("id"),
            system_id=row.get("system_id"),
            tag_key=str(row.get("tag_key") or ""),
            tag_value=str(row.get("tag_value") or ""),
            created_at=row.get("created_at"),
        )
    )


@router.delete(
    "/systems/{system_id}/{tag_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remove tag from a system",
)
@limiter.limit("60/minute")
async def delete_system_tag(
    request: Request,
    system_id: int,
    tag_id: int,
    auth: AuthContext = Depends(_require_operator),
) -> None:
    """Remove a tag from a system."""
    platform = getattr(request.app.state, "platform", None)
    if platform is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- vulnerability module unavailable",
        )
    module = platform.runtime.module_registry.require("vulnerability")
    async with async_session_scope() as session:
        deleted = await module.delete_system_tag(system_id, tag_id, session)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tag {tag_id} not found on system {system_id}",
        )
