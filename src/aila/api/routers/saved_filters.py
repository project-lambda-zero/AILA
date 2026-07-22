"""Saved filters router for AILA REST API.

Provides CRUD for user-saved filter configurations with team sharing.

Per BE-09 / D-41/D-42: user-scoped; shared filters visible to team (T-138-17).
Per D-27: DataEnvelope response.
Per D-26: offset/limit pagination.
Per D-31: slowapi rate limiting.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import or_, select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import SavedFilterCreate, SavedFilterResponse, SavedFilterUpdate
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.contracts import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import SavedFilterRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/saved-filters", tags=["saved-filters"], dependencies=[Depends(require_user_or_api_key)])


def _record_to_response(r: SavedFilterRecord) -> SavedFilterResponse:
    return SavedFilterResponse(
        id=r.id,
        user_id=r.user_id,
        name=r.name,
        entity_type=r.entity_type,
        filter_json=r.filter_json,
        is_pinned=r.is_pinned,
        shared_with_team=r.shared_with_team,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


@router.get(
    "",
    response_model=DataEnvelope[list[SavedFilterResponse]],
    summary="List saved filters for current user",
)
@limiter.limit("120/minute")
async def list_saved_filters(
    request: Request,
    entity_type: str | None = None,
    limit: int = 50,
    offset: int = 0,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[SavedFilterResponse]]:
    """List user's own saved filters plus team-shared filters (T-138-17).

    team-shared filters (shared_with_team=True) are visible to all users.
    """
    async with async_session_scope() as session:
        stmt = select(SavedFilterRecord).where(
            or_(
                SavedFilterRecord.user_id == auth.user_id,
                SavedFilterRecord.shared_with_team == True,
            )
        )
        if entity_type:
            stmt = stmt.where(SavedFilterRecord.entity_type == entity_type)
        stmt = stmt.order_by(SavedFilterRecord.updated_at.desc())  # type: ignore[attr-defined]
        all_rows = (await session.exec(stmt)).all()

    total = len(all_rows)
    page_rows = all_rows[offset : offset + limit]
    meta = PaginatedMeta(total=total, offset=offset, limit=limit).model_dump()
    return DataEnvelope(data=[_record_to_response(r) for r in page_rows], meta=meta)


@router.post(
    "",
    response_model=DataEnvelope[SavedFilterResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a saved filter",
)
@limiter.limit("60/minute")
async def create_saved_filter(
    request: Request,
    body: SavedFilterCreate,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[SavedFilterResponse]:
    """Create a new saved filter for the current user."""
    async with async_session_scope() as session:
        record = SavedFilterRecord(
            user_id=auth.user_id,
            name=body.name,
            entity_type=body.entity_type,
            filter_json=body.filter_json,
            is_pinned=body.is_pinned,
            shared_with_team=body.shared_with_team,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)

    return DataEnvelope(data=_record_to_response(record))


@router.patch(
    "/{filter_id}",
    response_model=DataEnvelope[SavedFilterResponse],
    summary="Update a saved filter",
)
@limiter.limit("60/minute")
async def update_saved_filter(
    request: Request,
    filter_id: str,
    body: SavedFilterUpdate,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[SavedFilterResponse]:
    """Update a saved filter. Only the owner can update (T-138-17)."""
    async with async_session_scope() as session:
        record = await session.get(SavedFilterRecord, filter_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Saved filter '{filter_id}' not found",
            )
        # Ownership check (T-138-17: prevent cross-user writes)
        if record.user_id != auth.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not own this saved filter",
            )

        if body.name is not None:
            record.name = body.name
        if body.filter_json is not None:
            record.filter_json = body.filter_json
        if body.is_pinned is not None:
            record.is_pinned = body.is_pinned
        if body.shared_with_team is not None:
            record.shared_with_team = body.shared_with_team
        record.updated_at = utc_now()

        session.add(record)
        await session.commit()
        await session.refresh(record)

    return DataEnvelope(data=_record_to_response(record))


@router.delete(
    "/{filter_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a saved filter",
)
@limiter.limit("60/minute")
async def delete_saved_filter(
    request: Request,
    filter_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> None:
    """Delete a saved filter. Only the owner can delete (T-138-17)."""
    async with async_session_scope() as session:
        record = await session.get(SavedFilterRecord, filter_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Saved filter '{filter_id}' not found",
            )
        if record.user_id != auth.user_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not own this saved filter",
            )
        await session.delete(record)
        await session.commit()
