"""Saved filters router for AILA REST API.

Provides CRUD for user-saved filter configurations with team sharing.

Per BE-09 / D-41/D-42: user-scoped; shared filters visible to team (T-138-17).
Per D-27: DataEnvelope response.
Per D-26: offset/limit pagination.
Per D-31: slowapi rate limiting.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func
from sqlmodel import or_, select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import SavedFilterCreate, SavedFilterResponse, SavedFilterUpdate
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.contracts import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import SavedFilterRecord, UserRecord

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

    #36: ``shared_with_team=True`` filters are visible only to callers whose
    team matches the filter owner's team; a god-tier admin (``team_id`` is
    None, TEAM-06) sees every shared filter regardless of team. Without this
    join, a filter that any user marked ``shared_with_team=True`` leaked to
    every other team on the platform. ``SavedFilterRecord`` has no team_id
    column, so ownership is resolved through the creator's ``UserRecord.team_id``.
    """
    async with async_session_scope() as session:
        # Own filters are always visible. The team-shared branch is scoped to
        # the caller's team by joining through UserRecord.team_id -- admins
        # (auth.team_id is None) skip the join and see every shared filter.
        own = SavedFilterRecord.user_id == auth.user_id
        if auth.team_id is None:
            shared = SavedFilterRecord.shared_with_team.is_(True)
            visibility = or_(own, shared)
        else:
            team_member_ids = select(UserRecord.id).where(
                UserRecord.team_id == auth.team_id
            )
            shared = SavedFilterRecord.shared_with_team.is_(True) & (
                SavedFilterRecord.user_id.in_(team_member_ids)  # type: ignore[attr-defined]
            )
            visibility = or_(own, shared)

        filters: list[Any] = [visibility]
        if entity_type:
            filters.append(SavedFilterRecord.entity_type == entity_type)

        # #204: SQL count + LIMIT/OFFSET instead of loading every visible row.
        count_stmt = select(func.count(SavedFilterRecord.id)).where(*filters)
        total = int((await session.exec(count_stmt)).one())

        stmt = (
            select(SavedFilterRecord)
            .where(*filters)
            .order_by(SavedFilterRecord.updated_at.desc())  # type: ignore[attr-defined]
            .offset(offset)
            .limit(limit)
        )
        page_rows = (await session.exec(stmt)).all()

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
