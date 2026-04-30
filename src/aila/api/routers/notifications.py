"""Notifications router for AILA REST API.

Provides per-user notification persistence with read/unread tracking.

Per RT-05 / D-32: user-scoped — never returns other users' notifications (T-138-18).
Per D-27: DataEnvelope response.
Per D-26: offset/limit pagination.
Per D-31: slowapi rate limiting.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import select

from aila.api.limiter import limiter
from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.schemas.endpoints import NotificationResponse, UnreadNotificationsResponse
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import NotificationRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/notifications", tags=["notifications"], dependencies=[Depends(require_user_or_api_key)])


def _record_to_response(r: NotificationRecord) -> NotificationResponse:
    return NotificationResponse(
        id=r.id,
        user_id=r.user_id,
        title=r.title,
        body=r.body,
        category=r.category,
        source_module=r.source_module,
        source_entity_id=r.source_entity_id,
        is_read=r.is_read,
        created_at=r.created_at,
        read_at=r.read_at,
    )


@router.get(
    "",
    response_model=DataEnvelope[list[NotificationResponse]],
    summary="List notifications for current user",
)
@limiter.limit("120/minute")
async def list_notifications(
    request: Request,
    is_read: bool | None = None,
    limit: int = 50,
    offset: int = 0,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[NotificationResponse]]:
    """List notifications for the current user (T-138-18: scoped to auth.user_id).

    Optionally filter by is_read state.
    """
    async with async_session_scope() as session:
        stmt = (
            select(NotificationRecord)
            .where(NotificationRecord.user_id == auth.user_id)
            .order_by(NotificationRecord.created_at.desc())  # type: ignore[attr-defined]
        )
        if is_read is not None:
            stmt = stmt.where(NotificationRecord.is_read == is_read)
        all_rows = (await session.exec(stmt)).all()

    total = len(all_rows)
    page_rows = all_rows[offset : offset + limit]
    meta = PaginatedMeta(total=total, offset=offset, limit=limit).model_dump()
    return DataEnvelope(data=[_record_to_response(r) for r in page_rows], meta=meta)


@router.get(
    "/unread",
    response_model=DataEnvelope[UnreadNotificationsResponse],
    summary="Get unread notification count and latest 10 unread",
)
@limiter.limit("120/minute")
async def get_unread_notifications(
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[UnreadNotificationsResponse]:
    """Return unread count and the 10 most recent unread notifications.

    Per T-138-18: strictly scoped to auth.user_id.
    """
    async with async_session_scope() as session:
        stmt = (
            select(NotificationRecord)
            .where(
                NotificationRecord.user_id == auth.user_id,
                NotificationRecord.is_read == False,
            )
            .order_by(NotificationRecord.created_at.desc())  # type: ignore[attr-defined]
        )
        all_unread = (await session.exec(stmt)).all()

    unread_count = len(all_unread)
    latest_10 = all_unread[:10]
    return DataEnvelope(
        data=UnreadNotificationsResponse(
            unread_count=unread_count,
            items=[_record_to_response(r) for r in latest_10],
        ),
        meta={"unread_count": unread_count},
    )


@router.post(
    "/{notification_id}/read",
    response_model=DataEnvelope[NotificationResponse],
    summary="Mark a notification as read",
)
@limiter.limit("120/minute")
async def mark_notification_read(
    request: Request,
    notification_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[NotificationResponse]:
    """Mark a notification as read. Sets read_at timestamp.

    Per T-138-18: validates notification belongs to auth.user_id.
    """
    async with async_session_scope() as session:
        record = await session.get(NotificationRecord, notification_id)
        if record is None or record.user_id != auth.user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Notification '{notification_id}' not found",
            )
        if not record.is_read:
            record.is_read = True
            record.read_at = utc_now()
            session.add(record)
            await session.commit()
            await session.refresh(record)

    return DataEnvelope(data=_record_to_response(record))


@router.post(
    "/read-all",
    response_model=DataEnvelope[dict[str, int]],
    summary="Mark all notifications as read",
)
@limiter.limit("30/minute")
async def mark_all_notifications_read(
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[dict[str, int]]:
    """Mark all unread notifications for the current user as read."""
    now = utc_now()
    async with async_session_scope() as session:
        stmt = select(NotificationRecord).where(
            NotificationRecord.user_id == auth.user_id,
            NotificationRecord.is_read == False,
        )
        unread = (await session.exec(stmt)).all()
        count = len(unread)
        for record in unread:
            record.is_read = True
            record.read_at = now
            session.add(record)
        if count > 0:
            await session.commit()

    return DataEnvelope(data={"marked_read": count}, meta={"user_id": auth.user_id})


@router.delete(
    "/{notification_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a notification",
)
@limiter.limit("60/minute")
async def delete_notification(
    request: Request,
    notification_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> None:
    """Delete a notification. Per T-138-18: validates ownership before deletion."""
    async with async_session_scope() as session:
        record = await session.get(NotificationRecord, notification_id)
        if record is None or record.user_id != auth.user_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Notification '{notification_id}' not found",
            )
        await session.delete(record)
        await session.commit()
