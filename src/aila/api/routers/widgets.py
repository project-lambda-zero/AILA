"""Widget layout router for AILA REST API.

Provides GET/PUT /widgets/layout: per-user widget layout JSON persistence.

Per BE-04 / D-35: one layout record per user (upsert).
Per T-138-19: max 64KB layout_json (enforced at schema layer).
Per D-27: DataEnvelope response.
Per D-31: slowapi rate limiting.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import WidgetLayoutRequest, WidgetLayoutResponse
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import WidgetLayoutRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/widgets", tags=["widgets"], dependencies=[Depends(require_user_or_api_key)])

_DEFAULT_LAYOUT = "{}"


@router.get(
    "/layout",
    response_model=DataEnvelope[WidgetLayoutResponse],
    summary="Get widget layout for current user",
)
@limiter.limit("120/minute")
async def get_widget_layout(
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[WidgetLayoutResponse]:
    """Return the current user's widget layout JSON.

    If no layout has been saved, returns the default empty layout.
    """
    async with async_session_scope() as session:
        stmt = select(WidgetLayoutRecord).where(WidgetLayoutRecord.user_id == auth.user_id)
        record = (await session.exec(stmt)).first()

    if record is None:
        now = utc_now()
        return DataEnvelope(
            data=WidgetLayoutResponse(
                user_id=auth.user_id,
                layout_json=_DEFAULT_LAYOUT,
                updated_at=now,
            ),
            meta={"is_default": True},
        )

    return DataEnvelope(
        data=WidgetLayoutResponse(
            user_id=record.user_id,
            layout_json=record.layout_json,
            updated_at=record.updated_at,
        ),
        meta={"is_default": False},
    )


@router.put(
    "/layout",
    response_model=DataEnvelope[WidgetLayoutResponse],
    summary="Upsert widget layout for current user",
)
@limiter.limit("60/minute")
async def put_widget_layout(
    request: Request,
    body: WidgetLayoutRequest,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[WidgetLayoutResponse]:
    """Save or replace the widget layout for the current user.

    Per T-138-19: layout_json is validated for max 64KB at schema layer.
    Upserts: creates a new record if none exists, replaces if one does.
    """
    now = utc_now()
    async with async_session_scope() as session:
        stmt = select(WidgetLayoutRecord).where(WidgetLayoutRecord.user_id == auth.user_id)
        record = (await session.exec(stmt)).first()

        if record is None:
            record = WidgetLayoutRecord(
                user_id=auth.user_id,
                layout_json=body.layout_json,
                updated_at=now,
            )
            session.add(record)
        else:
            record.layout_json = body.layout_json
            record.updated_at = now
            session.add(record)

        await session.commit()
        await session.refresh(record)

    return DataEnvelope(
        data=WidgetLayoutResponse(
            user_id=record.user_id,
            layout_json=record.layout_json,
            updated_at=record.updated_at,
        )
    )
