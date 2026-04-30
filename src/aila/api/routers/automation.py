"""Automation schedules router for AILA REST API.

Provides CRUD for automation schedules (team-scoped) and lists registered
automation actions from the platform AutomationRegistry.

Per AUTO-04: CRUD endpoints for schedule management.
Per AUTO-05: System ownership validation on schedule creation.
Per D-27: DataEnvelope response wrapper.
Per D-26: offset/limit pagination on list endpoint.
Per D-31: slowapi rate limiting on all endpoints.
"""
from __future__ import annotations

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.limiter import limiter
from aila.api.schemas.automation import (
    AutomationActionResponse,
    AutomationScheduleCreate,
    AutomationScheduleResponse,
    AutomationScheduleUpdate,
)
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.automation.models import AutomationScheduleRecord
from aila.platform.automation.registry import AutomationRegistry
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/automation",
    tags=["automation"],
    dependencies=[Depends(require_user_or_api_key)],
)


def _get_registry(request: Request) -> AutomationRegistry:
    """Retrieve AutomationRegistry from app.state.

    Returns an empty registry if not yet initialized (graceful degradation
    when Plan 02 runner has not wired it yet).
    """
    registry = getattr(request.app.state, "automation_registry", None)
    if registry is None:
        _log.warning("automation_registry not found on app.state; returning empty registry")
        return AutomationRegistry()
    return registry


def _validate_cron(expression: str) -> None:
    """Validate cron expression via croniter.

    Follows the same pattern as scheduled_reports.py (T-138-20).
    Never passes cron expressions to shell -- only stores after validation.
    """
    try:
        from croniter import croniter

        if not croniter.is_valid(expression):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid cron expression: '{expression}'. Example: '0 9 * * MON'",
            )
    except ImportError:
        _log.warning("croniter not installed; skipping cron validation")


def _record_to_response(record: AutomationScheduleRecord) -> AutomationScheduleResponse:
    """Convert DB record to API response model."""
    action_kwargs = json.loads(record.action_kwargs_json) if record.action_kwargs_json else {}
    return AutomationScheduleResponse(
        id=record.id,
        action_id=record.action_id,
        target_name=record.target_name,
        cron_expression=record.cron_expression,
        action_kwargs=action_kwargs,
        enabled=record.enabled,
        team_id=getattr(record, "team_id", None),
        created_by=record.created_by,
        created_at=record.created_at.isoformat() if record.created_at else "",
        updated_at=record.updated_at.isoformat() if record.updated_at else "",
        last_run_at=record.last_run_at.isoformat() if record.last_run_at else None,
        last_run_result=record.last_run_result,
    )


@router.get(
    "/schedules",
    response_model=DataEnvelope[list[AutomationScheduleResponse]],
    summary="List automation schedules for current team",
)
@limiter.limit("60/minute")
async def list_schedules(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[AutomationScheduleResponse]]:
    """List automation schedules scoped to the authenticated user's team.

    Admin (team_id=None) sees all schedules.
    """
    async with async_session_scope() as session:
        stmt = select(AutomationScheduleRecord).order_by(
            AutomationScheduleRecord.created_at.desc()  # type: ignore[attr-defined]
        )
        if auth.team_id is not None:
            stmt = stmt.where(AutomationScheduleRecord.team_id == auth.team_id)
        all_rows = (await session.exec(stmt)).all()

    total = len(all_rows)
    page_rows = all_rows[offset : offset + limit]
    meta = PaginatedMeta(total=total, offset=offset, limit=limit).model_dump()
    return DataEnvelope(data=[_record_to_response(r) for r in page_rows], meta=meta)


@router.post(
    "/schedules",
    response_model=DataEnvelope[AutomationScheduleResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create an automation schedule",
)
@limiter.limit("30/minute")
async def create_schedule(
    request: Request,
    body: AutomationScheduleCreate,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[AutomationScheduleResponse]:
    """Create a new automation schedule.

    Validates:
    1. action_id exists in the AutomationRegistry
    2. cron_expression is valid via croniter
    3. target_name system is owned by the caller's team (AUTO-05)
    """
    # 1. Validate action_id exists in registry
    registry = _get_registry(request)
    action = registry.get_action(body.action_id)
    if action is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown automation action: {body.action_id!r}. "
            "Use GET /automation/actions to list available actions.",
        )

    # 2. Validate cron expression
    _validate_cron(body.cron_expression)

    # 3. Validate target system ownership (AUTO-05 / T-07)
    from aila.storage.db_models import ManagedSystemRecord

    async with async_session_scope() as session:
        system_stmt = select(ManagedSystemRecord).where(
            ManagedSystemRecord.name == body.target_name
        )
        if auth.team_id is not None:
            system_stmt = system_stmt.where(
                ManagedSystemRecord.team_id == auth.team_id
            )
        system = (await session.exec(system_stmt)).first()
        if system is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"System {body.target_name!r} not found or not owned by your team",
            )

    # 4. Create record
    action_kwargs_json = json.dumps(body.action_kwargs) if body.action_kwargs else "{}"

    async with async_session_scope() as session:
        record = AutomationScheduleRecord(
            action_id=body.action_id,
            target_name=body.target_name,
            cron_expression=body.cron_expression,
            action_kwargs_json=action_kwargs_json,
            enabled=body.enabled,
            created_by=auth.user_id,
        )
        # Set team_id from auth context
        record.team_id = auth.team_id  # type: ignore[attr-defined]
        session.add(record)
        await session.commit()
        await session.refresh(record)

    return DataEnvelope(data=_record_to_response(record))


@router.patch(
    "/schedules/{schedule_id}",
    response_model=DataEnvelope[AutomationScheduleResponse],
    summary="Update an automation schedule",
)
@limiter.limit("30/minute")
async def update_schedule(
    request: Request,
    schedule_id: str,
    body: AutomationScheduleUpdate,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[AutomationScheduleResponse]:
    """Update an existing automation schedule.

    Only updates provided (non-None) fields. Validates cron if changed.
    Verifies team ownership before allowing the update.
    """
    if body.cron_expression is not None:
        _validate_cron(body.cron_expression)

    async with async_session_scope() as session:
        record = await session.get(AutomationScheduleRecord, schedule_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schedule '{schedule_id}' not found",
            )

        # Team ownership check
        record_team_id = getattr(record, "team_id", None)
        if auth.team_id is not None and record_team_id != auth.team_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Schedule '{schedule_id}' is not owned by your team",
            )

        if body.cron_expression is not None:
            record.cron_expression = body.cron_expression
        if body.action_kwargs is not None:
            record.action_kwargs_json = json.dumps(body.action_kwargs)
        if body.enabled is not None:
            record.enabled = body.enabled
        record.updated_at = utc_now()

        session.add(record)
        await session.commit()
        await session.refresh(record)

    return DataEnvelope(data=_record_to_response(record))


@router.delete(
    "/schedules/{schedule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete an automation schedule",
)
@limiter.limit("30/minute")
async def delete_schedule(
    request: Request,
    schedule_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> None:
    """Delete an automation schedule. Verifies team ownership."""
    async with async_session_scope() as session:
        record = await session.get(AutomationScheduleRecord, schedule_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Schedule '{schedule_id}' not found",
            )

        # Team ownership check
        record_team_id = getattr(record, "team_id", None)
        if auth.team_id is not None and record_team_id != auth.team_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Schedule '{schedule_id}' is not owned by your team",
            )

        await session.delete(record)
        await session.commit()


@router.get(
    "/actions",
    response_model=DataEnvelope[list[AutomationActionResponse]],
    summary="List registered automation actions",
)
@limiter.limit("60/minute")
async def list_actions(
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[AutomationActionResponse]]:
    """List all automation actions registered in the platform.

    Actions are registered by modules at startup and describe what
    automatable operations are available for scheduling.
    """
    registry = _get_registry(request)
    actions = registry.list_actions()
    return DataEnvelope(
        data=[
            AutomationActionResponse(
                action_id=a.action_id,
                description=a.description,
                module_id=a.module_id,
            )
            for a in actions
        ],
    )
