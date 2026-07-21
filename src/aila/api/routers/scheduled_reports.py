"""Scheduled reports router for AILA REST API.

Provides CRUD for scheduled report configurations with cron expressions.

Per BE-10 / D-33: admin-only.
Per T-138-20: cron_expression validated via croniter before storage.
Per D-27: DataEnvelope response.
Per D-26: offset/limit pagination.
Per D-31: slowapi rate limiting.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import (
    ScheduledReportCreate,
    ScheduledReportResponse,
    ScheduledReportTriggerResponse,
    ScheduledReportUpdate,
)
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import ScheduledReportRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/scheduled-reports", tags=["scheduled-reports"], dependencies=[Depends(require_user_or_api_key)])

_ROLE_LEVELS: dict[str, int] = {"reader": 0, "operator": 1, "admin": 2}


def _require_admin(auth: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    if _ROLE_LEVELS.get(auth.role, -1) < _ROLE_LEVELS[ROLE_ADMIN]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Scheduled reports require '{ROLE_ADMIN}' role; current role: '{auth.role}'",
        )
    return auth


def _assert_team_visible(record: ScheduledReportRecord, auth: AuthContext) -> None:
    """Raise 404 when a team-scoped caller addresses another team's row (#48-6).

    God-tier admins (``team_id`` is None, TEAM-06) skip the check and see
    every row. A team-scoped admin may only reach rows stamped with its own
    team; a mismatch returns 404 (not 403) so the row's existence does not
    leak across the team boundary.
    """
    if auth.team_id is not None and record.team_id != auth.team_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scheduled report not found",
        )


def _validate_cron(expression: str) -> None:
    """Validate cron expression via croniter (T-138-20).

    Never pass cron expressions to shell -- only store after validation.
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


def _record_to_response(r: ScheduledReportRecord) -> ScheduledReportResponse:
    return ScheduledReportResponse(
        id=r.id,
        name=r.name,
        report_type=r.report_type,
        cron_expression=r.cron_expression,
        recipient_emails_json=r.recipient_emails_json,
        config_json=r.config_json,
        is_active=r.is_active,
        last_run_at=r.last_run_at,
        created_by=r.created_by,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


@router.get(
    "",
    response_model=DataEnvelope[list[ScheduledReportResponse]],
    summary="List scheduled reports",
)
@limiter.limit("60/minute")
async def list_scheduled_reports(
    request: Request,
    limit: int = 50,
    offset: int = 0,
    auth: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[ScheduledReportResponse]]:
    """List all scheduled reports. Admin only."""
    async with async_session_scope() as session:
        stmt = select(ScheduledReportRecord).order_by(ScheduledReportRecord.created_at.desc())  # type: ignore[attr-defined]
        # #48-6: team-scoped admins see only their team; god-tier (team_id
        # None) sees all.
        if auth.team_id is not None:
            stmt = stmt.where(ScheduledReportRecord.team_id == auth.team_id)
        all_rows = (await session.exec(stmt)).all()

    total = len(all_rows)
    page_rows = all_rows[offset : offset + limit]
    meta = PaginatedMeta(total=total, offset=offset, limit=limit).model_dump()
    return DataEnvelope(data=[_record_to_response(r) for r in page_rows], meta=meta)


@router.post(
    "",
    response_model=DataEnvelope[ScheduledReportResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create a scheduled report",
)
@limiter.limit("30/minute")
async def create_scheduled_report(
    request: Request,
    body: ScheduledReportCreate,
    auth: AuthContext = Depends(_require_admin),
) -> DataEnvelope[ScheduledReportResponse]:
    """Create a new scheduled report with cron expression. Admin only.

    Validates cron_expression via croniter before storing (T-138-20).
    """
    _validate_cron(body.cron_expression)

    async with async_session_scope() as session:
        record = ScheduledReportRecord(
            name=body.name,
            report_type=body.report_type,
            cron_expression=body.cron_expression,
            recipient_emails_json=body.recipient_emails_json,
            config_json=body.config_json,
            is_active=body.is_active,
            created_by=auth.user_id,
            team_id=auth.team_id,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)

    return DataEnvelope(data=_record_to_response(record))


@router.patch(
    "/{report_id}",
    response_model=DataEnvelope[ScheduledReportResponse],
    summary="Update a scheduled report",
)
@limiter.limit("30/minute")
async def update_scheduled_report(
    request: Request,
    report_id: str,
    body: ScheduledReportUpdate,
    auth: AuthContext = Depends(_require_admin),
) -> DataEnvelope[ScheduledReportResponse]:
    """Update a scheduled report config. Admin only."""
    if body.cron_expression is not None:
        _validate_cron(body.cron_expression)

    async with async_session_scope() as session:
        record = await session.get(ScheduledReportRecord, report_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scheduled report '{report_id}' not found",
            )
        _assert_team_visible(record, auth)

        if body.name is not None:
            record.name = body.name
        if body.cron_expression is not None:
            record.cron_expression = body.cron_expression
        if body.recipient_emails_json is not None:
            record.recipient_emails_json = body.recipient_emails_json
        if body.config_json is not None:
            record.config_json = body.config_json
        if body.is_active is not None:
            record.is_active = body.is_active
        record.updated_at = utc_now()

        session.add(record)
        await session.commit()
        await session.refresh(record)

    return DataEnvelope(data=_record_to_response(record))


@router.delete(
    "/{report_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a scheduled report",
)
@limiter.limit("30/minute")
async def delete_scheduled_report(
    request: Request,
    report_id: str,
    auth: AuthContext = Depends(_require_admin),
) -> None:
    """Delete a scheduled report. Admin only."""
    async with async_session_scope() as session:
        record = await session.get(ScheduledReportRecord, report_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scheduled report '{report_id}' not found",
            )
        _assert_team_visible(record, auth)
        await session.delete(record)
        await session.commit()


@router.post(
    "/{report_id}/trigger",
    response_model=DataEnvelope[ScheduledReportTriggerResponse],
    summary="Manually trigger a scheduled report",
)
@limiter.limit("10/minute")
async def trigger_scheduled_report(
    request: Request,
    report_id: str,
    auth: AuthContext = Depends(_require_admin),
) -> DataEnvelope[ScheduledReportTriggerResponse]:
    """Manually trigger a report run. Admin only.

    Enqueues the report generation via the platform task queue if available.
    Returns the task ID for polling.
    """
    async with async_session_scope() as session:
        record = await session.get(ScheduledReportRecord, report_id)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scheduled report '{report_id}' not found",
            )
        _assert_team_visible(record, auth)
        if not record.is_active:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Scheduled report '{report_id}' is not active",
            )

    # Enqueue generate_scheduled_report_job via arq directly.
    # Uses arq.connections.create_pool() with Redis config from ConfigRegistry.
    # Falls back to task_id="manual" if arq/Redis is not available.
    task_id = "manual"
    try:
        import arq

        from aila.storage.registry import ConfigRegistry

        registry = ConfigRegistry()
        redis_url_raw = await registry.get("platform", "redis_url")
        redis_url = str(redis_url_raw) if redis_url_raw else "redis://localhost:6379"

        # Parse host/port from redis_url for arq RedisSettings
        import urllib.parse as _urlparse
        parsed = _urlparse.urlparse(redis_url)
        redis_host = parsed.hostname or "localhost"
        redis_port = parsed.port or 6379

        redis_settings = arq.connections.RedisSettings(host=redis_host, port=redis_port)
        pool = await arq.create_pool(redis_settings)
        job = await pool.enqueue_job(
            "generate_scheduled_report_job",
            report_id=report_id,
            triggered_by=auth.user_id,
        )
        task_id = job.job_id if job else "manual"
        await pool.aclose()
    except Exception:
        _log.debug("Could not enqueue scheduled report via arq; will run synchronously next worker cycle", exc_info=True)

    return DataEnvelope(
        data=ScheduledReportTriggerResponse(report_id=report_id, task_id=task_id, status="queued"),
        meta={"triggered_by": auth.user_id},
    )
