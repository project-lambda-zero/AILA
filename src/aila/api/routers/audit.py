"""Audit event and seal router for AILA REST API.

Provides GET /audit/events and GET /audit/events/{run_id} for querying
the immutable audit trail. Filtering uses structured params: AND across
fields, OR within a field (repeated params or a comma-joined value), a
target substring via search, and a created_at range via
created_at_since/created_at_until.

Phase 120: GET /audit/seals and GET /audit/seals/export for querying
cryptographic seal records. Both require admin auth (require_role("admin")).
"""
from __future__ import annotations

import json
import math
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlmodel import select

from aila.api.auth import AuthContext, require_role, require_user_or_api_key
from aila.api.schemas.audit import (
    AuditEventResponse,
    AuditListResponse,
    AuditSealListResponse,
    AuditSealResponse,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import AuditEventRecord, AuditSealRecord

__all__ = ["router"]

router = APIRouter(
    prefix="/audit",
    tags=["audit"],
    dependencies=[Depends(require_user_or_api_key)],
)


def _flatten(values: list[str] | None) -> list[str] | None:
    """Collapse repeated and comma-OR query params into one filter list.

    The console filter primitive posts a multi-select as repeated
    ``name=v`` params; a comma-joined ``name=a,b`` value is also accepted.
    Both forms flatten to the same de-duplicated, order-preserving,
    stripped list (AND across fields, OR within a field).
    """
    if not values:
        return None
    out: list[str] = []
    for raw in values:
        for part in raw.split(","):
            token = part.strip()
            if token and token not in out:
                out.append(token)
    return out or None


def _audit_event_to_response(record: AuditEventRecord) -> AuditEventResponse:
    try:
        details = json.loads(record.details_json) if record.details_json else {}
    except (json.JSONDecodeError, TypeError):
        details = {}
    return AuditEventResponse(
        id=record.id,
        run_id=record.run_id,
        stage=record.stage,
        action=record.action,
        status=record.status,
        target=record.target,
        user_id=record.user_id,
        details=details,
        created_at=record.created_at,
    )


@router.get("/events", response_model=AuditListResponse, summary="List audit events")
async def list_audit_events(
    run_id: str | None = Query(default=None, description="Filter to one run"),
    stage: list[str] | None = Query(default=None, description="Stage filter (repeated or comma-OR)"),
    action: list[str] | None = Query(default=None, description="Action filter (repeated or comma-OR)"),
    status: list[str] | None = Query(default=None, description="Status filter (repeated or comma-OR)"),
    user_id: list[str] | None = Query(default=None, description="User ID filter (repeated or comma-OR)"),
    search: str | None = Query(default=None, description="Substring match on target (case-insensitive)"),
    created_at_since: datetime | None = Query(default=None, description="Earliest created_at (ISO 8601)"),
    created_at_until: datetime | None = Query(default=None, description="Latest created_at (ISO 8601)"),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=250, description="Items per page (max 250)"),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> AuditListResponse:
    """Query audit events with structured filtering.

    Supports AND-across-fields, OR-within-a-field filtering (repeated
    params or a comma-joined value), a case-insensitive target substring
    via search, and a created_at range via created_at_since /
    created_at_until (ISO 8601 datetime strings).

    Team-scoped (#36): a team-scoped caller sees only its team's audit
    events; a god-tier admin (team_id=None, TEAM-06) sees all.
    """
    stage_values = _flatten(stage)
    action_values = _flatten(action)
    status_values = _flatten(status)
    user_id_values = _flatten(user_id)
    search_term = search.strip() if search and search.strip() else None

    async def _query() -> list[AuditEventRecord]:
        async with async_session_scope() as session:
            stmt = select(AuditEventRecord)
            if auth.team_id is not None:
                stmt = stmt.where(AuditEventRecord.team_id == auth.team_id)
            if run_id:
                stmt = stmt.where(AuditEventRecord.run_id == run_id)
            if stage_values:
                stmt = stmt.where(AuditEventRecord.stage.in_(stage_values))  # type: ignore[attr-defined]  # SQLModel column expression
            if action_values:
                stmt = stmt.where(AuditEventRecord.action.in_(action_values))  # type: ignore[attr-defined]  # SQLModel column expression
            if status_values:
                stmt = stmt.where(AuditEventRecord.status.in_(status_values))  # type: ignore[attr-defined]  # SQLModel column expression
            if user_id_values:
                stmt = stmt.where(AuditEventRecord.user_id.in_(user_id_values))  # type: ignore[attr-defined]  # SQLModel column expression
            if search_term:
                stmt = stmt.where(AuditEventRecord.target.ilike(f"%{search_term}%"))  # type: ignore[attr-defined]  # SQLModel column expression
            if created_at_since:
                stmt = stmt.where(AuditEventRecord.created_at >= created_at_since)
            if created_at_until:
                stmt = stmt.where(AuditEventRecord.created_at <= created_at_until)
            stmt = stmt.order_by(AuditEventRecord.created_at.desc())  # type: ignore[attr-defined]  # SQLModel column expression
            return list((await session.exec(stmt)).all())

    rows = await _query()
    total = len(rows)
    offset = (page - 1) * page_size
    page_rows = rows[offset : offset + page_size]
    pages = math.ceil(total / page_size) if total > 0 else 0
    return AuditListResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
        items=[_audit_event_to_response(r) for r in page_rows],
    )


@router.get("/events/{run_id}", response_model=AuditListResponse, summary="Get audit trail for one run")
async def get_run_audit_events(
    run_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> AuditListResponse:
    """Return all audit events for a specific workflow run.

    Returns all events without additional pagination -- use GET /audit/events
    with run_id query param for paginated access to large runs.

    Team-scoped (#36): a team-scoped caller reading another team's run_id
    receives an empty trail rather than that team's audit events; a
    god-tier admin (team_id=None) sees all.
    """

    async def _query() -> list[AuditEventRecord]:
        async with async_session_scope() as session:
            stmt = (
                select(AuditEventRecord)
                .where(AuditEventRecord.run_id == run_id)
                .order_by(AuditEventRecord.created_at.asc())  # type: ignore[attr-defined]  # SQLModel column expression
            )
            if auth.team_id is not None:
                stmt = stmt.where(AuditEventRecord.team_id == auth.team_id)
            return list((await session.exec(stmt)).all())

    rows = await _query()
    items = [_audit_event_to_response(r) for r in rows]
    return AuditListResponse(
        total=len(items),
        page=1,
        page_size=max(len(items), 1),
        pages=1 if items else 0,
        items=items,
    )


# ---------------------------------------------------------------------------
# Seal endpoints (Phase 120: Audit Sealing)
# ---------------------------------------------------------------------------


def _seal_record_to_response(
    record: AuditSealRecord,
    include_content: bool = False,
) -> AuditSealResponse:
    """Convert an AuditSealRecord to its API response model.

    Content fields (prompt_content, response_content) are excluded by default
    and only included when the caller explicitly requests them via
    ?include_content=true (D-16).
    """
    return AuditSealResponse(
        id=record.id,
        run_id=record.run_id,
        seal_hash=record.seal_hash,
        input_hash=record.input_hash,
        output_hash=record.output_hash,
        model_id=record.model_id,
        task_type=record.task_type,
        timestamp=record.timestamp,
        classification=record.classification,
        confidence=record.confidence,
        evidence_validation_pass=record.evidence_validation_pass,
        content_stored=record.content_stored,
        prompt_content=record.prompt_content if include_content else None,
        response_content=record.response_content if include_content else None,
        created_at=record.created_at,
    )


@router.get(
    "/seals",
    response_model=AuditSealListResponse,
    summary="List audit seals for a run",
)
async def list_seals(
    run_id: str = Query(..., description="Run ID to filter seals"),
    include_content: bool = Query(default=False, description="Include prompt/response content"),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=250, description="Items per page (max 250)"),
    _admin: Any = Depends(require_role("admin")),
) -> AuditSealListResponse:
    """Return paginated audit seals for a specific run.

    Requires admin role. Content fields are excluded unless
    ?include_content=true is passed (D-16, SEAL-03).
    """

    async def _query() -> list[AuditSealRecord]:
        async with async_session_scope() as session:
            stmt = (
                select(AuditSealRecord)
                .where(AuditSealRecord.run_id == run_id)
                .order_by(AuditSealRecord.timestamp.asc())  # type: ignore[attr-defined]
            )
            return list((await session.exec(stmt)).all())

    rows = await _query()
    total = len(rows)
    offset = (page - 1) * page_size
    page_rows = rows[offset : offset + page_size]
    pages = math.ceil(total / page_size) if total > 0 else 0
    return AuditSealListResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
        items=[_seal_record_to_response(r, include_content) for r in page_rows],
    )


@router.get(
    "/seals/export",
    response_model=AuditSealListResponse,
    summary="Export seals by date range",
)
async def export_seals(
    since: datetime = Query(..., description="Start date (ISO 8601)"),
    until: datetime = Query(..., description="End date (ISO 8601)"),
    include_content: bool = Query(default=False, description="Include prompt/response content"),
    page: int = Query(default=1, ge=1, description="Page number (1-indexed)"),
    page_size: int = Query(default=50, ge=1, le=250, description="Items per page (max 250)"),
    _admin: Any = Depends(require_role("admin")),
) -> AuditSealListResponse:
    """Export paginated audit seals within a date range.

    Uses since/until (not from/to) to avoid Python reserved word collision
    (Pitfall 8). Requires admin role (D-15, D-17, SEAL-07).
    """

    async def _query() -> list[AuditSealRecord]:
        async with async_session_scope() as session:
            stmt = (
                select(AuditSealRecord)
                .where(AuditSealRecord.created_at >= since)
                .where(AuditSealRecord.created_at <= until)
                .order_by(AuditSealRecord.created_at.asc())  # type: ignore[attr-defined]
            )
            return list((await session.exec(stmt)).all())

    rows = await _query()
    total = len(rows)
    offset = (page - 1) * page_size
    page_rows = rows[offset : offset + page_size]
    pages = math.ceil(total / page_size) if total > 0 else 0
    return AuditSealListResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=pages,
        items=[_seal_record_to_response(r, include_content) for r in page_rows],
    )
