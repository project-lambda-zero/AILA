"""Admin workflow inspection router (Phase 181).

Read-only surface for inspecting durable state-machine runs and their
transition audit logs. Mirrors the admin_dead_letter.py pattern: all
endpoints require admin role, all are rate-limited.

Endpoints:
    GET /admin/workflows/runs
        List recent workflow runs (WorkflowStateCursor rows), newest
        first. Supports ``definition_id`` and ``current_state`` query
        filters. Capped at 200 rows per call.

    GET /admin/workflows/runs/{run_id}/transitions
        List all transition audit rows for a run, oldest first (seq ASC).
        Returns empty list if the run has no transitions.

    GET /admin/workflows/runs/{run_id}/transitions/{seq}
        Return a single transition by (run_id, seq). 404 if not found.
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.transitions import TransitionView
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateCursor, WorkflowStateTransition

__all__ = ["router"]

_log = logging.getLogger(__name__)


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    return ctx


router = APIRouter(
    prefix="/admin/workflows",
    tags=["admin-workflows"],
    dependencies=[Depends(_require_admin)],
)

_MAX_RUNS = 200          # safety cap per call
_MAX_TRANSITIONS = 500  # safety cap -- prevents unbounded reads on high-retry runs


class WorkflowRunView(BaseModel):
    """Read-only view of one WorkflowStateCursor row."""

    run_id: str
    current_state: str
    definition_id: str
    retries_in_state: int
    version: int
    updated_at: datetime


@router.get(
    "/runs",
    response_model=DataEnvelope[list[WorkflowRunView]],
    summary="List recent workflow runs",
)
@limiter.limit("30/minute")
async def list_workflow_runs(
    request: Request,
    definition_id: str | None = Query(default=None, max_length=128),
    current_state: str | None = Query(default=None, max_length=128),
) -> DataEnvelope[list[WorkflowRunView]]:
    """Return up to 200 workflow cursor rows, newest first.

    Optionally filter by ``definition_id`` or ``current_state``. Admin only.
    """
    del request
    async with async_session_scope() as session:
        stmt = select(WorkflowStateCursor).order_by(
            WorkflowStateCursor.updated_at.desc()  # type: ignore[attr-defined]
        )
        if definition_id is not None:
            stmt = stmt.where(WorkflowStateCursor.definition_id == definition_id)  # type: ignore[arg-type]
        if current_state is not None:
            stmt = stmt.where(WorkflowStateCursor.current_state == current_state)  # type: ignore[arg-type]
        stmt = stmt.limit(_MAX_RUNS)
        rows = (await session.exec(stmt)).all()

    return DataEnvelope(
        data=[
            WorkflowRunView(
                run_id=r.run_id,
                current_state=r.current_state,
                definition_id=r.definition_id,
                retries_in_state=r.retries_in_state,
                version=r.version,
                updated_at=r.updated_at,
            )
            for r in rows
        ]
    )


@router.get(
    "/runs/{run_id}/transitions",
    response_model=DataEnvelope[list[TransitionView]],
    summary="List all transitions for a workflow run",
)
@limiter.limit("60/minute")
async def list_run_transitions(
    request: Request,
    run_id: str,
) -> DataEnvelope[list[TransitionView]]:
    """Return all transition audit rows for a run, oldest first. Admin only."""
    del request
    async with async_session_scope() as session:
        rows = (
            await session.exec(
                select(WorkflowStateTransition)
                .where(WorkflowStateTransition.run_id == run_id)
                .order_by(WorkflowStateTransition.seq)
                .limit(_MAX_TRANSITIONS)
            )
        ).all()
    _log.info("admin transitions.read run_id=%s rows=%d", run_id, len(rows))
    return DataEnvelope(data=[TransitionView.from_model(r) for r in rows])


@router.get(
    "/runs/{run_id}/transitions/{seq}",
    response_model=DataEnvelope[TransitionView],
    summary="Get a single transition by run_id and seq",
)
@limiter.limit("60/minute")
async def get_run_transition(
    request: Request,
    run_id: str,
    seq: int,
) -> DataEnvelope[TransitionView]:
    """Return a single transition row by (run_id, seq). Admin only.

    Raises 404 if the (run_id, seq) pair does not exist.
    """
    del request
    async with async_session_scope() as session:
        row = await session.get(WorkflowStateTransition, (run_id, seq))
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transition (run_id={run_id!r}, seq={seq}) not found",
        )
    return DataEnvelope(data=TransitionView.from_model(row))
