"""Admin LLM interaction log router (Plan 176e).

Exposes a single endpoint, GET /admin/llm-log, that lists LLMCostRecord
rows with filter + pagination + cost aggregate for the admin UI. The
endpoint is admin-only and joins through WorkflowRunRecord so the UI can
surface the originating run's action context.

Design notes:

* Explicit team_id filter for non-admin callers to match the defense-in-depth
  pattern used by the cost router (T-175-08 / T-175-09).
* `total_cost_usd` is summed across all matching rows, not just the page,
  so the UI can show a real total without paging through the result set.
* Prompt/response preview columns are returned verbatim -- they are already
  truncated at write time (see aila.platform.llm.cost._make_preview).
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlmodel import select

from aila.api.auth import AuthContext, require_role
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.llm_log import LLMLogEntry, LLMLogResponse
from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin",
    tags=["admin", "llm-log"],
    dependencies=[Depends(require_role("admin"))],
)


def _split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return parts or None


@router.get(
    "/llm-log",
    response_model=DataEnvelope[LLMLogResponse],
    summary="Admin LLM interaction log with filters + cost total",
)
@limiter.limit("60/minute")
async def list_llm_log(
    request: Request,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    model: str | None = Query(default=None, description="Comma-OR model filter"),
    task_type: str | None = Query(default=None, description="Comma-OR task_type filter"),
    user: str | None = Query(default=None, description="User id (exact match)"),
    team_id: str | None = Query(default=None, description="Team id (admin-only cross-tenant)"),
    from_date: datetime | None = Query(default=None, alias="from_date"),
    to_date: datetime | None = Query(default=None, alias="to_date"),
    status: str | None = Query(default=None, description="Comma-OR status filter"),
    min_cost: float | None = Query(default=None, ge=0.0),
    max_cost: float | None = Query(default=None, ge=0.0),
    search: str | None = Query(default=None, description="Substring match on prompt_preview"),
    auth: AuthContext = Depends(require_role("admin")),
) -> DataEnvelope[LLMLogResponse]:
    """Return paginated LLM interaction log entries with cost aggregation.

    Filtering is AND-across-fields; model/task_type/status accept comma-OR.
    Non-admin tokens are rejected at the dependency layer; admin tokens can
    cross-tenant via the optional team_id query param. When team_id is
    omitted, admin tokens default to the caller's team (if scoped) or to
    all teams (for __admin__ tokens).
    """
    model_values = _split_csv(model)
    task_type_values = _split_csv(task_type)
    status_values = _split_csv(status)

    # Build the base LLMCostRecord query. We filter on the cost record table
    # directly and then look up run task_type via a second query so the main
    # query stays a straightforward index scan.
    async with async_session_scope() as session:
        stmt = select(LLMCostRecord)

        # Team scoping. Admin tokens may pass team_id explicitly to cross tenants;
        # otherwise we honor the caller's own team_id.
        if team_id is not None:
            stmt = stmt.where(LLMCostRecord.team_id == team_id)
        elif auth.team_id is not None:
            stmt = stmt.where(LLMCostRecord.team_id == auth.team_id)

        if model_values:
            stmt = stmt.where(LLMCostRecord.model_id.in_(model_values))  # type: ignore[attr-defined]
        if task_type_values:
            stmt = stmt.where(LLMCostRecord.task_type.in_(task_type_values))  # type: ignore[attr-defined]
        if status_values:
            stmt = stmt.where(LLMCostRecord.status.in_(status_values))  # type: ignore[attr-defined]
        if from_date is not None:
            stmt = stmt.where(LLMCostRecord.created_at >= from_date)
        if to_date is not None:
            stmt = stmt.where(LLMCostRecord.created_at <= to_date)
        if min_cost is not None:
            stmt = stmt.where(LLMCostRecord.cost_usd >= min_cost)
        if max_cost is not None:
            stmt = stmt.where(LLMCostRecord.cost_usd <= max_cost)
        if search:
            # ILIKE for case-insensitive substring match on prompt_preview.
            # A NULL preview won't match ILIKE, which is the desired behaviour
            # (rows without captured text shouldn't satisfy a text search).
            pattern = f"%{search}%"
            stmt = stmt.where(LLMCostRecord.prompt_preview.ilike(pattern))  # type: ignore[attr-defined]

        # Pull all matching rows so we can compute total + total_cost without
        # a separate COUNT/SUM round-trip. LLMCostRecord is small (one row per
        # LLM call) and filtered; paging over >1M records isn't a concern yet.
        all_rows = list((await session.exec(stmt)).all())

        # Optional user_id filter runs via WorkflowRun join. We defer it here
        # so we can reuse a single run-id resolution pass and avoid N+1s.
        run_ids = {r.run_id for r in all_rows if r.run_id and r.run_id != "_no_run"}
        run_map: dict[str, WorkflowRunRecord] = {}
        if run_ids:
            run_stmt = select(WorkflowRunRecord).where(
                WorkflowRunRecord.id.in_(list(run_ids))  # type: ignore[attr-defined]
            )
            for run in (await session.exec(run_stmt)).all():
                run_map[run.id] = run

    # Apply user filter (WorkflowRunRecord has no user_id today -- the
    # closest honest signal is the run's team_id, so we match on that when
    # `user` is passed).  If the user filter cannot be resolved honestly we
    # produce zero rows rather than silently ignore the filter.
    if user:
        filtered: list[LLMCostRecord] = []
        for rec in all_rows:
            run = run_map.get(rec.run_id)
            # Match if the explicit user string equals the run's team_id --
            # the only user-linked identifier presently stored on WorkflowRun.
            if run is not None and run.team_id == user:
                filtered.append(rec)
        all_rows = filtered

    # Sort newest-first for the log view.
    all_rows.sort(
        key=lambda r: r.created_at if r.created_at is not None else datetime.min,
        reverse=True,
    )

    total = len(all_rows)
    total_cost = round(sum(r.cost_usd for r in all_rows), 6)
    page_rows = all_rows[offset : offset + limit]

    items: list[LLMLogEntry] = []
    for rec in page_rows:
        run = run_map.get(rec.run_id)
        items.append(
            LLMLogEntry(
                id=rec.id,
                timestamp=rec.created_at,
                model=rec.model_id,
                task_type=rec.task_type or (run.action_id if run else ""),
                input_tokens=rec.prompt_tokens,
                output_tokens=rec.completion_tokens,
                cost_usd=round(rec.cost_usd, 6),
                duration_ms=rec.duration_ms,
                status=rec.status,
                run_id=rec.run_id,
                user_id=None,
                team_id=rec.team_id,
                prompt_preview=rec.prompt_preview,
                response_preview=rec.response_preview,
            )
        )

    meta: dict[str, Any] = {"total": total, "offset": offset, "limit": limit}
    return DataEnvelope(
        data=LLMLogResponse(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            total_cost_usd=total_cost,
        ),
        meta=meta,
    )
