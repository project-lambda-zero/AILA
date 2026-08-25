"""Admin LLM interaction log router (Plan 176e).

Endpoints:

* ``GET /admin/llm-log`` -- paginated list of LLMCostRecord rows with
  filter + cost aggregate for the admin UI. Joins through
  WorkflowRunRecord so the UI can surface the originating run's action
  context.
* ``GET /admin/llm-log/{id}/content`` -- returns the full prompt/response
  bodies for one row. Resolves from the paired AuditSealRecord when the
  seal captured both bodies; otherwise returns the truncated preview from
  the cost row and names the ConfigRegistry toggle that would enable
  full retention.

Design notes:

* Explicit team_id filter for non-admin callers to match the defense-in-depth
  pattern used by the cost router (T-175-08 / T-175-09).
* ``total_cost_usd`` is summed across all matching rows, not just the page,
  so the UI can show a real total without paging through the result set.
* ``model``/``task_type``/``status`` accept the console filter primitive's
  wire encoding: repeated params (``?model=a&model=b``) OR a comma-joined
  value (``?model=a,b``). Both forms flatten identically (AND across
  fields, repeated-or-comma-OR within a field).
* The content endpoint never decrypts the ``prompt_content_encrypted`` /
  ``response_content_encrypted`` columns. In the paranoid posture only
  encrypted copies exist and the endpoint resolves to ``preview`` or
  ``missing``.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func
from sqlmodel import select

from aila.api.auth import AuthContext, require_role
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.llm_log import LLMLogContent, LLMLogEntry, LLMLogResponse
from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope
from aila.storage.db_models import AuditSealRecord, WorkflowRunRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/admin",
    tags=["admin", "llm-log"],
    dependencies=[Depends(require_role("admin"))],
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
    model: list[str] | None = Query(default=None, description="Model filter (repeated or comma-OR)"),
    task_type: list[str] | None = Query(default=None, description="Task-type filter (repeated or comma-OR)"),
    user_id: str | None = Query(default=None, description="User id (exact match)"),
    team_id: str | None = Query(default=None, description="Team id (admin-only cross-tenant)"),
    timestamp_since: datetime | None = Query(default=None, description="Earliest created_at (ISO 8601)"),
    timestamp_until: datetime | None = Query(default=None, description="Latest created_at (ISO 8601)"),
    status: list[str] | None = Query(default=None, description="Status filter (repeated or comma-OR)"),
    cost_usd_min: float | None = Query(default=None, ge=0.0),
    cost_usd_max: float | None = Query(default=None, ge=0.0),
    search: str | None = Query(default=None, description="Substring match on prompt_preview"),
    auth: AuthContext = Depends(require_role("admin")),
) -> DataEnvelope[LLMLogResponse]:
    """Return paginated LLM interaction log entries with cost aggregation.

    Filtering is AND-across-fields; ``model``/``task_type``/``status``
    accept the repeated-or-comma-OR wire encoding. Non-admin tokens are
    rejected at the dependency layer; admin tokens can cross-tenant via
    the optional ``team_id`` query param. When ``team_id`` is omitted,
    admin tokens default to the caller's team (if scoped) or to all
    teams (for god-tier tokens).
    """
    model_values = _flatten(model)
    task_type_values = _flatten(task_type)
    status_values = _flatten(status)

    # #204: aggregate + page in SQL. Previously loaded every matching row into
    # Python to compute ``total`` + ``total_cost`` and then sliced
    # ``[offset:offset+limit]``. LLMCostRecord grows one row per LLM call and
    # the admin filter widgets can be permissive, so a wide filter set could
    # materialize >1M rows into worker memory per request.
    filters: list[Any] = []

    # Team scoping. Admin tokens may pass team_id explicitly to cross tenants;
    # otherwise we honor the caller's own team_id.
    if team_id is not None:
        filters.append(LLMCostRecord.team_id == team_id)
    elif auth.team_id is not None:
        filters.append(LLMCostRecord.team_id == auth.team_id)

    if model_values:
        filters.append(LLMCostRecord.model_id.in_(model_values))  # type: ignore[attr-defined]
    if task_type_values:
        filters.append(LLMCostRecord.task_type.in_(task_type_values))  # type: ignore[attr-defined]
    if status_values:
        filters.append(LLMCostRecord.status.in_(status_values))  # type: ignore[attr-defined]
    if timestamp_since is not None:
        filters.append(LLMCostRecord.created_at >= timestamp_since)
    if timestamp_until is not None:
        filters.append(LLMCostRecord.created_at <= timestamp_until)
    if cost_usd_min is not None:
        filters.append(LLMCostRecord.cost_usd >= cost_usd_min)
    if cost_usd_max is not None:
        filters.append(LLMCostRecord.cost_usd <= cost_usd_max)
    if search:
        # ILIKE for case-insensitive substring match on prompt_preview.
        # A NULL preview won't match ILIKE, which is the desired behaviour
        # (rows without captured text shouldn't satisfy a text search).
        pattern = f"%{search}%"
        filters.append(LLMCostRecord.prompt_preview.ilike(pattern))  # type: ignore[attr-defined]

    # #124 user filter: LLMCostRecord.user_id is populated at write time
    # from ``current_user_id()`` (the ContextVar bound by the auth
    # dependency). Filter is now a direct index scan on the correct column.
    # Worker-triggered rows (agent turns, background scans) have NULL
    # user_id and never match, which is honest -- they have no live user.
    if user_id:
        filters.append(LLMCostRecord.user_id == user_id)

    async with async_session_scope() as session:
        aggregate_stmt = select(
            func.count(LLMCostRecord.id).label("total"),
            func.coalesce(func.sum(LLMCostRecord.cost_usd), 0.0).label("total_cost"),
        ).where(*filters)
        aggregate = (await session.exec(aggregate_stmt)).one()
        total = int(aggregate.total or 0)
        total_cost = round(float(aggregate.total_cost or 0.0), 6)

        page_stmt = (
            select(LLMCostRecord)
            .where(*filters)
            .order_by(LLMCostRecord.created_at.desc())  # type: ignore[attr-defined]
            .offset(offset)
            .limit(limit)
        )
        page_rows = list((await session.exec(page_stmt)).all())

        # Resolve run task_type context for the page only (was previously
        # keyed off the fully materialized result set).
        run_ids = {r.run_id for r in page_rows if r.run_id and r.run_id != "_no_run"}
        run_map: dict[str, WorkflowRunRecord] = {}
        if run_ids:
            run_stmt = select(WorkflowRunRecord).where(
                WorkflowRunRecord.id.in_(list(run_ids))  # type: ignore[attr-defined]
            )
            for run in (await session.exec(run_stmt)).all():
                run_map[run.id] = run

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
                user_id=rec.user_id,
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


@router.get(
    "/llm-log/{id}/content",
    response_model=DataEnvelope[LLMLogContent],
    summary="Full prompt/response body for one LLM interaction log row",
)
@limiter.limit("60/minute")
async def get_llm_log_content(
    request: Request,
    id: str,
    auth: AuthContext = Depends(require_role("admin")),
) -> DataEnvelope[LLMLogContent]:
    """Resolve the full prompt/response body for one cost row.

    Resolution order:

    1. If a paired ``AuditSealRecord`` exists (matched by ``run_id`` and
       ``model_id``, picked by closest ``created_at``) and stores BOTH
       ``prompt_content`` and ``response_content``, return those with
       ``source="audit_seal"``.
    2. Else if either preview column on the cost row is non-null, return
       the previews with ``source="preview"``.
    3. Else return null bodies with ``source="missing"``.

    In cases 2 and 3 ``config_flag`` names the
    ``llm_seal_store_content_<task_type>`` toggle so the operator knows
    which ConfigRegistry setting would enable full retention.

    Team scoping: a team-scoped admin sees only its team's rows; a
    god-tier admin (auth.team_id is None) sees any row. Unknown or
    cross-team ids return 404.
    """
    async with async_session_scope() as session:
        rec = (
            await session.exec(select(LLMCostRecord).where(LLMCostRecord.id == id))
        ).one_or_none()
        if rec is None:
            raise HTTPException(status_code=404, detail="llm log row not found")
        if auth.team_id is not None and rec.team_id != auth.team_id:
            raise HTTPException(status_code=404, detail="llm log row not found")

        seal: AuditSealRecord | None = None
        if rec.run_id and rec.run_id != "_no_run":
            candidates = list(
                (
                    await session.exec(
                        select(AuditSealRecord).where(
                            AuditSealRecord.run_id == rec.run_id,
                            AuditSealRecord.model_id == rec.model_id,
                        )
                    )
                ).all()
            )
            if candidates:
                seal = min(
                    candidates,
                    key=lambda s: abs((s.created_at - rec.created_at).total_seconds()),
                )

    task_type = rec.task_type or ""
    if (
        seal is not None
        and seal.prompt_content is not None
        and seal.response_content is not None
    ):
        content = LLMLogContent(
            prompt_content=seal.prompt_content,
            response_content=seal.response_content,
            source="audit_seal",
            task_type=task_type,
            config_flag=None,
        )
    elif rec.prompt_preview is not None or rec.response_preview is not None:
        content = LLMLogContent(
            prompt_content=rec.prompt_preview,
            response_content=rec.response_preview,
            source="preview",
            task_type=task_type,
            config_flag=f"llm_seal_store_content_{task_type}",
        )
    else:
        content = LLMLogContent(
            prompt_content=None,
            response_content=None,
            source="missing",
            task_type=task_type,
            config_flag=f"llm_seal_store_content_{task_type}",
        )

    return DataEnvelope(data=content)
