"""Cost intelligence router for AILA REST API (Phase 175).

Provides 5 endpoints under /cost:
  GET  /cost/runs/{run_id}     -- per-model cost breakdown for a run
  GET  /cost/history           -- historical cost data grouped by month/model
  POST /cost/estimate          -- pre-scan cost estimation from team history
  POST /cost/estimate-human    -- trigger human-equivalent cost estimation
  GET  /cost/roi               -- LLM cost vs human-equivalent ROI side-by-side

Security (T-175-08, T-175-09):
  - All endpoints require authentication via require_user_or_api_key.
  - TeamScopedMixin on LLMCostRecord auto-filters all queries by team_id.
  - /cost/estimate uses auth.team_id for history queries (never from request body).
  - ROI and history queries exclude task_type='cost_estimation' (T-175-10).
  - Fallback values come from ConfigRegistry, not hardcoded constants.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.deps import get_config_registry
from aila.api.limiter import limiter
from aila.api.schemas.cost import (
    CostBreakdownResponse,
    CostEstimateRequest,
    CostEstimateResponse,
    CostHistoryResponse,
    HumanEstimateRequest,
    HumanEstimateResponse,
    ModelCostEntry,
    MonthlyCostEntry,
    ROIResponse,
    TaskTypeEstimate,
)
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope

if TYPE_CHECKING:
    from aila.storage.registry import ConfigRegistry

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/cost",
    tags=["cost"],
    dependencies=[Depends(require_user_or_api_key)],
)

# Task type excluded from LLM cost totals in ROI and history (T-175-10)
_COST_ESTIMATION_TASK_TYPE = "cost_estimation"


# ---------------------------------------------------------------------------
# GET /cost/runs/{run_id}
# ---------------------------------------------------------------------------


@router.get(
    "/runs/{run_id}",
    response_model=DataEnvelope[CostBreakdownResponse],
    summary="Per-model cost breakdown for a run",
)
@limiter.limit("120/minute")
async def get_run_cost_breakdown(
    request: Request,
    run_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[CostBreakdownResponse]:
    """Return per-model cost breakdown for a single run (LLM-COST-01).

    TeamScopedMixin auto-filters to the authenticated team's records.
    Returns empty models list when run not found (no 404 -- run may have no LLM calls).
    """
    async with async_session_scope() as session:
        stmt = select(LLMCostRecord).where(LLMCostRecord.run_id == run_id)
        if auth.team_id is not None:
            stmt = stmt.where(LLMCostRecord.team_id == auth.team_id)
        records = (await session.exec(stmt)).all()

    # Aggregate by model_id
    model_map: dict[str, dict[str, Any]] = {}
    for rec in records:
        entry = model_map.setdefault(
            rec.model_id,
            {
                "model_id": rec.model_id,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cost_usd": 0.0,
                "call_count": 0,
            },
        )
        entry["prompt_tokens"] += rec.prompt_tokens
        entry["completion_tokens"] += rec.completion_tokens
        entry["cost_usd"] += rec.cost_usd
        entry["call_count"] += 1

    models = [
        ModelCostEntry(
            model_id=e["model_id"],
            prompt_tokens=e["prompt_tokens"],
            completion_tokens=e["completion_tokens"],
            total_tokens=e["prompt_tokens"] + e["completion_tokens"],
            cost_usd=round(e["cost_usd"], 6),
            call_count=e["call_count"],
        )
        for e in model_map.values()
    ]

    total_cost = round(sum(m.cost_usd for m in models), 6)
    total_tokens = sum(m.total_tokens for m in models)

    # #155: attach the process-local cache-hit-rate gauge when the
    # request lands in a process that owns the run's RunMemory (an
    # in-worker admin surface, an SSE consumer bound to the worker).
    # An API-only process returns 0.0 -- the operator reads the
    # process-agnostic mirror from Prometheus
    # (``aila_llm_cache_hit_ratio{model=...}``).
    cache_read_tokens = 0
    cache_write_tokens = 0
    cache_hit_rate = 0.0
    try:
        from aila.platform.llm.prompt_layout import get_cache_metrics
        from aila.platform.llm.run_memory import RunMemory
        _run_memory_singleton = RunMemory()
        gauge = get_cache_metrics(_run_memory_singleton, run_id)
        cache_read_tokens = int(gauge.get("cache_read_tokens", 0))
        cache_write_tokens = int(gauge.get("cache_write_tokens", 0))
        cache_hit_rate = float(gauge.get("cache_hit_rate", 0.0))
    except (ImportError, RuntimeError, ValueError, TypeError, AttributeError) as exc:
        _log.debug("cost.runs cache metrics read failed run_id=%s err=%s", run_id, exc)

    return DataEnvelope(
        data=CostBreakdownResponse(
            run_id=run_id,
            total_cost_usd=total_cost,
            total_tokens=total_tokens,
            models=models,
            cache_hit_rate=cache_hit_rate,
            cache_read_tokens=cache_read_tokens,
            cache_write_tokens=cache_write_tokens,
        )
    )


# ---------------------------------------------------------------------------
# GET /cost/history
# ---------------------------------------------------------------------------


@router.get(
    "/history",
    response_model=DataEnvelope[CostHistoryResponse],
    summary="Historical cost data grouped by month and model",
)
@limiter.limit("120/minute")
async def get_cost_history(
    request: Request,
    months: int = Query(default=6, ge=1, le=24),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[CostHistoryResponse]:
    """Return monthly aggregated cost data with per-model breakdown (LLM-COST-04).

    Excludes task_type='cost_estimation' from totals (T-175-10).
    Explicit team_id filter enforces tenant isolation at the application layer.
    """
    since = datetime.now(UTC) - timedelta(days=months * 30)

    # #204: aggregate in SQL. Previously loaded every matching row into Python
    # (months of history per request) and did the sum/group there.
    month_expr = func.to_char(
        func.date_trunc("month", LLMCostRecord.created_at),
        "YYYY-MM",
    )
    async with async_session_scope() as session:
        stmt = (
            select(
                month_expr.label("year_month"),
                LLMCostRecord.model_id.label("model_id"),  # type: ignore[attr-defined]
                func.coalesce(func.sum(LLMCostRecord.prompt_tokens), 0).label("prompt_tokens"),
                func.coalesce(func.sum(LLMCostRecord.completion_tokens), 0).label("completion_tokens"),
                func.coalesce(func.sum(LLMCostRecord.cost_usd), 0.0).label("cost_usd"),
                func.count().label("call_count"),
            )
            .where(LLMCostRecord.created_at >= since)
            .where(LLMCostRecord.task_type != _COST_ESTIMATION_TASK_TYPE)
            .group_by("year_month", LLMCostRecord.model_id)
            .order_by("year_month", LLMCostRecord.model_id)
        )
        if auth.team_id is not None:
            stmt = stmt.where(LLMCostRecord.team_id == auth.team_id)
        rows = (await session.exec(stmt)).all()

    # Bucket the flat (year_month, model_id) rows into MonthlyCostEntry ->
    # [ModelCostEntry]. The DB has already ordered by year_month; a single
    # linear pass preserves month + model ordering.
    month_map: dict[str, list[ModelCostEntry]] = {}
    for row in rows:
        ym = row.year_month if row.year_month is not None else "unknown"
        prompt_tokens = int(row.prompt_tokens or 0)
        completion_tokens = int(row.completion_tokens or 0)
        month_map.setdefault(ym, []).append(
            ModelCostEntry(
                model_id=row.model_id,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                total_tokens=prompt_tokens + completion_tokens,
                cost_usd=round(float(row.cost_usd or 0.0), 6),
                call_count=int(row.call_count or 0),
            )
        )

    month_entries: list[MonthlyCostEntry] = []
    for ym in sorted(month_map.keys()):
        models = month_map[ym]
        month_entries.append(
            MonthlyCostEntry(
                year_month=ym,
                total_cost_usd=round(sum(m.cost_usd for m in models), 6),
                total_tokens=sum(m.total_tokens for m in models),
                models=models,
            )
        )

    grand_total = round(sum(e.total_cost_usd for e in month_entries), 6)

    return DataEnvelope(
        data=CostHistoryResponse(
            months=month_entries,
            grand_total_usd=grand_total,
        )
    )


# ---------------------------------------------------------------------------
# POST /cost/estimate
# ---------------------------------------------------------------------------


@router.post(
    "/estimate",
    response_model=DataEnvelope[CostEstimateResponse],
    summary="Pre-scan cost estimation from team history",
)
@limiter.limit("120/minute")
async def estimate_scan_cost(
    request: Request,
    body: CostEstimateRequest,
    auth: AuthContext = Depends(require_user_or_api_key),
    registry: ConfigRegistry = Depends(get_config_registry),
) -> DataEnvelope[CostEstimateResponse]:
    """Estimate pre-scan cost from team-scoped historical averages (LLM-COST-03).

    For task_types with history: estimated = target_count * avg_cost_per_call.
    For task_types without history: worst_case = target_count * fallback_max_tokens
      * (fallback_price_per_1k / 1000). Fallback values come from ConfigRegistry
      (never hardcoded) per T-175-13.

    Team scoping: history query explicitly uses auth.team_id (T-175-09).
    """
    task_types = body.task_types or []
    target_count = body.target_count

    # Build per-task-type averages from team's history
    # Explicitly scope to auth.team_id to prevent cross-tenant leakage (T-175-09)
    task_type_stats: dict[str, dict[str, Any]] = {}

    if task_types and auth.team_id is not None:
        # #204: aggregate in SQL instead of streaming every historical row
        # for the team into Python.
        async with async_session_scope() as session:
            stmt = (
                select(
                    LLMCostRecord.task_type.label("task_type"),  # type: ignore[attr-defined]
                    func.coalesce(func.sum(LLMCostRecord.cost_usd), 0.0).label("total_cost"),
                    func.count().label("count"),
                )
                .where(LLMCostRecord.team_id == auth.team_id)
                .where(LLMCostRecord.task_type.in_(task_types))  # type: ignore[union-attr]
                .where(LLMCostRecord.task_type != _COST_ESTIMATION_TASK_TYPE)
                .group_by(LLMCostRecord.task_type)
            )
            rows = (await session.exec(stmt)).all()

        for row in rows:
            task_type_stats[row.task_type] = {
                "total_cost": float(row.total_cost or 0.0),
                "count": int(row.count or 0),
            }
    elif task_types and auth.team_id is None:
        # No team context -- refuse cross-tenant estimation queries. There is
        # deliberately no fallback query here: a team-less principal cannot run
        # an unscoped cross-tenant cost aggregation.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Team context required for cost estimation",
        )

    # Fetch fallback config values from ConfigRegistry (not hardcoded -- T-175-13)
    fallback_max_tokens_raw = await registry.get(
        "platform", "llm_cost_estimate_fallback_max_tokens"
    )
    fallback_price_per_1k_raw = await registry.get(
        "platform", "llm_cost_estimate_fallback_price_per_1k"
    )
    fallback_max_tokens: int = int(fallback_max_tokens_raw) if fallback_max_tokens_raw is not None else 4096
    fallback_price_per_1k: float = float(fallback_price_per_1k_raw) if fallback_price_per_1k_raw is not None else 0.03

    # Build breakdown per task_type
    breakdown: list[TaskTypeEstimate] = []
    total_estimated = 0.0
    has_worst_case = False

    for tt in task_types:
        stats = task_type_stats.get(tt)
        if stats and stats["count"] > 0:
            avg = stats["total_cost"] / stats["count"]
            estimated = target_count * avg
            breakdown.append(
                TaskTypeEstimate(
                    task_type=tt,
                    avg_cost_usd=round(avg, 6),
                    sample_count=stats["count"],
                )
            )
        else:
            # No history: use worst-case multiplier from ConfigRegistry
            worst_case_per_call = fallback_max_tokens * (fallback_price_per_1k / 1000.0)
            estimated = target_count * worst_case_per_call
            has_worst_case = True
            breakdown.append(
                TaskTypeEstimate(
                    task_type=tt,
                    avg_cost_usd=round(worst_case_per_call, 6),
                    sample_count=0,
                )
            )
        total_estimated += estimated

    confidence = "worst_case" if has_worst_case else "historical"

    return DataEnvelope(
        data=CostEstimateResponse(
            estimated_cost_usd=round(total_estimated, 6),
            confidence=confidence,
            breakdown=breakdown,
        )
    )


# ---------------------------------------------------------------------------
# POST /cost/estimate-human
# ---------------------------------------------------------------------------


@router.post(
    "/estimate-human",
    response_model=DataEnvelope[HumanEstimateResponse],
    summary="Trigger human-equivalent cost estimation for a completed scan",
)
@limiter.limit("120/minute")
async def estimate_human_cost_endpoint(
    request: Request,
    body: HumanEstimateRequest,
    auth: AuthContext = Depends(require_user_or_api_key),
    registry: ConfigRegistry = Depends(get_config_registry),
) -> DataEnvelope[HumanEstimateResponse]:
    """Trigger human-equivalent cost estimation for a completed scan (LLM-COST-05).

    Calls estimate_human_cost() from platform/llm/human_cost.py.
    The estimation LLM call uses task_type='cost_estimation' and run_id=None
    so its cost is tracked separately and excluded from ROI queries (D-06b).

    Human cost is stored by UPDATING the original run's LLMCostRecords
    (not sentinel records) -- keeps ROI queries simple.
    """
    from aila.platform.llm.human_cost import estimate_human_cost

    # Obtain the LLM client from the platform (if available)
    platform = request.app.state.platform
    if platform is None or not hasattr(platform, "runtime") or platform.runtime is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- LLM client unavailable for human cost estimation",
        )

    llm_client = getattr(platform.runtime, "llm_client", None)
    if llm_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM client not available on platform runtime for human cost estimation",
        )

    result = await estimate_human_cost(
        llm_client=llm_client,
        registry=registry,
        team_id=auth.team_id,
        run_id=body.run_id,
        target_count=body.target_count,
        finding_count=body.finding_count,
        task_types_performed=body.task_types_performed,
        scan_duration_minutes=body.scan_duration_minutes,
    )

    if result is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Human cost estimation failed or no LLM cost records found for this run",
        )

    # Compute USD using the same rate the module used
    rate_raw = await registry.get("platform", "llm_human_consultant_hourly_rate")
    hourly_rate = float(rate_raw) if rate_raw is not None else 150.0
    human_cost_usd = result.estimated_hours * hourly_rate

    return DataEnvelope(
        data=HumanEstimateResponse(
            estimated_hours=result.estimated_hours,
            human_cost_usd=round(human_cost_usd, 2),
            confidence=result.confidence,
            reasoning=result.reasoning,
        )
    )


# ---------------------------------------------------------------------------
# GET /cost/roi
# ---------------------------------------------------------------------------


@router.get(
    "/roi",
    response_model=DataEnvelope[ROIResponse],
    summary="LLM cost vs human-equivalent cost ROI",
)
@limiter.limit("120/minute")
async def get_roi(
    request: Request,
    months: int = Query(default=3, ge=1, le=24),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[ROIResponse]:
    """Return ROI: LLM cost vs human-equivalent cost side-by-side (LLM-COST-05).

    LLM cost: SUM(cost_usd) WHERE task_type != 'cost_estimation' (T-175-10).
    Human cost: SUM(human_cost_usd) WHERE human_cost_usd IS NOT NULL AND task_type != 'cost_estimation'.
    Human hours: SUM(human_cost_hours) WHERE human_cost_hours IS NOT NULL AND task_type != 'cost_estimation'.

    Human cost is read directly from LLMCostRecord.human_cost_usd/human_cost_hours
    -- stored there by estimate_human_cost() on a SINGLE per-run row so the SUM
    equals the estimated aggregate even when late-arriving records for the run
    stay NULL (issue #38 -- previously an even split across records existing at
    estimation time silently dropped human cost for any row that landed after).

    ROI = ((human_cost - llm_cost) / human_cost) * 100 if human_cost > 0 else 0.
    Explicit team_id filter enforces tenant isolation at the application layer.
    """
    now = datetime.now(UTC)
    since = now - timedelta(days=months * 30)
    period_start = since.date().isoformat()
    period_end = now.date().isoformat()

    # #204: aggregate in SQL. Previously loaded every matching row into Python
    # to compute the same SUMs and DISTINCT run_ids -- a full worker
    # materialization of months of LLM-call history per request.
    async with async_session_scope() as session:
        stmt = (
            select(
                func.coalesce(func.sum(LLMCostRecord.cost_usd), 0.0).label("llm_cost"),
                func.coalesce(func.sum(LLMCostRecord.human_cost_usd), 0.0).label("human_cost"),
                func.coalesce(func.sum(LLMCostRecord.human_cost_hours), 0.0).label("human_hours"),
                func.count(func.distinct(LLMCostRecord.run_id)).label("run_count"),
            )
            .where(LLMCostRecord.created_at >= since)
            .where(LLMCostRecord.task_type != _COST_ESTIMATION_TASK_TYPE)
        )
        if auth.team_id is not None:
            stmt = stmt.where(LLMCostRecord.team_id == auth.team_id)
        row = (await session.exec(stmt)).one()

    llm_cost = float(row.llm_cost or 0.0)
    human_cost = float(row.human_cost or 0.0)
    human_hours = float(row.human_hours or 0.0)
    run_count = int(row.run_count or 0)

    roi_percentage = 0.0
    if human_cost > 0:
        roi_percentage = ((human_cost - llm_cost) / human_cost) * 100.0

    return DataEnvelope(
        data=ROIResponse(
            period_start=period_start,
            period_end=period_end,
            llm_cost_usd=round(llm_cost, 6),
            human_equivalent_cost_usd=round(human_cost, 6),
            human_equivalent_hours=round(human_hours, 2),
            roi_percentage=round(roi_percentage, 2),
            run_count=run_count,
        )
    )
