"""Admin retrieval-eval read router (RFC #140).

Thin admin surface over the ``retrieval_eval_benchmarks`` and
``retrieval_eval_runs`` tables (migrated at 099) so an operator can see
what benchmarks are registered and inspect the sweep-recorded runs
without dropping to SQL.

Endpoints:
    GET  /platform/retrieval-eval/benchmarks     list registered benchmarks
    GET  /platform/retrieval-eval/runs           list scored runs (paged)

The retrieval-eval subsystem has no ``team_id`` on either table (the
knowledge store is a platform-wide singleton), so this router mirrors
:mod:`aila.api.routers.knowledge` -- god-tier admin only, ``team_id``
MUST be ``None``. Read-only by design; benchmark registration and run
scoring remain owned by the CLI + the scheduled
``platform.retrieval_eval_sweep`` action (RFC #140 report-mode).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.eval.retrieval_models import (
    RetrievalBenchmarkRecord,
    RetrievalRunRecord,
)
from aila.storage.database import async_session_scope

__all__ = ["router"]

_log = logging.getLogger(__name__)


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """God-tier admin gate.

    The retrieval-eval tables carry no ``team_id`` column: benchmarks
    and their scored runs are platform-wide, exactly like the
    KnowledgeService they replay against. A team-scoped admin therefore
    has no business browsing them -- ``team_id`` MUST be ``None``
    (same rule as :mod:`aila.api.routers.knowledge` and
    :mod:`aila.api.routers.admin_eval`).
    """
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'"
            ),
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Retrieval-eval administration is restricted to god-tier "
                "administrators."
            ),
        )
    return ctx


router = APIRouter(
    prefix="/platform/retrieval-eval",
    tags=["admin-retrieval-eval"],
    dependencies=[Depends(_require_admin)],
)


class RetrievalBenchmarkInfo(BaseModel):
    """Read-only view of a :class:`RetrievalBenchmarkRecord` row.

    ``case_count`` is derived from ``cases_json`` (parsed at read time)
    so the payload stays a stable operator summary without exposing
    the potentially-large raw JSON blob. A malformed ``cases_json``
    reports ``case_count=0`` rather than 500ing the whole list.
    """

    id: str
    key: str
    name: str
    k: int
    case_count: int
    created_by: str
    created_at: datetime


class RetrievalRunInfo(BaseModel):
    """Read-only view of a :class:`RetrievalRunRecord` row.

    ``report`` is the parsed ``report_json`` payload (candidate report +
    optional baseline report + regression tolerance). A malformed
    ``report_json`` collapses to ``{}`` so a bad row never poisons the
    list; the ``id`` is still returned so an operator can drill in.
    """

    id: str
    key: str
    benchmark_id: str
    candidate_label: str
    baseline_label: str | None
    verdict: str
    actor: str
    created_at: datetime
    report: dict[str, Any] = Field(default_factory=dict)


def _case_count(cases_json: str) -> int:
    """Return the recorded case count, tolerating malformed JSON."""
    try:
        parsed = json.loads(cases_json)
    except (TypeError, ValueError):
        _log.debug("retrieval-eval: malformed cases_json; reporting case count 0")
        return 0
    if isinstance(parsed, list):
        return len(parsed)
    return 0


def _parse_report(report_json: str) -> dict[str, Any]:
    """Return the parsed report payload, tolerating malformed JSON."""
    try:
        parsed = json.loads(report_json)
    except (TypeError, ValueError):
        _log.debug("retrieval-eval: malformed report_json; reporting empty report")
        return {}
    if isinstance(parsed, dict):
        return parsed
    return {}


def _benchmark_info(row: RetrievalBenchmarkRecord) -> RetrievalBenchmarkInfo:
    return RetrievalBenchmarkInfo(
        id=row.id,
        key=row.key,
        name=row.name,
        k=row.k,
        case_count=_case_count(row.cases_json),
        created_by=row.created_by,
        created_at=row.created_at,
    )


def _run_info(row: RetrievalRunRecord) -> RetrievalRunInfo:
    return RetrievalRunInfo(
        id=row.id,
        key=row.key,
        benchmark_id=row.benchmark_id,
        candidate_label=row.candidate_label,
        baseline_label=row.baseline_label,
        verdict=row.verdict,
        actor=row.actor,
        created_at=row.created_at,
        report=_parse_report(row.report_json),
    )


@router.get("/benchmarks")
@limiter.limit("60/minute")
async def list_benchmarks(
    request: Request,
    key: str | None = Query(
        default=None,
        max_length=256,
        description=(
            "Optional exact-match filter on the benchmark ``key`` column."
        ),
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[RetrievalBenchmarkInfo]]:
    """List registered retrieval benchmarks, newest first."""
    del ctx, request
    async with async_session_scope() as session:
        base = select(RetrievalBenchmarkRecord)
        if key is not None:
            base = base.where(RetrievalBenchmarkRecord.key == key)
        stmt = (
            base
            .order_by(RetrievalBenchmarkRecord.created_at.desc())
            .offset(int(offset))
            .limit(int(limit))
        )
        rows = list((await session.exec(stmt)).all())

        # Total count for the paginated meta -- separate SELECT COUNT so
        # a large corpus doesn't force the client to page every row to
        # know the total.
        count_stmt = select(func.count()).select_from(RetrievalBenchmarkRecord)
        if key is not None:
            count_stmt = count_stmt.where(
                RetrievalBenchmarkRecord.key == key,
            )
        total = int((await session.exec(count_stmt)).one())

    return DataEnvelope(
        data=[_benchmark_info(row) for row in rows],
        meta=PaginatedMeta(total=total, offset=offset, limit=limit).model_dump(),
    )


@router.get("/runs")
@limiter.limit("60/minute")
async def list_runs(
    request: Request,
    key: str | None = Query(
        default=None,
        max_length=256,
        description=(
            "Optional exact-match filter on the run ``key`` column."
        ),
    ),
    benchmark_id: str | None = Query(
        default=None,
        max_length=64,
        description=(
            "Optional exact-match filter on the run ``benchmark_id`` column."
        ),
    ),
    verdict: str | None = Query(
        default=None,
        max_length=16,
        description=(
            "Optional filter on run verdict "
            "(``pass`` | ``fail`` | ``baseline_only``)."
        ),
    ),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[RetrievalRunInfo]]:
    """List scored retrieval runs, newest first."""
    del ctx, request
    async with async_session_scope() as session:
        base = select(RetrievalRunRecord)
        if key is not None:
            base = base.where(RetrievalRunRecord.key == key)
        if benchmark_id is not None:
            base = base.where(
                RetrievalRunRecord.benchmark_id == benchmark_id,
            )
        if verdict is not None:
            base = base.where(RetrievalRunRecord.verdict == verdict)
        stmt = (
            base
            .order_by(RetrievalRunRecord.created_at.desc())
            .offset(int(offset))
            .limit(int(limit))
        )
        rows = list((await session.exec(stmt)).all())

        count_stmt = select(func.count()).select_from(RetrievalRunRecord)
        if key is not None:
            count_stmt = count_stmt.where(RetrievalRunRecord.key == key)
        if benchmark_id is not None:
            count_stmt = count_stmt.where(
                RetrievalRunRecord.benchmark_id == benchmark_id,
            )
        if verdict is not None:
            count_stmt = count_stmt.where(
                RetrievalRunRecord.verdict == verdict,
            )
        total = int((await session.exec(count_stmt)).one())

    return DataEnvelope(
        data=[_run_info(row) for row in rows],
        meta=PaginatedMeta(total=total, offset=offset, limit=limit).model_dump(),
    )
