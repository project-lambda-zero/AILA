"""Admin HTTP surface for the VR benchmark-measurement harness.

God-tier admin only (a measurement run is a release-gate activity, not a
team-scoped one). Endpoints: start a run, list runs, inspect one run with
its per-task results, trigger scoring, and read the leaderboard.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlmodel import select

from aila.api.deps import get_task_queue
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.contracts.auth import AuthContext, require_auth
from aila.platform.uow import UnitOfWork

from ..db_models.eval_suite import VREvalSuiteRunRecord
from .contracts import SUPPORTED_SUITES, LeaderboardRow, SuiteRunSummary
from .suite_runner import leaderboard, run_summary

__all__ = ["create_vr_eval_router"]


class SuiteRunRequest(BaseModel):
    """Start-a-run payload."""

    model_config = ConfigDict(extra="forbid")

    suite: str


class SuiteRunAccepted(BaseModel):
    """Response for an enqueued run or collect."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    suite: str | None = None
    run_id: str | None = None


def _require_admin(auth: AuthContext) -> None:
    if auth.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Benchmark measurement is restricted to platform admins.",
        )


def create_vr_eval_router() -> APIRouter:
    """Construct the benchmark-measurement admin router."""
    router = APIRouter(tags=["vr-eval"])

    @router.post(
        "/eval-suites/runs",
        response_model=DataEnvelope[SuiteRunAccepted],
        status_code=status.HTTP_202_ACCEPTED,
        summary="Start a benchmark measurement run over a suite.",
    )
    @limiter.limit("10/minute")
    async def start_run(
        request: Request,
        body: SuiteRunRequest,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[SuiteRunAccepted]:
        _require_admin(auth)
        if body.suite not in SUPPORTED_SUITES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"unknown suite '{body.suite}'; supported: {sorted(SUPPORTED_SUITES)}",
            )
        from ..workflow.task import run_vr_eval_suite  # noqa: PLC0415

        handle = await get_task_queue("vr", request).submit(
            track="vr",
            fn=run_vr_eval_suite,
            kwargs={
                "suite": body.suite,
                "requested_by": auth.user_id,
                "team_id": auth.team_id,
            },
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return DataEnvelope(data=SuiteRunAccepted(task_id=handle.task_id, suite=body.suite))

    @router.get(
        "/eval-suites/runs",
        response_model=DataEnvelope[list[SuiteRunSummary]],
        summary="List benchmark measurement runs.",
    )
    @limiter.limit("60/minute")
    async def list_runs(
        request: Request,
        auth: AuthContext = Depends(require_auth),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=200),
    ) -> DataEnvelope[list[SuiteRunSummary]]:
        del request
        _require_admin(auth)
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                select(VREvalSuiteRunRecord)
                .order_by(VREvalSuiteRunRecord.created_at.desc())
                .offset(offset).limit(limit),
            )).all()
            items = [
                SuiteRunSummary(
                    id=r.id,
                    suite=r.suite,
                    status=r.status,
                    solved_count=r.solved_count,
                    total_count=r.total_count,
                    total_cost_usd=r.total_cost_usd,
                    created_at=r.created_at.isoformat() if r.created_at else None,
                    finished_at=r.finished_at.isoformat() if r.finished_at else None,
                )
                for r in rows
            ]
        return DataEnvelope(data=items)

    @router.get(
        "/eval-suites/runs/{run_id}",
        response_model=DataEnvelope[SuiteRunSummary],
        summary="Inspect one measurement run with its per-task results.",
    )
    @limiter.limit("60/minute")
    async def get_run(
        request: Request,
        run_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[SuiteRunSummary]:
        del request
        _require_admin(auth)
        async with UnitOfWork() as uow:
            summary = await run_summary(uow, run_id)
        if summary is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"measurement run {run_id} not found",
            )
        return DataEnvelope(data=summary)

    @router.post(
        "/eval-suites/runs/{run_id}/collect",
        response_model=DataEnvelope[SuiteRunAccepted],
        status_code=status.HTTP_202_ACCEPTED,
        summary="Score a measurement run from its terminal investigations.",
    )
    @limiter.limit("20/minute")
    async def collect_run(
        request: Request,
        run_id: str,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[SuiteRunAccepted]:
        _require_admin(auth)
        from ..workflow.task import run_vr_eval_collect  # noqa: PLC0415

        handle = await get_task_queue("vr", request).submit(
            track="vr",
            fn=run_vr_eval_collect,
            kwargs={"run_id": run_id},
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return DataEnvelope(data=SuiteRunAccepted(task_id=handle.task_id, run_id=run_id))

    @router.get(
        "/eval-suites/leaderboard",
        response_model=DataEnvelope[list[LeaderboardRow]],
        summary="Per-suite leaderboard across the most recent runs.",
    )
    @limiter.limit("60/minute")
    async def get_leaderboard(
        request: Request,
        auth: AuthContext = Depends(require_auth),
    ) -> DataEnvelope[list[LeaderboardRow]]:
        del request
        _require_admin(auth)
        async with UnitOfWork() as uow:
            rows = await leaderboard(uow)
        return DataEnvelope(data=rows)

    return router
