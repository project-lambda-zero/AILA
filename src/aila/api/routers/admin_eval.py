"""Admin eval-harness router (RFC-08 step 1).

Operator surface for the eval runner: register a benchmark of pre-scored
cases, run an eval for a candidate prompt version (which resolves the
current production baseline, scores both bundles, and optionally flips
the production alias on a passing verdict), and list prior eval runs.

All endpoints require god-tier admin (team_id=None): prompt evaluation
and promotion is platform-wide, not team-scoped, exactly like the
underlying prompt version store (RFC-09). Every request is
rate-limited to match the admin-prompts pattern.

Endpoints:
    POST /admin/eval/benchmarks   register a benchmark of scored cases
    POST /admin/eval/runs         score a candidate against a benchmark
    GET  /admin/eval/runs?key=    list prior eval runs for a key
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.eval.runner import (
    BenchmarkNotFoundError,
    EmptyCaseBundleError,
    EvalRunner,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)

_RUNNER = EvalRunner()


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Eval promotion flips the production prompt alias platform-wide, so a
    team-scoped admin is refused; only a god-tier admin (team_id=None)
    may register benchmarks or run evals that gate every team's
    investigations."""
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Eval-harness administration is restricted to god-tier administrators.",
        )
    return ctx


router = APIRouter(
    prefix="/admin/eval",
    tags=["admin-eval"],
    dependencies=[Depends(_require_admin)],
)


class BenchmarkCaseSpec(BaseModel):
    """One scored case in a benchmark, optionally attributed to a version."""

    model_config = ConfigDict(extra="forbid")

    outcome_kind: str = Field(min_length=1, max_length=64)
    predicted_verdict: str = Field(min_length=1, max_length=32)
    verified_verdict: str = Field(min_length=1, max_length=32)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    version: str | None = Field(default=None, max_length=32)


class RegisterBenchmarkRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    name: str = Field(min_length=1, max_length=256)
    cases: list[BenchmarkCaseSpec] = Field(min_length=1)


class BenchmarkInfo(BaseModel):
    id: str
    key: str
    name: str
    case_count: int
    created_by: str
    created_at: datetime


class RunEvalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    candidate_version: str = Field(min_length=1, max_length=32)
    benchmark_id: str = Field(min_length=1, max_length=64)
    auto_promote: bool = False


class EvalRunInfo(BaseModel):
    id: str
    key: str
    candidate_version: str
    baseline_version: str | None
    benchmark_id: str
    verdict: str
    actor: str
    created_at: datetime
    report: dict[str, Any]


def _case_specs_to_dicts(cases: list[BenchmarkCaseSpec]) -> list[dict[str, object]]:
    """Convert BenchmarkCaseSpec entries to plain dicts for the runner."""
    out: list[dict[str, object]] = []
    for spec in cases:
        entry: dict[str, object] = {
            "outcome_kind": spec.outcome_kind,
            "predicted_verdict": spec.predicted_verdict,
            "verified_verdict": spec.verified_verdict,
            "confidence": spec.confidence,
        }
        if spec.version is not None:
            entry["version"] = spec.version
        out.append(entry)
    return out


@router.post("/benchmarks", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def register_benchmark(
    request: Request,
    body: RegisterBenchmarkRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[BenchmarkInfo]:
    """Register a benchmark of pre-scored cases under a prompt key."""
    del request
    record = await _RUNNER.register_benchmark(
        key=body.key,
        name=body.name,
        cases=_case_specs_to_dicts(body.cases),
        created_by=ctx.user_id,
    )
    return DataEnvelope(data=BenchmarkInfo(
        id=record.id,
        key=record.key,
        name=record.name,
        case_count=len(body.cases),
        created_by=record.created_by,
        created_at=record.created_at,
    ))


@router.post("/runs", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def run_eval(
    request: Request,
    body: RunEvalRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[EvalRunInfo]:
    """Score a candidate against a benchmark. Optionally flip production."""
    del request
    try:
        run_record = await _RUNNER.run(
            key=body.key,
            candidate_version=body.candidate_version,
            benchmark_id=body.benchmark_id,
            auto_promote=body.auto_promote,
            actor=ctx.user_id,
        )
    except BenchmarkNotFoundError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=str(exc),
        ) from exc
    except EmptyCaseBundleError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc),
        ) from exc
    report_payload = json.loads(run_record.report_json)
    return DataEnvelope(data=EvalRunInfo(
        id=run_record.id,
        key=run_record.key,
        candidate_version=run_record.candidate_version,
        baseline_version=run_record.baseline_version,
        benchmark_id=run_record.benchmark_id,
        verdict=run_record.verdict,
        actor=run_record.actor,
        created_at=run_record.created_at,
        report=report_payload,
    ))


@router.get("/runs")
@limiter.limit("60/minute")
async def list_runs(
    request: Request,
    key: str = Query(min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=500),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[EvalRunInfo]]:
    """List eval runs for a key, newest first."""
    del request, ctx
    rows = await _RUNNER.list_runs(key, limit=limit)
    return DataEnvelope(data=[
        EvalRunInfo(
            id=r.id,
            key=r.key,
            candidate_version=r.candidate_version,
            baseline_version=r.baseline_version,
            benchmark_id=r.benchmark_id,
            verdict=r.verdict,
            actor=r.actor,
            created_at=r.created_at,
            report=json.loads(r.report_json),
        )
        for r in rows
    ])
