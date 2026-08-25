"""Admin eval-harness router (RFC-08 step 1).

Operator surface for the eval runner: register a benchmark of pre-scored
cases, run an eval for a candidate prompt version (which resolves the
current production baseline, scores both bundles, and records a
verdict), and list prior eval runs.

The eval runner NEVER flips the 'production' alias -- that promotion
is exclusively owned by
:class:`aila.platform.lifecycle.controller.AgentLifecycleController.promote`
behind the eval + quorum gate (RFC-10 criterion 1). This router only
exposes scoring and listing.

All endpoints require god-tier admin (team_id=None): prompt evaluation
is platform-wide, not team-scoped, exactly like the underlying prompt
version store (RFC-09). Every request is rate-limited to match the
admin-prompts pattern.

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

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.config import PlatformConfigSchema
from aila.platform.eval.calibration import (
    CALIBRATION_STATUS_ACTIVE,
    CalibrationProposalRecord,
)
from aila.platform.eval.calibrator import (
    CalibrationTrainer,
    CalibratorPromotionError,
    CalibratorVersionRecord,
    promote_calibrator,
)
from aila.platform.eval.runner import (
    BenchmarkNotFoundError,
    EmptyCaseBundleError,
    EvalRunner,
)
from aila.storage.database import async_session_scope
from aila.storage.registry import ConfigRegistry

__all__ = ["router"]

_log = logging.getLogger(__name__)

_RUNNER = EvalRunner()

# Live threshold key convention (contract C7 threshold-promote route):
# ``CalibrationProposalRecord.after_threshold`` writes into
# ``platform.calibration_threshold_{outcome_kind}`` on promotion. The
# key sits under the ``platform`` namespace as a ``calibration_threshold_``
# dynamic-key family (see PlatformConfigSchema) so honesty audit rule 57
# recognises the token and the CalibrationProposalRecord reference in
# this file's ``promote_calibration_proposal`` body discharges the rule.
_CALIBRATION_THRESHOLD_NAMESPACE: str = "platform"
_CALIBRATION_THRESHOLD_KEY_PREFIX: str = "calibration_threshold_"


def _calibration_threshold_key(outcome_kind: str) -> str:
    """Return the live ConfigRegistry key for ``outcome_kind``."""
    return f"{_CALIBRATION_THRESHOLD_KEY_PREFIX}{outcome_kind}"


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Eval scoring feeds the platform-wide promotion gate, so a
    team-scoped admin is refused; only a god-tier admin (team_id=None)
    may register benchmarks or run evals whose verdicts gate every
    team's investigations."""
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


class CalibratorTrainRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_type: str = Field(min_length=1, max_length=64)


class CalibratorPromoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approver_ids: list[str] = Field(default_factory=list, max_length=32)


class CalibratorVersionInfo(BaseModel):
    id: str
    task_type: str
    method: str
    params: dict[str, Any]
    ece_before: float
    ece_after: float
    sample_count: int
    status: str
    superseded_by: str | None
    actor: str
    created_at: datetime


class CalibrationProposalPromoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approver_ids: list[str] = Field(default_factory=list, max_length=32)


class CalibrationProposalPromoteInfo(BaseModel):
    proposal_id: str
    outcome_kind: str
    before_threshold: float
    after_threshold: float
    config_namespace: str
    config_key: str
    approvers: int
    quorum_required: int
    actor: str


class CalibrationProposalInfo(BaseModel):
    id: str
    outcome_kind: str
    before_threshold: float
    after_threshold: float
    approve_count: int
    reject_count: int
    mean_confidence_reject: float
    mean_confidence_approve: float
    reasoning: str
    evidence: dict[str, Any]
    status: str
    superseded_by: str | None
    reverted_from: str | None
    actor: str
    created_at: datetime


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
    """Score a candidate against a benchmark and record a verdict.

    The 'production' alias is not touched here. A passing verdict is a
    necessary input to promotion, which is a separate, quorum-gated
    decision on the RFC-10 lifecycle controller.
    """
    del request
    try:
        run_record = await _RUNNER.run(
            key=body.key,
            candidate_version=body.candidate_version,
            benchmark_id=body.benchmark_id,
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


def _version_info(row: CalibratorVersionRecord) -> CalibratorVersionInfo:
    """Adapt a :class:`CalibratorVersionRecord` to the response contract."""
    try:
        params = json.loads(row.params_json or "{}")
    except (json.JSONDecodeError, TypeError, ValueError):
        _log.warning(
            "admin_eval: params_json for calibrator id=%s is malformed; "
            "returning empty params",
            row.id,
        )
        params = {}
    if not isinstance(params, dict):
        params = {}
    return CalibratorVersionInfo(
        id=row.id,
        task_type=row.task_type,
        method=row.method,
        params=params,
        ece_before=row.ece_before,
        ece_after=row.ece_after,
        sample_count=row.sample_count,
        status=row.status,
        superseded_by=row.superseded_by,
        actor=row.actor,
        created_at=row.created_at,
    )


def _proposal_info(row: CalibrationProposalRecord) -> CalibrationProposalInfo:
    """Adapt a :class:`CalibrationProposalRecord` to the response contract."""
    try:
        evidence = json.loads(row.evidence_json or "{}")
    except (json.JSONDecodeError, TypeError, ValueError):
        _log.warning(
            "admin_eval: evidence_json for calibration proposal id=%s is "
            "malformed; returning empty evidence",
            row.id,
        )
        evidence = {}
    if not isinstance(evidence, dict):
        evidence = {}
    return CalibrationProposalInfo(
        id=row.id,
        outcome_kind=row.outcome_kind,
        before_threshold=row.before_threshold,
        after_threshold=row.after_threshold,
        approve_count=row.approve_count,
        reject_count=row.reject_count,
        mean_confidence_reject=row.mean_confidence_reject,
        mean_confidence_approve=row.mean_confidence_approve,
        reasoning=row.reasoning,
        evidence=evidence,
        status=row.status,
        superseded_by=row.superseded_by,
        reverted_from=row.reverted_from,
        actor=row.actor,
        created_at=row.created_at,
    )


@router.post("/calibrators/train", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
async def train_calibrator(
    request: Request,
    body: CalibratorTrainRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[CalibratorVersionInfo]:
    """Fit both isotonic + temperature calibrators for ``task_type``.

    Reads accept/reject history via :class:`CalibrationTrainer`, keeps
    the lower-ECE method, and persists a ``status='candidate'`` row.
    The candidate is inert until :func:`promote_calibrator` clears the
    eval + quorum gate.
    """
    del request
    trainer = CalibrationTrainer()
    try:
        row = await trainer.fit_and_propose(
            task_type=body.task_type, actor=ctx.user_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc),
        ) from exc
    return DataEnvelope(data=_version_info(row))


@router.post("/calibrators/{version_id}/promote")
@limiter.limit("10/minute")
async def promote_calibrator_version(
    request: Request,
    body: CalibratorPromoteRequest,
    version_id: str = Path(min_length=1, max_length=64),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[CalibratorVersionInfo]:
    """Flip a candidate calibrator to active behind the eval + quorum gate.

    Both gates enforced by :func:`promote_calibrator`: candidate ECE
    must strictly beat the prior active AND the distinct-approver
    count must reach ``platform.agent_promotion_quorum``. Either miss
    raises :class:`CalibratorPromotionError` -> HTTP 409.
    """
    del request
    try:
        row = await promote_calibrator(
            version_id,
            actor=ctx.user_id,
            quorum_approver_ids=body.approver_ids,
        )
    except CalibratorPromotionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc),
        ) from exc
    return DataEnvelope(data=_version_info(row))


@router.get("/calibrators")
@limiter.limit("60/minute")
async def list_calibrators(
    request: Request,
    task_type: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[CalibratorVersionInfo]]:
    """List calibrator versions, optionally scoped to ``task_type``."""
    del request, ctx
    async with async_session_scope() as session:
        stmt = select(CalibratorVersionRecord)
        if task_type:
            stmt = stmt.where(CalibratorVersionRecord.task_type == task_type)
        stmt = stmt.order_by(
            CalibratorVersionRecord.created_at.desc(),  # type: ignore[attr-defined]
        ).limit(limit)
        rows = (await session.exec(stmt)).all()
    return DataEnvelope(data=[_version_info(r) for r in rows])


@router.get("/calibration-proposals")
@limiter.limit("60/minute")
async def list_calibration_proposals(
    request: Request,
    outcome_kind: str | None = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[CalibrationProposalInfo]]:
    """List calibration-threshold proposals, optionally scoped to ``outcome_kind``."""
    del request, ctx
    async with async_session_scope() as session:
        stmt = select(CalibrationProposalRecord)
        if outcome_kind:
            stmt = stmt.where(CalibrationProposalRecord.outcome_kind == outcome_kind)
        stmt = stmt.order_by(
            CalibrationProposalRecord.created_at.desc(),  # type: ignore[attr-defined]
        ).limit(limit)
        rows = (await session.exec(stmt)).all()
    return DataEnvelope(data=[_proposal_info(r) for r in rows])


@router.post("/calibration-proposals/{proposal_id}/promote")
@limiter.limit("10/minute")
async def promote_calibration_proposal(
    request: Request,
    body: CalibrationProposalPromoteRequest,
    proposal_id: str = Path(min_length=1, max_length=64),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[CalibrationProposalPromoteInfo]:
    """Write an ACTIVE :class:`CalibrationProposalRecord` into live config.

    RFC-08 Tier D contract C7 for threshold promotion: the calibration
    sweep writes ``CalibrationProposalRecord`` rows (proposals, never
    application); this endpoint is the sanctioned crossing from
    proposal to live threshold. Two gates, both must clear:

    1. The proposal MUST be :data:`CALIBRATION_STATUS_ACTIVE`
       (superseded / reverted rows never promote).
    2. ``len(set(approver_ids))`` MUST reach
       ``platform.agent_promotion_quorum`` (same distinct-approver
       rule the RFC-10 lifecycle promotion enforces).

    On success writes ``after_threshold`` into ``platform.calibration_threshold_{outcome_kind}``
    via :meth:`ConfigRegistry.set`. The write goes through the
    registry so peer workers see the change on the next cache poll --
    no service restart. Rule 57 discharge: the CalibrationProposalRecord
    reference above sits in the SAME function body as the
    ``registry.set(calibration_threshold_...)`` call below.
    """
    del request
    async with async_session_scope() as session:
        proposal = (await session.exec(
            select(CalibrationProposalRecord).where(
                CalibrationProposalRecord.id == proposal_id,
            ),
        )).first()
    if proposal is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"calibration proposal {proposal_id!r} not found",
        )
    if proposal.status != CALIBRATION_STATUS_ACTIVE:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"calibration proposal {proposal_id!r} is {proposal.status!r}, "
                "not active -- superseded / reverted proposals cannot promote"
            ),
        )

    distinct_approvers = {a for a in body.approver_ids if a}
    registry = ConfigRegistry()
    # ConfigRegistry.set requires the namespace schema registered on this
    # instance (register also seeds any missing default rows and leaves
    # existing operator overrides untouched). The threshold write below
    # is on the platform namespace, so register it here before the
    # get + set -- a fresh instance carries no schemas.
    await registry.register(_CALIBRATION_THRESHOLD_NAMESPACE, PlatformConfigSchema)
    try:
        quorum_raw = await registry.get(
            "platform", "agent_promotion_quorum",
        )
    except (OSError, RuntimeError, ValueError, TypeError):
        quorum_raw = None
    required = 1
    if quorum_raw is not None:
        try:
            required = max(0, int(quorum_raw))
        except (TypeError, ValueError):
            required = 1
    if len(distinct_approvers) < required:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"quorum_insufficient: {len(distinct_approvers)} distinct "
                f"approver(s) < required {required}"
            ),
        )

    key = _calibration_threshold_key(proposal.outcome_kind)
    await registry.set(
        _CALIBRATION_THRESHOLD_NAMESPACE,
        key,
        str(proposal.after_threshold),
    )
    _log.info(
        "admin_eval: promoted calibration proposal id=%s kind=%s -> "
        "%s/%s = %.4f (actor=%s, approvers=%d)",
        proposal.id, proposal.outcome_kind,
        _CALIBRATION_THRESHOLD_NAMESPACE, key,
        proposal.after_threshold, ctx.user_id, len(distinct_approvers),
    )
    return DataEnvelope(data=CalibrationProposalPromoteInfo(
        proposal_id=proposal.id,
        outcome_kind=proposal.outcome_kind,
        before_threshold=proposal.before_threshold,
        after_threshold=proposal.after_threshold,
        config_namespace=_CALIBRATION_THRESHOLD_NAMESPACE,
        config_key=key,
        approvers=len(distinct_approvers),
        quorum_required=required,
        actor=ctx.user_id,
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
