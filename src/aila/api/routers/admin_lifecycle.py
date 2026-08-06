"""Admin agent-lifecycle router (RFC-10 step 4).

Operator surface for the ``AgentLifecycleController``: evaluate a
candidate prompt version against a benchmark, promote a version that
has cleared its evaluation gate, rollback the production alias to a
prior production version, or read the append-only transition journal.
Every endpoint writes (or reads) a ``LifecycleTransitionRecord`` row --
the stage moves that this router exposes are the same ones an operator
would otherwise trigger by hand through a code release.

All endpoints require god-tier admin (team_id=None): the production
alias for a prompt key is platform-wide and gates every team's
investigations, exactly like the underlying prompt-version store
(RFC-09) and the eval-harness (RFC-08). Every request is rate-limited
to match the admin-eval / admin-prompts routers.

Endpoints:
    POST /admin/lifecycle/evaluate       score a candidate + journal a transition
    POST /admin/lifecycle/approve        sign off on a passing eval (RFC-10 quorum vote)
    POST /admin/lifecycle/promote        flip production alias if eval + quorum pass
    POST /admin/lifecycle/rollback       flip production alias back to a prior version
    POST /admin/lifecycle/shadow         register a shadow assignment for a candidate
    POST /admin/lifecycle/canary         register a canary assignment at cohort_percent
    POST /admin/lifecycle/canary/signal  feed one drift+cost sample into the hold gate
    POST /admin/lifecycle/shadow/run     off-path replay report for the active shadow
    GET  /admin/lifecycle/shadow/report  latest shadow report for (key, version)
    GET  /admin/lifecycle/transitions    list transitions for a key (newest first)
    GET  /admin/lifecycle/route          preview the cohort route for one investigation
    GET  /admin/lifecycle/metrics/versions  per-version metrics aggregation for a key

Promotion is exclusively owned here: the RFC-08 eval-runner scores
and records a verdict but NEVER flips the 'production' alias -- that
flip requires both a passing eval and a distinct-approver quorum, and
both conditions are enforced by ``AgentLifecycleController.promote``.
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
)
from aila.platform.lifecycle.assignments import (
    AssignmentState,
    LifecycleCanaryAssignment,
)
from aila.platform.lifecycle.controller import (
    AgentLifecycleController,
    CanarySignalOutcome,
    CohortRoute,
    StageTransitionError,
)
from aila.platform.lifecycle.models import (
    LifecycleStage,
    LifecycleTransitionRecord,
)
from aila.platform.lifecycle.shadow import (
    ShadowReportRecord,
    latest_shadow_report,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)

_CONTROLLER = AgentLifecycleController()


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Lifecycle transitions flip the production alias for a prompt key
    across every team, so a team-scoped admin is refused; only a god-tier
    admin (team_id=None) may evaluate, promote, or rollback a version
    that gates every team's investigations."""
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent-lifecycle administration is restricted to god-tier administrators.",
        )
    return ctx


router = APIRouter(
    prefix="/admin/lifecycle",
    tags=["admin-lifecycle"],
    dependencies=[Depends(_require_admin)],
)


class EvaluateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=32)
    benchmark_id: str = Field(min_length=1, max_length=64)


class ApproveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=4096)


class PromoteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=4096)


class RollbackRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=32)
    target_version: str | None = Field(default=None, max_length=32)
    reason: str = Field(default="", max_length=4096)


class ShadowRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=4096)


class CanaryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=32)
    cohort_percent: int = Field(ge=1, le=100)
    reason: str = Field(default="", max_length=4096)


class CanarySignalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    drift: float = Field(ge=0.0)
    cost: float = Field(ge=0.0)


class ShadowRunRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=256)
    version: str = Field(min_length=1, max_length=32)
    sample_n: int = Field(default=5, ge=1, le=100)


class ShadowReportInfo(BaseModel):
    """Response contract for a persisted shadow report row.

    Mirrors :class:`ShadowReportRecord` field-for-field so the API
    envelope reads the same shape a stored row does. ``diff_summary``
    is the decoded ``diff_summary_json`` payload -- a dict with
    ``attempts`` + ``successes`` trails and the faithfulness floor the
    run scored against.
    """

    id: str
    key: str
    version: str
    assignment_id: str | None
    sample_attempted: int
    sample_succeeded: int
    mean_faithfulness: float
    mean_determinism: float
    regressions: int
    diff_summary: dict[str, Any]
    actor: str
    created_at: datetime


class CanarySignalResponse(BaseModel):
    fired: bool
    reason: str
    signal: dict[str, Any] | None
    transition: TransitionInfo | None


class CohortRouteResponse(BaseModel):
    key: str
    version: str | None
    bucket: int
    on_canary: bool
    canary_version: str | None
    production_version: str | None
    cohort_percent: int | None


class VersionMetricsRow(BaseModel):
    """Per-version metrics aggregation row.

    Cost and drift signals are attributed to the exact ``prompt_version``
    on the ``llm_cost_records`` row (RFC-09 write-side) and the most
    recent canary hold signal on ``lifecycle_canary_assignments``. Eval
    score comes from the latest ``EvalRunRecord`` for the (key, version);
    quorum accept rate is the count of distinct approver actors on
    ``approved`` transitions over the count of prior ``evaluated``
    transitions for the same (key, version).
    """

    key: str
    version: str
    latest_stage: str | None
    eval_verdict: str | None
    eval_run_id: str | None
    eval_created_at: datetime | None
    approver_count: int
    evaluated_count: int
    quorum_accept_rate: float
    cost_usd_total: float
    cost_call_count: int
    drift_status: str | None
    drift_last_recorded: datetime | None


class VersionMetricsResponse(BaseModel):
    """Envelope for the per-version metrics endpoint."""

    key: str
    rows: list[VersionMetricsRow]


class TransitionInfo(BaseModel):
    id: str
    key: str
    version: str
    from_stage: str
    to_stage: str
    actor: str
    reason: str
    metrics_snapshot: dict[str, Any] | None
    created_at: datetime


def _to_info(record: LifecycleTransitionRecord) -> TransitionInfo:
    """Serialize a journal row into the response contract."""
    snapshot: dict[str, Any] | None
    if record.metrics_snapshot_json is None:
        snapshot = None
    else:
        parsed = json.loads(record.metrics_snapshot_json)
        snapshot = parsed if isinstance(parsed, dict) else None
    return TransitionInfo(
        id=record.id,
        key=record.key,
        version=record.version,
        from_stage=record.from_stage,
        to_stage=record.to_stage,
        actor=record.actor,
        reason=record.reason,
        metrics_snapshot=snapshot,
        created_at=record.created_at,
    )


@router.post("/evaluate", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def evaluate(
    request: Request,
    body: EvaluateRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[TransitionInfo]:
    """Score ``version`` against ``benchmark_id`` and journal a
    ``built``-to-``evaluated`` (or re-eval) transition. The eval verdict
    and referenced run id land in ``metrics_snapshot`` so ``promote`` can
    gate on the verdict without replaying the runner."""
    del request
    try:
        record = await _CONTROLLER.evaluate(
            key=body.key,
            version=body.version,
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
    return DataEnvelope(data=_to_info(record))


@router.post("/approve", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def approve(
    request: Request,
    body: ApproveRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[TransitionInfo]:
    """Record ``ctx.user_id`` as one distinct approver on a passing eval.

    Enforces the RFC-10 quorum half of the promotion gate: an approve
    row is what ``promote`` counts against ``platform.agent_promotion_quorum``
    when deciding whether to flip the production alias. Requires the
    (key, version) pair to already have a passing ``evaluated`` transition
    on record -- otherwise surfaces ``StageTransitionError`` as 409 and
    writes no journal row.
    """
    del request
    try:
        record = await _CONTROLLER.approve(
            key=body.key,
            version=body.version,
            actor=ctx.user_id,
            reason=body.reason,
        )
    except StageTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc),
        ) from exc
    return DataEnvelope(data=_to_info(record))


@router.post("/promote", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def promote(
    request: Request,
    body: PromoteRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[TransitionInfo]:
    """Flip the production alias to ``version`` when both gates pass.

    Returns 409 when the eval gate has not passed (no ``evaluated`` row
    with ``verdict='pass'``) or the quorum has not been met (fewer
    distinct approver strings on ``approved`` rows than
    ``platform.agent_promotion_quorum`` demands). The alias is left
    untouched in either case.

    RFC-10: when ``version`` is the active canary for ``key``, the flip
    goes through ``promote_from_canary`` so the min-sample gate
    (``platform.agent_canary_min_sample``) also applies and the active
    canary row is superseded. A direct (non-canary) promotion keeps the
    plain ``promote`` path unchanged.
    """
    del request
    try:
        canary_row = await _CONTROLLER.active_canary(body.key)
        if canary_row is not None and canary_row.version == body.version:
            record = await _CONTROLLER.promote_from_canary(
                key=body.key,
                version=body.version,
                actor=ctx.user_id,
                reason=body.reason,
            )
        else:
            record = await _CONTROLLER.promote(
                key=body.key,
                version=body.version,
                actor=ctx.user_id,
                reason=body.reason,
            )
    except StageTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc),
        ) from exc
    return DataEnvelope(data=_to_info(record))


@router.post("/rollback", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def rollback(
    request: Request,
    body: RollbackRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[TransitionInfo]:
    """Flip the production alias back to a prior production version.
    When ``target_version`` is omitted, resolves it as the most recent
    prior production version for the key that differs from ``version``.
    Returns 409 when no prior production transition is on record and no
    explicit ``target_version`` was supplied."""
    del request
    try:
        record = await _CONTROLLER.rollback(
            key=body.key,
            version=body.version,
            actor=ctx.user_id,
            reason=body.reason,
            target_version=body.target_version,
        )
    except StageTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc),
        ) from exc
    return DataEnvelope(data=_to_info(record))


@router.get("/transitions")
@limiter.limit("60/minute")
async def list_transitions(
    request: Request,
    key: str = Query(min_length=1, max_length=256),
    limit: int = Query(default=100, ge=1, le=500),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[TransitionInfo]]:
    """List lifecycle transitions for ``key``, newest first, bounded by
    ``limit``. Read-only inspection of the append-only journal."""
    del request, ctx
    rows = await _CONTROLLER.list_transitions(key, limit=limit)
    return DataEnvelope(data=[_to_info(r) for r in rows])


@router.post("/shadow", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def shadow(
    request: Request,
    body: ShadowRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[TransitionInfo]:
    """Register ``version`` as the active shadow for ``key``.

    Requires a prior passing evaluate on record for (key, version).
    Supersedes any prior active shadow row for the key so exactly one
    shadow is live at a time; the router still hands production to
    every real turn (a shadow is off-path by construction). Returns
    409 when the eval gate has not passed for this candidate.
    """
    del request
    try:
        record = await _CONTROLLER.shadow(
            key=body.key,
            version=body.version,
            actor=ctx.user_id,
            reason=body.reason,
        )
    except StageTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc),
        ) from exc
    return DataEnvelope(data=_to_info(record))


@router.post("/canary", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def canary(
    request: Request,
    body: CanaryRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[TransitionInfo]:
    """Register ``version`` as the active canary for ``key`` at
    ``cohort_percent`` of new investigations.

    Requires the (key, version) pair to be the current active shadow;
    a candidate cannot skip shadow and enter live cohorts. Returns 409
    when the shadow gate has not been cleared for this candidate.
    """
    del request
    try:
        record = await _CONTROLLER.canary(
            key=body.key,
            version=body.version,
            cohort_percent=body.cohort_percent,
            actor=ctx.user_id,
            reason=body.reason,
        )
    except StageTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc),
        ) from exc
    return DataEnvelope(data=_to_info(record))


@router.post("/canary/signal", status_code=status.HTTP_200_OK)
@limiter.limit("120/minute")
async def canary_signal(
    request: Request,
    body: CanarySignalRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[CanarySignalResponse]:
    """Feed one drift + cost sample into the canary hold gate.

    When either observed value breaches the matching ceiling
    (``platform.agent_canary_drift_ceiling``,
    ``platform.agent_canary_cost_ceiling_usd``), the active canary is
    held: its assignment row flips to ``held``, a ``canary``-to-``held``
    transition is journaled with the breach payload, and a WARN log
    records the breach for the operator alert path. Returns
    ``fired=false`` with ``reason='no_active_canary'`` when no active
    canary is on record for ``key``.
    """
    del request
    outcome = await _CONTROLLER.record_canary_signal(
        key=body.key,
        drift=body.drift,
        cost=body.cost,
        actor=ctx.user_id or "canary_monitor",
    )
    return DataEnvelope(data=_signal_to_response(outcome))


@router.post("/shadow/run", status_code=status.HTTP_201_CREATED)
@limiter.limit("6/minute")
async def shadow_run(
    request: Request,
    body: ShadowRunRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[ShadowReportInfo]:
    """Run the off-path shadow comparison for (key, version).

    Samples recent turns from ``llm_idempotency_cache`` (prefer rows
    matching the module's task_type), rebuilds each into a frozen
    transcript via :class:`TranscriptRecorder`, replays each transcript
    under ``version`` through :meth:`EvalRunner.replay`, and persists a
    single :class:`ShadowReportRecord` row. Returns the report summary
    -- reads only recorded state, never touches a live investigation.
    Requires an ACTIVE shadow assignment on (key, version); returns 409
    otherwise.

    Rate limit is deliberately lower than the other lifecycle writes
    because each call fans out to ``sample_n`` LLM replays through the
    replay bridge; six runs per operator per minute is generous for
    interactive inspection.
    """
    del request
    try:
        record = await _CONTROLLER.run_shadow(
            key=body.key,
            version=body.version,
            sample_n=body.sample_n,
            actor=ctx.user_id or "shadow_runner",
        )
    except StageTransitionError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail=str(exc),
        ) from exc
    if not isinstance(record, ShadowReportRecord):
        # Defensive: run_shadow's declared runtime type is object to
        # avoid a circular import, but the delegate always returns
        # ShadowReportRecord. A shape drift is a bug, not a data issue.
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="internal: run_shadow returned an unexpected type",
        )
    return DataEnvelope(data=_shadow_report_to_info(record))


@router.get("/shadow/report")
@limiter.limit("60/minute")
async def shadow_report(
    request: Request,
    key: str = Query(min_length=1, max_length=256),
    version: str = Query(min_length=1, max_length=32),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[ShadowReportInfo | None]:
    """Return the latest shadow report for (key, version), or null.

    Read-only inspection: the report table is append-only, so a caller
    that wants a history uses the transition journal filtered on
    SHADOW-to-SHADOW rows (each such row carries the report id in its
    metrics snapshot).
    """
    del request, ctx
    record = await latest_shadow_report(key=key, version=version)
    if record is None:
        return DataEnvelope(data=None)
    return DataEnvelope(data=_shadow_report_to_info(record))


def _shadow_report_to_info(record: ShadowReportRecord) -> ShadowReportInfo:
    """Render a persisted report row as the response contract."""
    diff_summary: dict[str, Any]
    if not record.diff_summary_json:
        diff_summary = {}
    else:
        try:
            parsed = json.loads(record.diff_summary_json)
            diff_summary = parsed if isinstance(parsed, dict) else {}
        except (TypeError, ValueError) as exc:
            _log.warning(
                "shadow report diff_summary_json decode failed id=%s: %s",
                record.id, exc,
            )
            diff_summary = {}
    return ShadowReportInfo(
        id=record.id,
        key=record.key,
        version=record.version,
        assignment_id=record.assignment_id,
        sample_attempted=record.sample_attempted,
        sample_succeeded=record.sample_succeeded,
        mean_faithfulness=record.mean_faithfulness,
        mean_determinism=record.mean_determinism,
        regressions=record.regressions,
        diff_summary=diff_summary,
        actor=record.actor,
        created_at=record.created_at,
    )


@router.get("/route")
@limiter.limit("120/minute")
async def resolve_route(
    request: Request,
    key: str = Query(min_length=1, max_length=256),
    investigation_id: str = Query(min_length=1, max_length=128),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[CohortRouteResponse]:
    """Resolve the cohort route for one (key, investigation_id) pair.

    Deterministic: the same ``investigation_id`` always lands in the
    same bucket, so an operator can preview which version a specific
    new investigation would receive without spending an LLM turn.
    """
    del request, ctx
    route = await _CONTROLLER.resolve_version_for_investigation(
        key=key, investigation_id=investigation_id,
    )
    return DataEnvelope(data=_route_to_response(route))


def _signal_to_response(outcome: CanarySignalOutcome) -> CanarySignalResponse:
    """Render a controller outcome as the response contract."""
    signal_payload: dict[str, Any] | None
    if outcome.signal is None:
        signal_payload = None
    else:
        signal_payload = outcome.signal.as_snapshot()
    transition_info: TransitionInfo | None
    if outcome.transition is None:
        transition_info = None
    else:
        transition_info = _to_info(outcome.transition)
    return CanarySignalResponse(
        fired=outcome.fired,
        reason=outcome.reason,
        signal=signal_payload,
        transition=transition_info,
    )


def _route_to_response(route: CohortRoute) -> CohortRouteResponse:
    """Render a cohort route as the response contract."""
    return CohortRouteResponse(
        key=route.key,
        version=route.version,
        bucket=route.bucket,
        on_canary=route.on_canary,
        canary_version=route.canary_version,
        production_version=route.production_version,
        cohort_percent=route.cohort_percent,
    )


@router.get("/metrics/versions")
@limiter.limit("30/minute")
async def list_version_metrics(
    request: Request,
    key: str = Query(min_length=1, max_length=256),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[VersionMetricsResponse]:
    """Return per-version metrics aggregation for ``key``.

    One row per version observed in the transition journal, join-
    aggregated with:

    * **Eval score** -- the verdict + run id from the most recent
      :class:`EvalRunRecord` for (key, version).
    * **Cost** -- ``SUM(cost_usd)`` from :class:`LLMCostRecord` grouped
      by ``prompt_version``.
    * **Quorum accept rate** -- distinct approver actors on ``approved``
      transitions divided by prior ``evaluated`` transitions for the
      same (key, version). 0.0 when no eval is on record.
    * **Drift** -- the most recent canary hold signal's drift status
      from :class:`LifecycleCanaryAssignment.last_signal_json`.

    Rows are ordered by the most recent transition (newest first), so
    the current production version -- or the last held canary -- lands
    at the top of the returned list.
    """
    del request, ctx
    rows = await _aggregate_version_metrics(key)
    return DataEnvelope(
        data=VersionMetricsResponse(key=key, rows=rows),
    )


async def _aggregate_version_metrics(key: str) -> list[VersionMetricsRow]:
    """Build the per-version metrics list for ``key``.

    Runs four bounded queries per call: (1) distinct versions +
    latest_stage from ``lifecycle_transitions``; (2) evaluated rows
    per version; (3) approver counts per version; (4) cost totals per
    prompt_version; plus one canary-assignment-per-version fetch for
    the drift signal. All queries scope to the single ``key``, so cost
    stays proportional to the version history depth (typically < 20
    rows).
    """
    from sqlmodel import func as _func
    from sqlmodel import select

    from aila.platform.eval.models import EvalRunRecord
    from aila.platform.llm.cost_record import LLMCostRecord
    from aila.storage.database import async_session_scope

    async with async_session_scope() as session:
        # (1) Distinct versions + latest transition per version.
        transitions = (await session.exec(
            select(LifecycleTransitionRecord)
            .where(LifecycleTransitionRecord.key == key)
            .order_by(LifecycleTransitionRecord.created_at.desc())
        )).all()
        if not transitions:
            return []
        latest_stage_by_version: dict[str, str] = {}
        evaluated_count_by_version: dict[str, int] = {}
        approvers_by_version: dict[str, set[str]] = {}
        order: list[str] = []
        for row in transitions:
            if row.version not in latest_stage_by_version:
                latest_stage_by_version[row.version] = row.to_stage
                order.append(row.version)
            if row.to_stage == LifecycleStage.EVALUATED.value:
                evaluated_count_by_version[row.version] = (
                    evaluated_count_by_version.get(row.version, 0) + 1
                )
            if row.to_stage == LifecycleStage.APPROVED.value:
                approvers_by_version.setdefault(
                    row.version, set(),
                ).add(row.actor or "")

        # (2) Latest eval verdict per (key, version).
        eval_rows = (await session.exec(
            select(EvalRunRecord)
            .where(EvalRunRecord.key == key)
            .order_by(EvalRunRecord.created_at.desc())
        )).all()
        latest_eval_by_version: dict[str, EvalRunRecord] = {}
        for row in eval_rows:
            if row.candidate_version not in latest_eval_by_version:
                latest_eval_by_version[row.candidate_version] = row

        # (3) Cost aggregation grouped by prompt_version. Scoped to the
        # versions we already know exist (versions the transition journal
        # never mentioned would not appear here anyway; the transition
        # journal is the source of truth for which versions exist for key).
        cost_rows = (await session.exec(
            select(  # type: ignore[call-overload]
                LLMCostRecord.prompt_version,
                _func.coalesce(_func.sum(LLMCostRecord.cost_usd), 0.0),
                _func.count(LLMCostRecord.id),
            )
            .where(LLMCostRecord.prompt_version.in_(list(latest_stage_by_version.keys())))  # type: ignore[attr-defined]
            .group_by(LLMCostRecord.prompt_version)
        )).all()
        cost_total_by_version: dict[str, float] = {}
        cost_count_by_version: dict[str, int] = {}
        for prompt_version, total, count in cost_rows:
            if prompt_version is None:
                continue
            cost_total_by_version[str(prompt_version)] = float(total or 0.0)
            cost_count_by_version[str(prompt_version)] = int(count or 0)

        # (4) Drift signal per version: pull every canary assignment
        # for the key so an in-active or held row's last_signal_json
        # still surfaces here for operator inspection.
        assignment_rows = (await session.exec(
            select(LifecycleCanaryAssignment)
            .where(LifecycleCanaryAssignment.key == key)
            .order_by(LifecycleCanaryAssignment.updated_at.desc())
        )).all()
        drift_by_version: dict[str, tuple[str, datetime]] = {}
        for row in assignment_rows:
            if row.version in drift_by_version:
                continue
            drift_status: str | None = None
            if row.last_signal_json:
                try:
                    payload = json.loads(row.last_signal_json)
                    if isinstance(payload, dict):
                        # Prefer explicit status; otherwise fall back to
                        # the state (held / active) as a proxy signal.
                        raw_status = (
                            payload.get("status")
                            or payload.get("drift_status")
                        )
                        if raw_status is not None:
                            drift_status = str(raw_status)
                except (TypeError, ValueError):
                    drift_status = None
            if drift_status is None:
                # Reflect the current row state so a held-without-payload
                # canary still surfaces a signal string.
                drift_status = (
                    "held"
                    if row.state == AssignmentState.HELD.value
                    else None
                )
            if drift_status is not None:
                drift_by_version[row.version] = (drift_status, row.updated_at)

    # Assemble the response rows, preserving the newest-transition order.
    rows_out: list[VersionMetricsRow] = []
    for version in order:
        evaluated_count = evaluated_count_by_version.get(version, 0)
        approvers = approvers_by_version.get(version, set())
        approver_count = len({a for a in approvers if a})
        quorum_accept_rate = (
            approver_count / evaluated_count
            if evaluated_count > 0
            else 0.0
        )
        eval_row = latest_eval_by_version.get(version)
        drift_pair = drift_by_version.get(version)
        rows_out.append(
            VersionMetricsRow(
                key=key,
                version=version,
                latest_stage=latest_stage_by_version.get(version),
                eval_verdict=eval_row.verdict if eval_row else None,
                eval_run_id=eval_row.id if eval_row else None,
                eval_created_at=eval_row.created_at if eval_row else None,
                approver_count=approver_count,
                evaluated_count=evaluated_count,
                quorum_accept_rate=quorum_accept_rate,
                cost_usd_total=cost_total_by_version.get(version, 0.0),
                cost_call_count=cost_count_by_version.get(version, 0),
                drift_status=drift_pair[0] if drift_pair else None,
                drift_last_recorded=drift_pair[1] if drift_pair else None,
            ),
        )
    return rows_out
