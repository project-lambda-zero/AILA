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
    GET  /admin/lifecycle/transitions    list transitions for a key (newest first)

The RFC-08 eval-runner ``auto_promote`` fast path stays admin-opt-in
and is eval-only by design; the quorum-gated path lives here on the
lifecycle controller.
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
from aila.platform.lifecycle.controller import (
    AgentLifecycleController,
    StageTransitionError,
)
from aila.platform.lifecycle.models import LifecycleTransitionRecord

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
    """
    del request
    try:
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
