"""Admin auto-patch attempts router (issue #149).

Operator surface for reviewing :class:`PlatformPatchAttemptRecord`
rows produced by :mod:`aila.platform.services.patching`. Every
endpoint requires god-tier admin (``team_id=None``): patch attempts
carry cross-module context (a synthesised diff, sandbox output, cost
roll-up) and a team-scoped admin has no business reading another
team's diffs.

Endpoints:

    GET /platform/patching/attempts
        List patch attempts with optional filtering by
        ``investigation_id`` / ``module_id`` / ``verify_status``.
        Paginated newest-first via ``limit`` + ``offset``. Returns
        every column of :class:`PlatformPatchAttemptRecord` projected
        through :class:`PatchAttemptResponse`.

    GET /platform/patching/attempts/{attempt_id}
        Fetch one attempt by id. 404 when the row is not found.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlmodel import select as _select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import PlatformPatchAttemptRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Patch-attempt visibility is a platform-wide operator surface.

    A team-scoped admin has no business reading another team's
    synthesised diffs or sandbox output; every route below is
    god-tier only.
    """
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Platform patch-attempt visibility is restricted to "
                "god-tier administrators."
            ),
        )
    return ctx


router = APIRouter(
    prefix="/platform/patching",
    tags=["platform-patching"],
    dependencies=[Depends(_require_admin)],
)


class PatchAttemptResponse(BaseModel):
    """Projection of :class:`PlatformPatchAttemptRecord` for the admin
    surface. Every column is surfaced verbatim -- there is no
    aggregation or derived field so an operator can correlate a row
    with the underlying DB write without an extra lookup."""

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str | None
    outcome_id: str | None
    module_id: str
    team_id: str | None
    finding_ref: str
    synth_model: str
    synth_task_type: str
    synth_prompt_tokens: int
    synth_completion_tokens: int
    synth_cost_usd: float
    patch_diff: str
    patch_files: list[str]
    verify_status: str
    verify_backend: str
    verify_exit_code: int | None
    verify_stdout: str
    verify_stderr: str
    verify_duration_s: float
    verify_reason: str
    harness: dict[str, Any]
    total_cost_usd: float
    created_at: str
    updated_at: str


class PatchAttemptListResponse(BaseModel):
    """Paginated response for ``GET /platform/patching/attempts``."""

    model_config = ConfigDict(extra="forbid")

    attempts: list[PatchAttemptResponse]
    count: int
    limit: int
    offset: int


def _to_response(row: PlatformPatchAttemptRecord) -> PatchAttemptResponse:
    """Project a DB row into the response shape.

    JSON columns (``patch_files_json``, ``harness_json``) are decoded
    into typed fields so the admin UI does not have to re-parse them.
    Malformed JSON degrades to empty defaults rather than raising --
    the row was written by the platform, but an operator running a
    manual UPDATE could still hand us junk.
    """
    try:
        patch_files = json.loads(row.patch_files_json or "[]")
        if not isinstance(patch_files, list):
            patch_files = []
    except (ValueError, TypeError):
        patch_files = []
    try:
        harness = json.loads(row.harness_json or "{}")
        if not isinstance(harness, dict):
            harness = {}
    except (ValueError, TypeError):
        harness = {}

    return PatchAttemptResponse(
        id=row.id,
        investigation_id=row.investigation_id,
        outcome_id=row.outcome_id,
        module_id=row.module_id,
        team_id=row.team_id,
        finding_ref=row.finding_ref,
        synth_model=row.synth_model,
        synth_task_type=row.synth_task_type,
        synth_prompt_tokens=row.synth_prompt_tokens,
        synth_completion_tokens=row.synth_completion_tokens,
        synth_cost_usd=row.synth_cost_usd,
        patch_diff=row.patch_diff,
        patch_files=[str(p) for p in patch_files],
        verify_status=row.verify_status,
        verify_backend=row.verify_backend,
        verify_exit_code=row.verify_exit_code,
        verify_stdout=row.verify_stdout,
        verify_stderr=row.verify_stderr,
        verify_duration_s=row.verify_duration_s,
        verify_reason=row.verify_reason,
        harness=harness,
        total_cost_usd=row.total_cost_usd,
        created_at=row.created_at.isoformat(),
        updated_at=row.updated_at.isoformat(),
    )


@router.get("/attempts", status_code=status.HTTP_200_OK)
@limiter.limit("60/minute")
async def list_patch_attempts(
    request: Request,
    ctx: AuthContext = Depends(_require_admin),
    investigation_id: str | None = Query(
        default=None,
        description="Filter to attempts for one investigation.",
    ),
    module_id: str | None = Query(
        default=None,
        description="Filter to attempts by module id (``vr`` / ``malware`` / ...).",
    ),
    verify_status: str | None = Query(
        default=None,
        description="Filter to one verify verdict (``accepted`` / ``rejected`` / ``skipped`` / ``error`` / ``pending``).",
    ),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> DataEnvelope[PatchAttemptListResponse]:
    """Paginated newest-first list of :class:`PlatformPatchAttemptRecord`
    rows. Every filter is optional; empty result set is normal on any
    deployment that has not flipped ``platform.autopatch_enabled`` to
    True (the flag defaults OFF and no rows are ever written).
    """
    del request, ctx
    async with UnitOfWork() as uow:
        stmt = _select(PlatformPatchAttemptRecord)
        if investigation_id:
            stmt = stmt.where(
                PlatformPatchAttemptRecord.investigation_id == investigation_id,
            )
        if module_id:
            stmt = stmt.where(
                PlatformPatchAttemptRecord.module_id == module_id,
            )
        if verify_status:
            stmt = stmt.where(
                PlatformPatchAttemptRecord.verify_status == verify_status,
            )
        stmt = stmt.order_by(
            PlatformPatchAttemptRecord.created_at.desc(),
        ).offset(offset).limit(limit)
        rows = list((await uow.session.exec(stmt)).all())

    projected = [_to_response(r) for r in rows]
    return DataEnvelope(data=PatchAttemptListResponse(
        attempts=projected,
        count=len(projected),
        limit=limit,
        offset=offset,
    ))


@router.get("/attempts/{attempt_id}", status_code=status.HTTP_200_OK)
@limiter.limit("60/minute")
async def get_patch_attempt(
    request: Request,
    attempt_id: str,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[PatchAttemptResponse]:
    """Fetch one attempt by id. 404 when the row is not found."""
    del request, ctx
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            _select(PlatformPatchAttemptRecord).where(
                PlatformPatchAttemptRecord.id == attempt_id,
            )
        )).first()
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"patch attempt {attempt_id!r} not found",
        )
    return DataEnvelope(data=_to_response(row))
