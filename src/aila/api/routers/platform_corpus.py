"""Admin router for the trajectory -> SFT/DPO corpus export (issue #158).

Two endpoints, both god-tier admin (``team_id=None``):

* ``POST /platform/eval/corpus/export`` -- enqueues the
  :func:`aila.platform.tasks.corpus_export.run_corpus_export` platform
  task through the standard :class:`TaskQueue` submit path; returns
  the resulting ``task_id`` so the caller can poll ``GET /tasks/{id}``
  for completion.
* ``GET /platform/eval/corpus/stats`` -- reads the latest
  ``manifest.json`` from the configured corpus directory and returns
  the counts + coverage; a fresh install with no prior export replies
  with a clear ``no corpus yet`` marker instead of a 500.

Corpus export is platform-wide (walks every configured module's
outcome table) so a team-scoped admin has no business kicking it off
-- the auth dependency mirrors the pattern in ``admin_eval.py``,
``admin_lifecycle.py`` and ``admin_journal_replay.py``.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import SQLAlchemyError

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.deps import get_config_registry
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.config import PlatformConfigSchema
from aila.platform.eval.corpus import resolve_corpus_output_dir
from aila.platform.tasks.corpus_export import run_corpus_export
from aila.platform.tasks.queue import TaskQueue
from aila.storage.registry import ConfigRegistry

__all__ = ["router"]

_log = logging.getLogger(__name__)


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Corpus export walks every configured module's outcome table and
    writes a shared platform-wide artifact -- god-tier only, matching
    :mod:`aila.api.routers.admin_eval`."""
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Corpus export is restricted to god-tier administrators."
            ),
        )
    return ctx


router = APIRouter(
    prefix="/platform/eval/corpus",
    tags=["admin-corpus"],
    dependencies=[Depends(_require_admin)],
)


class CorpusExportRequest(BaseModel):
    """Optional overrides for a manual corpus export trigger."""

    model_config = ConfigDict(extra="forbid")

    modules: list[str] | None = Field(
        default=None,
        description=(
            "Optional override of ``platform.corpus_modules``. Omit or "
            "pass an empty list to use the configured value."
        ),
    )
    lookback_days: int | None = Field(
        default=None,
        ge=1,
        le=3650,
        description=(
            "Window (in days) counted back from now; ``None`` scans "
            "everything the outcome tables carry."
        ),
    )


class CorpusExportResponse(BaseModel):
    """Response body for the manual export trigger."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    status: str
    modules: list[str] | None
    lookback_days: int | None


class CorpusStatsResponse(BaseModel):
    """Latest-manifest projection returned by the stats endpoint."""

    model_config = ConfigDict(extra="forbid")

    has_corpus: bool
    corpus_dir: str
    sft_path: str | None = None
    dpo_path: str | None = None
    manifest_path: str | None = None
    generated_at: datetime | None = None
    sft_count: int = 0
    dpo_count: int = 0
    investigations: int = 0
    module_breakdown: dict[str, int] = Field(default_factory=dict)
    modules: list[str] = Field(default_factory=list)
    min_turns: int = 0
    max_field_chars: int = 0
    skipped_short_branches: int = 0
    skipped_unparseable_decisions: int = 0
    detail: str | None = None


@router.post(
    "/export",
    response_model=DataEnvelope[CorpusExportResponse],
    summary="Trigger a trajectory -> SFT/DPO corpus export",
)
@limiter.limit("5/minute")
async def trigger_corpus_export(
    request: Request,
    body: CorpusExportRequest | None = None,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[CorpusExportResponse]:
    """Enqueue the corpus-export platform task and return the task id."""
    payload = body or CorpusExportRequest()
    modules = payload.modules or None
    lookback_days = payload.lookback_days

    task_queue = TaskQueue(
        config_registry=get_config_registry(request),
        module_id="__platform__",
    )
    try:
        handle = await task_queue.submit(
            track="default",
            fn=run_corpus_export,
            kwargs={
                "modules": list(modules) if modules else None,
                "lookback_days": lookback_days,
            },
            user_id=ctx.user_id,
            group_id=ctx.role,
            team_id=ctx.team_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return DataEnvelope(
        data=CorpusExportResponse(
            task_id=handle.task_id,
            status="queued",
            modules=modules,
            lookback_days=lookback_days,
        ),
        meta={"triggered_by": ctx.user_id},
    )


@router.get(
    "/stats",
    response_model=DataEnvelope[CorpusStatsResponse],
    summary="Return the latest corpus export manifest",
)
@limiter.limit("60/minute")
async def read_corpus_stats(
    request: Request,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[CorpusStatsResponse]:
    """Return the latest ``manifest.json`` counts, or a ``no corpus yet``.

    Reads the on-disk manifest so the response is cheap even when the
    corpus is large -- we never re-open the jsonl files here.
    """
    del ctx
    registry = get_config_registry(request)
    output_dir_raw = await _read_str(
        registry, "corpus_output_dir", PlatformConfigSchema().corpus_output_dir,
    )
    output_dir = resolve_corpus_output_dir(output_dir_raw)
    manifest_path = output_dir / "manifest.json"

    if not manifest_path.exists():
        return DataEnvelope(
            data=CorpusStatsResponse(
                has_corpus=False,
                corpus_dir=str(output_dir),
                detail="no corpus yet -- POST /platform/eval/corpus/export to build one",
            ),
            meta={},
        )
    try:
        raw = manifest_path.read_text(encoding="utf-8")
        payload: dict[str, Any] = json.loads(raw)
    except (OSError, ValueError, TypeError) as exc:
        _log.warning(
            "corpus stats manifest unreadable at %s: %s", manifest_path, exc,
        )
        return DataEnvelope(
            data=CorpusStatsResponse(
                has_corpus=False,
                corpus_dir=str(output_dir),
                manifest_path=str(manifest_path),
                detail=f"manifest present but unreadable: {type(exc).__name__}",
            ),
            meta={},
        )

    generated_at_raw = payload.get("generated_at")
    generated_at: datetime | None = None
    if isinstance(generated_at_raw, str):
        try:
            generated_at = datetime.fromisoformat(generated_at_raw)
        except ValueError:
            generated_at = None

    return DataEnvelope(
        data=CorpusStatsResponse(
            has_corpus=True,
            corpus_dir=str(output_dir),
            sft_path=payload.get("sft_path") or str(output_dir / "sft.jsonl"),
            dpo_path=payload.get("dpo_path") or str(output_dir / "dpo.jsonl"),
            manifest_path=str(manifest_path),
            generated_at=generated_at,
            sft_count=int(payload.get("sft_count") or 0),
            dpo_count=int(payload.get("dpo_count") or 0),
            investigations=int(payload.get("investigations") or 0),
            module_breakdown=dict(payload.get("module_breakdown") or {}),
            modules=list(payload.get("modules") or []),
            min_turns=int(payload.get("min_turns") or 0),
            max_field_chars=int(payload.get("max_field_chars") or 0),
            skipped_short_branches=int(payload.get("skipped_short_branches") or 0),
            skipped_unparseable_decisions=int(
                payload.get("skipped_unparseable_decisions") or 0,
            ),
        ),
        meta={},
    )


async def _read_str(registry: ConfigRegistry, key: str, default: str) -> str:
    """Resolve a platform-namespaced string config with schema-default fallback."""
    try:
        raw = await registry.get("platform", key)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    return str(raw)
