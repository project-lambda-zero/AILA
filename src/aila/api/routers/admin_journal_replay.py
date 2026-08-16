"""Admin journal-replay router (#209 dead-column liveness).

Drains ``platform_journal_deadletter`` back into the main hash-chained
journal. Every un-replayed row (``replayed_at IS NULL``) is re-attempted
via the standard :func:`append` path against the current chain head; on
success the row is stamped with ``replayed_at`` and ``replay_seq`` so a
second call is idempotent and does not double-append. A row that still
fails the chain (or a DB integrity error) is left un-replayed with the
failure class recorded in the response.

All endpoints require god-tier admin (team_id=None): a team-scoped admin
could otherwise force a replay of another team's dead-lettered audit
row into the wrong chain scope.

Endpoints:
    POST /admin/journal/deadletter/replay
        Body: {"team_id": "<id>" | null, "limit": <int> | null}
        Run one :func:`replay_deadletters` batch. Returns per-row
        outcomes plus scanned/replayed/failed counts.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.services.journal import (
    DeadletterReplayEntry,
    ReplayResult,
    replay_deadletters,
)
from aila.storage.database import async_session_scope

__all__ = ["router"]

_log = logging.getLogger(__name__)


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Replay writes rows into a chain the operator does not necessarily
    own; god-tier admin (team_id=None) only, matching admin_dead_letter."""
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Journal dead-letter replay is restricted to god-tier "
                "administrators."
            ),
        )
    return ctx


router = APIRouter(
    prefix="/admin/journal",
    tags=["admin-journal"],
    dependencies=[Depends(_require_admin)],
)


class ReplayRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team_id: str | None = Field(default=None, min_length=1, max_length=36)
    limit: int | None = Field(default=None, ge=1, le=1000)


class ReplayResponseEntry(BaseModel):
    deadletter_id: str
    chain_id: str
    team_id: str | None
    replayed: bool
    journal_id: str | None
    seq: int | None
    error: str | None


class ReplayResponse(BaseModel):
    scanned: int
    replayed: int
    failed: int
    entries: list[ReplayResponseEntry]


def _entry_to_response(entry: DeadletterReplayEntry) -> ReplayResponseEntry:
    return ReplayResponseEntry(
        deadletter_id=entry.deadletter_id,
        chain_id=entry.chain_id,
        team_id=entry.team_id,
        replayed=entry.replayed,
        journal_id=entry.journal_id,
        seq=entry.seq,
        error=entry.error,
    )


def _result_to_response(result: ReplayResult) -> ReplayResponse:
    return ReplayResponse(
        scanned=result.scanned,
        replayed=result.replayed,
        failed=result.failed,
        entries=[_entry_to_response(e) for e in result.entries],
    )


@router.post("/deadletter/replay", status_code=status.HTTP_200_OK)
@limiter.limit("10/minute")
async def replay_journal_deadletters(
    request: Request,
    body: ReplayRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[ReplayResponse]:
    """Drain un-replayed journal dead-letter rows back into their chains."""
    del request
    _log.info(
        "admin.journal.replay team_id=%s limit=%s actor=%s",
        body.team_id, body.limit, ctx.user_id or "unknown",
    )
    async with async_session_scope() as session:
        result = await replay_deadletters(
            session, team_id=body.team_id, limit=body.limit
        )
        await session.commit()
    return DataEnvelope(data=_result_to_response(result))
