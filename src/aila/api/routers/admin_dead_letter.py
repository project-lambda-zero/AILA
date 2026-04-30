"""Admin dead-letter router (Phase 178).

Exposes the dead-letter sorted sets ``arq:dead-letter:{track}`` as a
read-only admin surface plus a manual requeue action. Dead-lettered tasks
are NOT retried automatically — operators must inspect the failure, fix
the root cause, then issue POST /admin/tasks/dead-letter/{task_id}/requeue
to re-submit the same payload.

All endpoints require admin role. Every request is rate-limited.

Endpoints:
    GET  /admin/tasks/dead-letter
        List dead-lettered tasks for the configured tracks. Supports a
        ``track`` query parameter to narrow the result. Returns the
        original fn_path, kwargs, exception class, attempt count, and
        the UTC timestamp when the task was dead-lettered.

    POST /admin/tasks/dead-letter/{task_id}/requeue
        Reset the TaskRecord poison counter, move it back to QUEUED, and
        re-enqueue onto the original track. Removes the dead-letter entry
        from Redis on success. 404 if the task is not found; 409 if it is
        not currently in status=dead_letter.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from typing import Any

import structlog
from redis.exceptions import RedisError as _AnyRedisError
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import update as sa_update
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.tasks.constants import (
    ARQ_DEAD_LETTER_KEY_TEMPLATE,
)
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import async_session_scope

__all__ = ["router"]

_log = logging.getLogger(__name__)
_slog = structlog.get_logger(__name__)


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    return ctx


router = APIRouter(
    prefix="/admin/tasks",
    tags=["admin-tasks"],
    dependencies=[Depends(_require_admin)],
)


class DeadLetterEntry(BaseModel):
    task_id: str
    track: str
    fn_path: str
    fn_module: str
    user_id: str
    error: str
    attempts: int
    exception_class: str
    dead_lettered_at: datetime


async def _scan_tracks() -> list[str]:
    """Return every track that currently has a dead-letter set in Redis."""
    redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not redis_url:
        return []

    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
    try:
        tracks: list[str] = []
        pattern = ARQ_DEAD_LETTER_KEY_TEMPLATE.format(track="*")
        async for key in client.scan_iter(match=pattern, count=100):
            key_str = key.decode("utf-8", errors="replace") if isinstance(key, bytes) else str(key)
            track = key_str.split(":")[-1]
            tracks.append(track)
        return tracks
    finally:
        try:
            await client.aclose()
        except OSError:
            _log.debug("dead-letter redis close failed (_scan_tracks)", exc_info=True)


async def _load_entries(track: str | None) -> list[DeadLetterEntry]:
    redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if not redis_url:
        return []

    tracks = [track] if track else await _scan_tracks()
    if not tracks:
        return []

    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
    entries: list[DeadLetterEntry] = []
    try:
        for tr in tracks:
            key = ARQ_DEAD_LETTER_KEY_TEMPLATE.format(track=tr)
            # Newest first (ZREVRANGE); cap at 500 per track for safety.
            raw_entries = await client.zrevrange(key, 0, 499)
            for raw in raw_entries:
                try:
                    data: dict[str, Any] = json.loads(
                        raw.decode("utf-8") if isinstance(raw, bytes) else raw
                    )
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                try:
                    entries.append(
                        DeadLetterEntry(
                            task_id=str(data.get("task_id", "")),
                            track=str(data.get("track", tr)),
                            fn_path=str(data.get("fn_path", "")),
                            fn_module=str(data.get("fn_module", "")),
                            user_id=str(data.get("user_id", "")),
                            error=str(data.get("error", "")),
                            attempts=int(data.get("attempts", 0) or 0),
                            exception_class=str(data.get("exception_class", "")),
                            dead_lettered_at=datetime.fromisoformat(
                                str(data.get("dead_lettered_at"))
                            ),
                        )
                    )
                except (KeyError, ValueError, TypeError):
                    _log.debug("dropped malformed dead-letter entry", exc_info=True)
    finally:
        try:
            await client.aclose()
        except OSError:
            _log.debug("dead-letter redis close failed (_load_entries)", exc_info=True)
    return entries


@router.get(
    "/dead-letter",
    response_model=DataEnvelope[list[DeadLetterEntry]],
    summary="List dead-lettered tasks",
)
@limiter.limit("30/minute")
async def list_dead_letter(
    request: Request,
    track: str | None = Query(default=None, max_length=64),
) -> DataEnvelope[list[DeadLetterEntry]]:
    """Return dead-lettered tasks, newest first. Admin only."""
    del request  # FastAPI signature requirement for the rate-limiter decorator.
    entries = await _load_entries(track)
    return DataEnvelope(data=entries)


@router.post(
    "/dead-letter/{task_id}/requeue",
    response_model=DataEnvelope[dict[str, str]],
    summary="Manually requeue a dead-lettered task",
)
@limiter.limit("10/minute")
async def requeue_dead_letter(
    request: Request,
    task_id: str,
) -> DataEnvelope[dict[str, str]]:
    """Transition dead_letter -> queued, re-enqueue (Phase 179)."""
    del request
    async with async_session_scope() as session:
        rec = (await session.exec(
            select(TaskRecord).where(TaskRecord.id == task_id)
        )).first()
        if rec is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task {task_id!r} not found",
            )
        if rec.status != TaskStatus.DEAD_LETTER:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Task {task_id!r} is not dead-lettered (status={rec.status}). "
                    "Only dead-lettered tasks can be requeued via this endpoint."
                ),
            )

        current_version = rec.version
        result = await session.execute(
            sa_update(TaskRecord)
            .where(TaskRecord.id == task_id)
            .where(TaskRecord.version == current_version)
            .values(
                status=TaskStatus.QUEUED,
                error=None,
                completed_at=None,
                version=current_version + 1,
            )
        )
        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Optimistic lock conflict; retry",
            )
        await session.commit()
        track = rec.track

    # Remove the entry from the dead-letter zset (best-effort).
    redis_url = os.environ.get("AILA_PLATFORM_REDIS_URL", "").strip()
    if redis_url:
        try:
            import redis.asyncio as aioredis

            client = aioredis.Redis.from_url(redis_url, socket_connect_timeout=2.0)
            try:
                key = ARQ_DEAD_LETTER_KEY_TEMPLATE.format(track=track)
                members = await client.zrange(key, 0, -1)
                for raw in members:
                    try:
                        data = json.loads(
                            raw.decode("utf-8") if isinstance(raw, bytes) else raw
                        )
                        if str(data.get("task_id")) == task_id:
                            await client.zrem(key, raw)
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
            finally:
                try:
                    await client.aclose()
                except OSError:
                    pass
        except (OSError, _AnyRedisError):
            _log.warning("failed to trim dead-letter entry for %s", task_id, exc_info=True)

    _slog.info("dead_letter_requeued", task_id=task_id, track=track)
    return DataEnvelope(data={"task_id": task_id, "status": TaskStatus.QUEUED})
