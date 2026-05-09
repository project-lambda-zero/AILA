"""Tasks router for AILA REST API.

Exposes the task queue lifecycle surface:
- GET  /tasks                    — list tasks (scoped to user's group_id)
- GET  /tasks/{task_id}          — get single task (scoped)
- POST /tasks/{task_id}/cancel   — cancel a non-terminal task
- POST /tasks/{task_id}/resume   — resume a PAUSED task (MOD-09/D-11)
- GET  /tasks/{task_id}/events   — SSE stream from Redis Streams (TASK-08/09)
- GET  /tasks/queue-depth        — admin: task counts by status (OPS-04)
- POST /tasks/drain              — admin: pause new submissions (OPS-05)
- POST /tasks/requeue-failed     — admin: requeue recent failures (OPS-05)
- POST /task                     — submit freeform task (TASK-01, D-09)

All endpoints require authentication (Bearer JWT).
List/get queries are scoped by group_id unless the caller is admin (D-22/MOD-13).

SSE endpoint:
1. Verifies the caller has access to the task (same scoping as get endpoint)
2. If Redis is configured: replays all events from last_id param via catchup(),
   then streams new events via stream_events() (D-17/TASK-09 late-connect)
3. If Redis is not configured: returns a single informational SSE event and closes

POST /task:
- Requires operator+ role (D-15)
- Wraps TaskQueue.submit() in asyncio.to_thread() per HANG-03 (sync call from async def)
- Returns 503 if platform is not initialized

Ownership: Platform API layer — not module-specific.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlmodel import select

from aila.api.auth import AuthContext, require_role, require_user_or_api_key
from aila.api.constants import (
    AUDIT_ACTION_TASK_CANCEL,
    AUDIT_ACTION_TASK_RESUME,
    AUDIT_ACTION_TASK_SUBMIT,
    AUDIT_STAGE_TASK,
    AUDIT_STATUS_COMPLETED,
    MEDIA_TYPE_SSE,
    MODULE_ID_PLATFORM,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    TRACK_PLATFORM,
)
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.tasks import (
    DrainQueueResponse,
    TaskActionResponse,
    TaskCreateRequest,
    TaskListResponse,
    TaskResponse,
    TaskSubmitResponse,
)
from aila.api.schemas.transitions import TransitionView
from aila.platform.services.audit import record_audit_event
from aila.platform.services.redis_pool import pool_available
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.storage import TaskRepository
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowStateTransition

__all__ = ["router", "task_submit_router"]

_log = logging.getLogger(__name__)
_TRANSITIONS_LIMIT = 500  # safety cap — prevents unbounded reads on high-retry runs

router = APIRouter(
    prefix="/tasks",
    tags=["tasks"],
    dependencies=[Depends(require_user_or_api_key)],
)


def _record_to_response(record: TaskRecord) -> TaskResponse:
    return TaskResponse(
        task_id=record.id,
        track=record.track,
        status=record.status,
        user_id=record.user_id,
        group_id=record.group_id,
        fn_path=record.fn_path,
        fn_module=record.fn_module,
        created_at=record.created_at,
        started_at=record.started_at,
        completed_at=record.completed_at,
        heartbeat_at=record.heartbeat_at,
        error=record.error,
        result_path=record.result_path,
        # Phase 179: cursor column dropped; state lives in
        # workflow_state_cursor. Always False until Phase 180 wires a
        # workflow-cursor lookup for the schema field.
        has_checkpoint=False,
    )


@router.get(
    "",
    response_model=TaskListResponse,
    summary="List tasks visible to the authenticated user",
)
async def list_tasks(
    track: str | None = Query(default=None, description="Filter by task track"),
    task_status: str | None = Query(default=None, alias="status", description="Filter by status"),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> TaskListResponse:
    """Return all tasks visible to the authenticated user.

    Admin role sees all tasks. Other roles see only tasks in their group_id.
    Optional track and status query parameters narrow the result set.
    """

    async def _query() -> list[TaskRecord]:
        async with async_session_scope() as session:
            return await TaskRepository.list_for_user(session, auth, track=track, status=task_status)

    records = await _query()
    return TaskListResponse(
        tasks=[_record_to_response(r) for r in records],
        total=len(records),
    )


# ---- Admin queue management helpers (OPS-04/OPS-05) ----


def _get_task_queue(request: Request):  # type: ignore[return]
    """Get the platform TaskQueue from app state.

    Used by admin queue management endpoints. Falls back to a minimal
    TaskQueue instance if the platform is not initialized.
    """
    from aila.platform.tasks.queue import TaskQueue

    platform = getattr(request.app.state, "platform", None)
    if platform is not None:
        tq = getattr(platform, "task_queue", None)
        if tq is not None:
            return tq
    # Fallback: create a lightweight TaskQueue for admin-only operations
    # (depth/drain/requeue don't need config_registry or module_id). We use
    # the canonical MODULE_ID_PLATFORM constant instead of the literal so
    # grep-based audits can trace every platform-scoped enqueue path (D-06 /
    # BE-G from Phase 176a). This helper does NOT create user-visible tasks;
    # those go through module-specific submit paths with real module_ids.
    return TaskQueue(config_registry=None, module_id=MODULE_ID_PLATFORM)  # type: ignore[arg-type]


@limiter.limit("10/minute")
@router.get(
    "/queue-depth",
    response_model=DataEnvelope[dict[str, int]],
    summary="Get queue depth by status",
)
async def get_queue_depth(
    request: Request,
    auth: AuthContext = Depends(require_role(ROLE_ADMIN)),
) -> DataEnvelope[dict[str, int]]:
    """Return task counts grouped by status. Admin only."""
    queue = _get_task_queue(request)
    depth = await queue.depth()
    return DataEnvelope(data=depth)


@limiter.limit("5/minute")
@router.post(
    "/drain",
    response_model=DataEnvelope[DrainQueueResponse],
    summary="Drain queue - stop new submissions",
)
async def drain_queue(
    request: Request,
    auth: AuthContext = Depends(require_role(ROLE_ADMIN)),
) -> DataEnvelope[DrainQueueResponse]:
    """Pause new task submissions and return pending task count. Admin only."""
    queue = _get_task_queue(request)
    pending = await queue.drain()
    return DataEnvelope(data=DrainQueueResponse(pending=pending, draining=True))


@limiter.limit("5/minute")
@router.post(
    "/requeue-failed",
    response_model=DataEnvelope[dict[str, int]],
    summary="Requeue recently failed tasks",
)
async def requeue_failed_tasks(
    request: Request,
    auth: AuthContext = Depends(require_role(ROLE_ADMIN)),
    max_age_hours: int = Query(default=24, ge=1, le=168),
) -> DataEnvelope[dict[str, int]]:
    """Requeue tasks that failed within max_age_hours. Admin only."""
    queue = _get_task_queue(request)
    count = await queue.requeue_failed(max_age_hours=max_age_hours)
    return DataEnvelope(data={"requeued": count})


# ---- Per-task endpoints (must be after static paths to avoid route conflicts) ----


@router.get(
    "/{task_id}",
    response_model=TaskResponse,
    summary="Get a single task by ID",
)
async def get_task(
    task_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> TaskResponse:
    """Return a single task visible to the authenticated user.

    Raises 404 if the task does not exist or is not accessible to the caller.
    """

    async def _fetch() -> TaskRecord | None:
        async with async_session_scope() as session:
            return await TaskRepository.get_for_user(session, task_id, auth)

    record = await _fetch()
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id!r} not found or not accessible -- verify the task_id via GET /tasks",
        )
    return _record_to_response(record)


@limiter.limit("60/minute")
@router.post(
    "/{task_id}/cancel",
    response_model=TaskActionResponse,
    summary="Cancel a non-terminal task",
)
async def cancel_task(
    request: Request,
    task_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> TaskActionResponse:
    """Mark a non-terminal task as CANCELLED.

    Returns 409 Conflict if the task is already in a terminal state
    (done, failed, cancelled) or 404 if not found / not accessible.
    """

    async def _cancel() -> bool:
        async with async_session_scope() as session:
            return await TaskRepository.set_cancelled(session, task_id, auth)

    updated = await _cancel()
    if not updated:
        # Distinguish 404 (not found/accessible) from 409 (already terminal)
        async def _exists() -> bool:
            async with async_session_scope() as session:
                return await TaskRepository.get_for_user(session, task_id, auth) is not None

        exists = await _exists()
        if not exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task {task_id!r} not found or not accessible -- verify the task_id via GET /tasks",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Task {task_id!r} is already in a terminal state (done/failed/cancelled) -- only non-terminal tasks can be cancelled",
        )

    async def _audit_cancel() -> None:
        async with async_session_scope() as session:
            record_audit_event(
                session,
                run_id=task_id,
                stage=AUDIT_STAGE_TASK,
                action=AUDIT_ACTION_TASK_CANCEL,
                status=AUDIT_STATUS_COMPLETED,
                target=task_id,
                user_id=auth.user_id,
            )
            await session.commit()

    await _audit_cancel()

    return TaskActionResponse(task_id=task_id, status=TaskStatus.CANCELLED)


@limiter.limit("60/minute")
@router.post(
    "/{task_id}/resume",
    response_model=TaskActionResponse,
    summary="Resume a paused task (MOD-09)",
)
async def resume_task(
    request: Request,
    task_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> TaskActionResponse:
    """Transition a PAUSED task back to QUEUED (MOD-09/D-11).

    Returns 409 Conflict if the task is not in PAUSED state.
    Returns 404 if not found or not accessible.
    """

    async def _resume() -> bool:
        async with async_session_scope() as session:
            return await TaskRepository.set_queued_from_paused(session, task_id, auth)

    updated = await _resume()
    if not updated:
        async def _exists() -> bool:
            async with async_session_scope() as session:
                return await TaskRepository.get_for_user(session, task_id, auth) is not None

        exists = await _exists()
        if not exists:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task {task_id!r} not found or not accessible -- verify the task_id via GET /tasks",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Task {task_id!r} is not in PAUSED state -- only paused tasks can be resumed via POST /tasks/{{task_id}}/resume",
        )

    async def _audit_resume() -> None:
        async with async_session_scope() as session:
            record_audit_event(
                session,
                run_id=task_id,
                stage=AUDIT_STAGE_TASK,
                action=AUDIT_ACTION_TASK_RESUME,
                status=AUDIT_STATUS_COMPLETED,
                target=task_id,
                user_id=auth.user_id,
            )
            await session.commit()

    await _audit_resume()

    return TaskActionResponse(task_id=task_id, status=TaskStatus.QUEUED)


@limiter.limit("60/minute")
@router.get(
    "/{task_id}/transitions",
    response_model=DataEnvelope[list[TransitionView]],
    summary="List workflow state transitions for a task (Phase 181)",
)
async def list_task_transitions(
    request: Request,
    task_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[TransitionView]]:
    """Return all workflow state transition audit rows for a task.

    Verifies the caller has access to the task (same scoping as GET /tasks/{id}).
    Returns an empty list for non-workflow tasks — never a 404.
    Results are ordered by seq ascending (oldest first).
    """
    del request  # required by rate-limiter signature
    async with async_session_scope() as session:
        record = await TaskRepository.get_for_user(session, task_id, auth)
        if record is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Task {task_id!r} not found or not accessible -- verify the task_id via GET /tasks",
            )
        rows = (
            await session.exec(
                select(WorkflowStateTransition)
                .where(WorkflowStateTransition.run_id == task_id)
                .order_by(WorkflowStateTransition.seq)
                .limit(_TRANSITIONS_LIMIT)
            )
        ).all()

    _log.info(
        "transitions.read task_id=%s user_id=%s rows=%d",
        task_id, auth.user_id, len(rows),
    )
    return DataEnvelope(data=[TransitionView.from_model(r) for r in rows])


@router.get(
    "/{task_id}/events",
    summary="Stream task progress events via SSE (TASK-08/09)",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "SSE event stream with task progress updates",
            "content": {
                "text/event-stream": {
                    "schema": {
                        "type": "string",
                        "description": (
                            "Server-Sent Events stream. Each `data:` line contains JSON "
                            "with keys: stage (str), message (str), percent (int|null), "
                            "timestamp (str ISO-8601)."
                        ),
                    },
                },
            },
        },
    },
)
async def stream_task_events(
    task_id: str,
    last_id: str = Query(default="0", description="Redis Stream ID to start from (default '0' = all events)"),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> StreamingResponse:
    """Stream task progress events using Server-Sent Events.

    Verifies the caller has access to the task, then:
    1. Replays all events from last_id via catchup() (late-connect replay)
    2. Streams new events via stream_events() (blocking generator, 30s ping keepalive)

    If Redis is not configured, returns a single informational SSE message.

    Returns text/event-stream response for use with EventSource API.
    """
    # Verify task exists and is accessible before opening the stream
    async def _fetch_task() -> TaskRecord | None:
        async with async_session_scope() as session:
            return await TaskRepository.get_for_user(session, task_id, auth)

    record = await _fetch_task()
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task {task_id!r} not found or not accessible -- verify the task_id via GET /tasks",
        )

    if not pool_available():
        async def _no_redis_generator() -> AsyncGenerator[str, None]:
            msg = json.dumps({"message": "Redis not configured — no progress stream available"})
            yield f"data: {msg}\n\n"

        return StreamingResponse(
            _no_redis_generator(),
            media_type=MEDIA_TYPE_SSE,
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    _terminal_statuses = frozenset({TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.CANCELLED})

    async def _check_terminal(tid: str) -> str | None:
        """Return the task status if terminal, else None."""
        async with async_session_scope() as session:
            task = (await session.exec(select(TaskRecord).where(TaskRecord.id == tid))).first()
            if task and task.status in _terminal_statuses:
                return task.status
        return None

    async def _sse_generator() -> AsyncGenerator[str, None]:
        from aila.platform.tasks.progress import ProgressStream

        stream = ProgressStream()

        # Replay all events since last_id (late-connect catchup, D-17/TASK-09)
        try:
            catchup_events = await stream.catchup(task_id, last_id)
            for event in catchup_events:
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as exc:
            _log.warning("SSE catchup failed for task %s: %s", task_id, exc)

        # Check if task already terminal after catchup
        terminal = await _check_terminal(task_id)
        if terminal:
            yield f"event: done\ndata: {json.dumps({'status': terminal})}\n\n"
            return

        # Stream live events via ProgressStream.stream_events() async API
        async for event in stream.stream_events(task_id, last_id):
            yield f"data: {json.dumps(event)}\n\n"
            # After each ping, check for terminal state (OPS-02)
            if event.get("type") == "ping":
                terminal = await _check_terminal(task_id)
                if terminal:
                    yield f"event: done\ndata: {json.dumps({'status': terminal})}\n\n"
                    return

    return StreamingResponse(
        _sse_generator(),
        media_type=MEDIA_TYPE_SSE,
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


task_submit_router = APIRouter(
    prefix="",
    tags=["tasks"],
    dependencies=[Depends(require_user_or_api_key)],
)


@limiter.limit("10/hour")
@task_submit_router.post(
    "/task",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=TaskSubmitResponse,
    summary="Submit freeform task",
    description=(
        "Submit a freeform query to AILAPlatform.handle() via task queue (TASK-01, D-09). "
        "Returns 202 Accepted with run_id. Client polls GET /tasks/{run_id} for status. "
        "Per HANG-03: TaskQueue.submit() is sync; wrapped in asyncio.to_thread(). "
        "Returns 503 if platform is not initialized. Requires operator+ role."
    ),
)
async def submit_task(
    req: TaskCreateRequest,
    request: Request,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),
) -> TaskSubmitResponse:
    platform = getattr(request.app.state, "platform", None)
    if platform is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- check server logs for startup errors and restart the API server",
        )

    def _submit() -> str:
        handle = platform.task_queue.submit(
            track=TRACK_PLATFORM,
            fn=platform.handle,
            kwargs={"query": req.query_text},
            user_id=auth.user_id,
            group_id=auth.role,
        )
        return str(handle.task_id)

    task_id = await asyncio.to_thread(_submit)

    async def _audit_submit() -> None:
        async with async_session_scope() as session:
            record_audit_event(
                session,
                run_id=task_id,
                stage=AUDIT_STAGE_TASK,
                action=AUDIT_ACTION_TASK_SUBMIT,
                status=AUDIT_STATUS_COMPLETED,
                target=task_id,
                user_id=auth.user_id,
                details={"query": req.query_text[:200]},
            )
            await session.commit()

    await _audit_submit()

    return TaskSubmitResponse(run_id=task_id, status="submitted")
