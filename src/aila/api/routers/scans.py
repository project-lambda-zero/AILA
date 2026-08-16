"""Scan submission and status polling router for AILA REST API.

Endpoints:
  POST /analyze -- submit vulnerability scan via task queue (API-01, ASYNC-01)
  GET /scans/{run_id} -- poll scan status for authenticated user (API-02, ASYNC-02, ASYNC-06)
  GET /scans/{run_id}/events -- SSE stream of scan progress (ASYNC-03, ASYNC-04)

Per D-03: handle() NEVER runs in Starlette threadpool -- always via ARQ background job.
Per HANG-03: TaskQueue.submit() is sync; always wrap in asyncio.to_thread().
"""
from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlmodel import select

from aila.api.auth import AuthContext, require_role, require_user_or_api_key
from aila.api.constants import (
    AUDIT_ACTION_SCAN_SUBMIT,
    AUDIT_STAGE_SCAN,
    AUDIT_STATUS_COMPLETED,
    MEDIA_TYPE_SSE,
    MODULE_ID_PLATFORM,
    ROLE_OPERATOR,
)
from aila.api.limiter import limiter
from aila.api.metrics import ACTIVE_SSE
from aila.api.schemas.scans import ScanCancelResponse
from aila.api.schemas.tasks import ScanStatusResponse, ScanSubmissionRequest, TaskSubmitResponse
from aila.platform.services.audit import record_audit_event
from aila.platform.services.redis_pool import pool_available
from aila.platform.tasks.entrypoints import run_platform_handle
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.progress import ProgressStream
from aila.platform.tasks.queue import _env_redis_url
from aila.platform.tasks.storage import TaskRepository
from aila.storage.database import async_session_scope

_log = logging.getLogger(__name__)

__all__ = ["router", "run_platform_handle"]


# Platform-owned queued scan entrypoint. The API submits this callable to the
# task queue without importing module internals directly.


router = APIRouter(
    prefix="",
    tags=["scans"],
    dependencies=[Depends(require_user_or_api_key)],
)


@limiter.limit("10/hour")
@router.post("/analyze", status_code=status.HTTP_202_ACCEPTED, summary="Submit vulnerability scan")
async def submit_scan(
    req: ScanSubmissionRequest,
    request: Request,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),
) -> TaskSubmitResponse:
    """Enqueue an async vulnerability scan via TaskQueue. Returns 202 immediately."""
    platform = request.app.state.platform
    if platform is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- check server logs for startup errors and restart the API server",
        )

    async def _submit() -> str:
        from aila.platform.tasks.queue import TaskQueue

        task_queue = TaskQueue(
            config_registry=getattr(getattr(platform, "runtime", None), "config_registry", None),
            module_id=MODULE_ID_PLATFORM,
        )
        # scan_submission_track() has a None-returning protocol default, so every
        # module inherits a callable of that name. first_with() matches on method
        # existence and would return the first-registered module (whose default is
        # None) rather than the module that actually publishes a track. Resolve
        # the first module that answers with a non-None track instead.
        track: str | None = None
        for scan_module in platform.runtime.module_registry.all_with("scan_submission_track"):
            candidate = scan_module.scan_submission_track()
            if candidate is not None:
                track = candidate
                break
        if track is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No registered module accepts scan submissions.",
            )
        handle = await task_queue.submit(
            track=track,
            fn=run_platform_handle,
            kwargs={
                "query": req.query_text,
                "module_payload": {"target_names": req.targets},
            },
            user_id=auth.user_id,
            group_id=auth.role,
            team_id=auth.team_id,
        )
        return handle.task_id

    task_id = await _submit()

    async def _audit() -> None:
        async with async_session_scope() as session:
            record_audit_event(
                session,
                run_id=task_id,
                stage=AUDIT_STAGE_SCAN,
                action=AUDIT_ACTION_SCAN_SUBMIT,
                status=AUDIT_STATUS_COMPLETED,
                target=task_id,
                user_id=auth.user_id,
                team_id=auth.team_id,
                details={"query": req.query_text[:200]},
            )
            await session.commit()

    await _audit()

    return TaskSubmitResponse(run_id=task_id, status="submitted")


@router.get("/scans/{run_id}", response_model=ScanStatusResponse, summary="Poll scan status")
async def get_scan_status(
    run_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> ScanStatusResponse:
    """Return current status of a submitted scan (API-02, ASYNC-02).

    Per D-21/D-22: only the submitting user's group can see their scans.
    Admin sees all tasks; other roles are restricted to their own group_id.
    Returns 404 if run_id not found or belongs to a different group.
    """
    async def _fetch() -> ScanStatusResponse | None:
        async with async_session_scope() as session:
            record = await TaskRepository.get_for_user(
                session=session,
                task_id=run_id,
                auth=auth,
            )
            if record is None:
                return None
            return ScanStatusResponse(
                run_id=record.id,
                status=record.status,
                track=record.track,
                started_at=record.started_at.isoformat() if record.started_at else None,
                completed_at=record.completed_at.isoformat() if record.completed_at else None,
            )

    result = await _fetch()
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{run_id}' not found or not accessible -- verify the run_id via GET /tasks",
        )
    return result


_TERMINAL_TASK_STATUSES: frozenset[str] = frozenset({
    TaskStatus.DONE,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
    TaskStatus.DEAD_LETTER,
})


@limiter.limit("60/minute")
@router.post(
    "/scans/{run_id}/cancel",
    response_model=ScanCancelResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Cancel a submitted scan",
)
async def cancel_scan(
    run_id: str,
    request: Request,
    auth: AuthContext = Depends(require_role(ROLE_OPERATOR)),
) -> ScanCancelResponse:
    """Abort a running or queued scan.

    Contract:
    * Ownership is checked via the same team/group scoping as
      ``GET /scans/{run_id}`` -- a caller who cannot see the scan gets
      ``404`` instead of leaking its existence.
    * Already-terminal rows (``done``/``failed``/``cancelled``/``dead_letter``)
      return their current status with ``202``. This is intentional: the
      operator asked to stop the run, and it is already stopped, so the
      request succeeded and the response tells them the truth. A second
      cancel is never a 500.
    * For non-terminal rows we first ask ARQ to abort the running job
      (``arq.jobs.Job.abort``, wired up by ``allow_abort_jobs=True`` on
      the worker), then flip the DB row to ``CANCELLED`` inside a single
      transaction, then drop the ``arq:in-progress:<id>`` key via the
      shared ``finalize_cancel_side_effects`` helper. Ordering matches
      the pattern documented on
      :meth:`aila.platform.tasks.storage.TaskRepository.set_cancelled`:
      the ARQ side-effect never fires ahead of a commit that then rolls
      back, and a failed abort does not leave the row un-flipped.
    """
    async def _fetch() -> TaskRecord | None:
        async with async_session_scope() as session:
            return await TaskRepository.get_for_user(session, run_id, auth)

    record = await _fetch()
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{run_id}' not found or not accessible -- verify the run_id via GET /tasks",
        )

    if record.status in _TERMINAL_TASK_STATUSES:
        return ScanCancelResponse(run_id=run_id, status=record.status)

    # Best-effort ARQ abort. A running job receives the abort signal
    # (worker was started with ``allow_abort_jobs=True``); a merely
    # queued job is removed from the run queue. Failure here does not
    # block the DB-side flip: the reaper reconciles orphan locks on its
    # next sweep, and the row transition is what the operator's UI keys
    # off. Heterogeneous transport errors surface here (RedisError,
    # OSError, ValueError from DSN parsing, TimeoutError), all of which
    # we treat uniformly as "abort was best-effort".
    redis_url = _env_redis_url()
    if redis_url:
        from arq.connections import RedisSettings, create_pool
        from arq.jobs import Job

        from aila.platform.tasks.constants import ARQ_QUEUE_KEY_TEMPLATE

        pool = None
        try:
            pool = await create_pool(RedisSettings.from_dsn(redis_url))
            queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track=record.track)
            job = Job(run_id, pool, _queue_name=queue_key)
            await job.abort(timeout=1.0)
        except Exception as exc:
            _log.warning(
                "cancel_scan: ARQ abort failed for run_id=%s track=%s: %s -- "
                "proceeding with DB cancel; reaper will reconcile orphan lock",
                run_id, record.track, exc,
            )
        finally:
            if pool is not None:
                await pool.aclose()
    else:
        _log.debug(
            "cancel_scan: AILA_PLATFORM_REDIS_URL unset -- skipping ARQ abort for %s",
            run_id,
        )

    async def _flip() -> str:
        async with async_session_scope() as session:
            # Re-read inside this session so ``set_cancelled`` can stage
            # its status flip. The prior ``get_for_user`` above only
            # served the terminal-state short-circuit.
            fresh = await TaskRepository.get_for_user(session, run_id, auth)
            if fresh is None:
                # Row vanished between the two reads (deletion by another
                # admin, TTL sweep). Treat as terminal from the caller's
                # perspective -- there is nothing left to cancel.
                return TaskStatus.CANCELLED
            if fresh.status in _TERMINAL_TASK_STATUSES:
                return fresh.status
            staged = await TaskRepository.set_cancelled(session, run_id, auth)
            if not staged:
                # ``set_cancelled`` only refuses when the row is missing
                # or already terminal; both branches were handled above,
                # so a False here is a genuine race. Return the freshly
                # observed status.
                await session.rollback()
                current = await TaskRepository.get_for_user(session, run_id, auth)
                return current.status if current is not None else TaskStatus.CANCELLED
            await session.commit()
            return TaskStatus.CANCELLED

    final_status = await _flip()
    if final_status == TaskStatus.CANCELLED:
        await TaskRepository.finalize_cancel_side_effects(run_id)
    return ScanCancelResponse(run_id=run_id, status=final_status)


@router.get(
    "/scans/{run_id}/events",
    summary="Stream scan progress events via SSE (ASYNC-03/04)",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "SSE event stream with scan progress updates",
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
async def stream_scan_events(
    run_id: str,
    request: Request,
    last_id: str = Query(default="0", description="Redis Stream ID to start from (default '0' = all events)"),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> StreamingResponse:
    """Stream scan progress events using Server-Sent Events (ASYNC-03/ASYNC-04).

    Verifies caller access, replays past events via XRANGE catchup (TASK-09),
    then streams new events via blocking XREAD with 30s ping keepalive.

    Each data line is JSON with keys: stage, message, percent, timestamp.
    Returns a single informational event if Redis is not configured.
    """
    from aila.api.sse_gate import enforce_sse_cap

    # #60 global SSE ceiling: refuse new streams when ACTIVE_SSE is at
    # or above the configured cap. Runs before the DB fetch so a runaway
    # reconnect burst does not pay any DB cost either.
    enforce_sse_cap()

    async def _fetch_scan() -> object:
        async with async_session_scope() as session:
            return await TaskRepository.get_for_user(session, run_id, auth)

    record = await _fetch_scan()
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan {run_id!r} not found or not accessible -- verify the run_id and your permissions via GET /tasks",
        )

    if not pool_available():
        async def _no_redis_generator() -> AsyncGenerator[str, None]:
            msg = json.dumps({"message": "Redis not configured -- no progress stream available"})
            yield f"data: {msg}\n\n"

        return StreamingResponse(
            _no_redis_generator(),
            media_type=MEDIA_TYPE_SSE,
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    _terminal_statuses = frozenset({
        TaskStatus.DONE, TaskStatus.FAILED, TaskStatus.CANCELLED, TaskStatus.DEAD_LETTER,
    })

    async def _fetch_task_state(tid: str) -> tuple[str | None, datetime | None]:
        """Return (status, heartbeat_at) from DB. status is None if record missing."""
        async with async_session_scope() as session:
            task = (await session.exec(select(TaskRecord).where(TaskRecord.id == tid))).first()
            if task is None:
                return None, None
            return task.status, task.heartbeat_at

    async def _sse_generator() -> AsyncGenerator[str, None]:
        from datetime import datetime as _dt

        # 60-6: ACTIVE_SSE gauge tracks live SSE connections. The try/finally
        # guarantees .dec() runs on every exit path including client
        # disconnect (StreamingResponse cancels the async generator, which
        # runs finally cleanup) and exceptions raised mid-stream.
        ACTIVE_SSE.inc()
        try:
            stream = ProgressStream()

            # Send initial connected event immediately so frontend knows SSE is up
            yield f"data: {json.dumps({'stage': 'stream', 'message': 'Connected', 'percent': 0})}\n\n"

            # Track the newest stream id we replayed so the live stream does not
            # re-emit those same events (previous behaviour duplicated every event).
            resume_from = last_id
            latest_stage = "submitted"
            try:
                catchup_events = await stream.catchup(run_id, last_id)
                for event in catchup_events:
                    yield f"data: {json.dumps(event)}\n\n"
                    stage = event.get("stage")
                    if stage:
                        latest_stage = stage
                # ProgressStream.catchup returns events without their stream ids
                # today, so use "$" to mean "only new events from here" -- avoids
                # the duplicate replay reported by operators.
                resume_from = "$"
            except Exception as exc:
                _log.warning("Scan SSE catchup failed for %s: %s", run_id, exc)

            # Check if task already terminal after catchup
            status, _ = await _fetch_task_state(run_id)
            if status in _terminal_statuses:
                yield f"event: done\ndata: {json.dumps({'status': status})}\n\n"
                return

            # Wrap the live stream so a mid-stream backend error (e.g. a Redis blip)
            # closes the SSE connection with a done sentinel instead of crashing the
            # response, mirroring the catchup block above.
            try:
                async for event in stream.stream_events(run_id, resume_from):
                    # 60-4: end the generator promptly when the client hangs
                    # up so the server does not hold a Redis connection +
                    # coroutine per zombie client until the next XREAD tick
                    # (up to 30 s).
                    if await request.is_disconnected():
                        return
                    if event.get("type") == "ping":
                        # Failsafe: on every ping, synthesise a heartbeat event with
                        # the DB-recorded status + age so the frontend never thinks a
                        # long-running stage has silently died. Stages such as advisory
                        # and intel enrichment can run for minutes without emitting
                        # progress; this keeps the UI honest.
                        status, hb = await _fetch_task_state(run_id)
                        if status in _terminal_statuses:
                            yield f"event: done\ndata: {json.dumps({'status': status})}\n\n"
                            return
                        hb_age_s: float | None = None
                        if hb is not None:
                            now = _dt.now(tz=UTC)
                            hb_for_calc = hb if hb.tzinfo is not None else hb.replace(tzinfo=UTC)
                            hb_age_s = max(0.0, (now - hb_for_calc).total_seconds())
                        hb_payload = {
                            "stage": "heartbeat",
                            "message": f"Scan still running (stage={latest_stage}, last worker beat {int(hb_age_s)}s ago)"
                            if hb_age_s is not None
                            else f"Scan still running (stage={latest_stage})",
                            "percent": None,
                            "task_status": status,
                            "heartbeat_age_s": round(hb_age_s, 1) if hb_age_s is not None else None,
                        }
                        yield f"data: {json.dumps(hb_payload)}\n\n"
                        continue

                    yield f"data: {json.dumps(event)}\n\n"
                    stage = event.get("stage")
                    if stage:
                        latest_stage = stage
            except Exception as exc:
                # End the generator quietly so the StreamingResponse completes with
                # 200 instead of surfacing a 500 mid-stream. No done sentinel is
                # emitted -- the client's EventSource then auto-reconnects, which is
                # the right behaviour for a transient backend error.
                _log.warning("Scan SSE live stream failed for %s: %s", run_id, exc)
        finally:
            ACTIVE_SSE.dec()

    return StreamingResponse(
        _sse_generator(),
        media_type=MEDIA_TYPE_SSE,
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
