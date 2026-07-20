"""Conversation session router for AILA REST API.

Endpoints:
  POST /sessions -- create a conversation session (TASK-02)
  POST /sessions/{session_id}/messages -- add message + get response (TASK-03, TASK-04, TASK-06)
  GET /sessions/{session_id}/messages -- return full message history (TASK-05)

All session endpoints require reader+ role (D-23: even readers can chat).
Sessions are scoped by user_id from the JWT (D-25).
Phase 56 adds SSE streaming via content negotiation on Accept: text/event-stream.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import (
    AUDIT_ACTION_SESSION_CREATE,
    AUDIT_ACTION_SESSION_MESSAGE,
    AUDIT_STAGE_SESSION,
    AUDIT_STATUS_COMPLETED,
    MEDIA_TYPE_SSE,
)
from aila.api.limiter import limiter
from aila.api.schemas.sessions import (
    SessionCreateRequest,
    SessionListResponse,
    SessionMessageRequest,
    SessionMessageResponse,
    SessionMessagesResponse,
    SessionResponse,
    SessionSummary,
)
from aila.platform.services.audit import record_audit_event
from aila.storage.database import async_session_scope
from aila.storage.db_models import SessionMessageRecord, SessionRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/sessions",
    tags=["sessions"],
    dependencies=[Depends(require_user_or_api_key)],
)


def _session_to_response(record: SessionRecord) -> SessionResponse:
    return SessionResponse(
        session_id=record.id,
        user_id=record.user_id,
        title=record.title,
        created_at=record.created_at,
    )


def _message_to_response(record: SessionMessageRecord) -> SessionMessageResponse:
    return SessionMessageResponse(
        message_id=record.id,
        role=record.role,
        content=record.content,
        run_id=record.run_id,
        created_at=record.created_at,
    )


@router.get(
    "",
    response_model=SessionListResponse,
    summary="List caller's conversation sessions",
)
async def list_sessions(
    auth: AuthContext = Depends(require_user_or_api_key),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
) -> SessionListResponse:
    """Return the caller's sessions, newest first, with last-message previews.

    Scoped by user_id (D-25). Readers can list their own sessions (D-23).
    """
    from sqlmodel import func, select

    async def _query() -> tuple[int, list[SessionSummary]]:
        async with async_session_scope() as db:
            # Fetch all sessions for this user, newest first.
            sess_stmt = (
                select(SessionRecord)
                .where(SessionRecord.user_id == auth.user_id)
                .order_by(SessionRecord.created_at.desc())  # type: ignore[attr-defined]
            )
            sess_rows = list((await db.exec(sess_stmt)).all())
            total = len(sess_rows)

            offset = (page - 1) * page_size
            page_rows = sess_rows[offset : offset + page_size]

            # Pull last message + count for each session in the page. Use a
            # single grouped query over the page session_ids to avoid N+1.
            session_ids = [s.id for s in page_rows]
            last_at: dict[str, object] = {}
            count_by: dict[str, int] = {}
            preview_by: dict[str, str] = {}
            if session_ids:
                # Aggregate count + max(created_at)
                agg_stmt = (
                    select(
                        SessionMessageRecord.session_id,
                        func.count(SessionMessageRecord.id),  # type: ignore[arg-type]
                        func.max(SessionMessageRecord.created_at),  # type: ignore[arg-type]
                    )
                    .where(SessionMessageRecord.session_id.in_(session_ids))  # type: ignore[attr-defined]
                    .group_by(SessionMessageRecord.session_id)  # type: ignore[arg-type]
                )
                for sid, cnt, mx in (await db.exec(agg_stmt)).all():
                    count_by[sid] = int(cnt)
                    last_at[sid] = mx

                # Latest message per session for preview -- fetch all messages
                # belonging to these sessions and keep the newest content per session.
                msg_stmt = (
                    select(SessionMessageRecord)
                    .where(SessionMessageRecord.session_id.in_(session_ids))  # type: ignore[attr-defined]
                    .order_by(SessionMessageRecord.created_at.desc())  # type: ignore[attr-defined]
                )
                for row in (await db.exec(msg_stmt)).all():
                    if row.session_id not in preview_by:
                        snippet = (row.content or "").strip().replace("\n", " ")
                        if len(snippet) > 140:
                            snippet = snippet[:137] + "…"
                        preview_by[row.session_id] = snippet

            summaries = [
                SessionSummary(
                    session_id=s.id,
                    user_id=s.user_id,
                    title=s.title,
                    created_at=s.created_at,
                    last_message_at=last_at.get(s.id),  # type: ignore[arg-type]
                    last_message_preview=preview_by.get(s.id),
                    message_count=count_by.get(s.id, 0),
                )
                for s in page_rows
            ]
            return total, summaries

    total, items = await _query()
    return SessionListResponse(total=total, items=items)


@limiter.limit("30/minute")
@router.post("", response_model=SessionResponse, status_code=status.HTTP_201_CREATED,
             summary="Create conversation session")
async def create_session(
    request: Request,
    req: SessionCreateRequest,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> SessionResponse:
    """Create a new conversation session for the authenticated user (TASK-02).

    Sessions are scoped by user_id (D-25). Readers can chat (D-23).
    """
    async def _create() -> SessionRecord:
        async with async_session_scope() as db:
            record = SessionRecord(
                user_id=auth.user_id,
                title=req.title or "Untitled",
            )
            db.add(record)
            await db.commit()
            await db.refresh(record)
            record_audit_event(
                db,
                run_id=record.id,
                stage=AUDIT_STAGE_SESSION,
                action=AUDIT_ACTION_SESSION_CREATE,
                status=AUDIT_STATUS_COMPLETED,
                target=record.id,
                user_id=auth.user_id,
                details={"title": record.title},
            )
            await db.commit()
            await db.refresh(record)
            return record

    record = await _create()
    return _session_to_response(record)


@limiter.limit("60/minute")
@router.post(
    "/{session_id}/messages",
    response_model=SessionMessageResponse,
    summary="Send message and get response (streaming if Accept: text/event-stream)",
    responses={
        200: {
            "description": "Assistant response (JSON or SSE depending on Accept header)",
            "content": {
                "application/json": {
                    "schema": {"$ref": "#/components/schemas/SessionMessageResponse"},
                },
                "text/event-stream": {
                    "schema": {
                        "type": "string",
                        "description": (
                            "SSE token stream. Each `data:` line is a JSON object with "
                            "keys: token (str), done (bool). Final event has done=true "
                            "and includes message_id, role, content, run_id, created_at."
                        ),
                    },
                },
            },
        },
    },
)
async def post_message(
    session_id: str,
    req: SessionMessageRequest,
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> SessionMessageResponse | StreamingResponse:
    """Add a user message to a session and return the assistant response (TASK-03/TASK-04).

    If the client sends Accept: text/event-stream, streams response tokens via SSE
    using a per-connection asyncio.Queue bridge (D-06/D-12/D-13). Complete message
    written to DB only after streaming completes (D-07). asyncio.CancelledError caught
    on client disconnect to discard queue and cancel background task (D-09).

    If Accept header is not text/event-stream, returns JSON SessionMessageResponse
    (unchanged behaviour from Phase 55).

    Returns 404 if session not found or belongs to another user (D-25).
    Returns 503 if platform not initialized.
    """
    accept = request.headers.get("accept", "")
    if MEDIA_TYPE_SSE in accept:
        return await _stream_message(session_id, req, request, auth)
    return await _sync_message(session_id, req, request, auth)


async def _sync_message(
    session_id: str,
    req: SessionMessageRequest,
    request: Request,
    auth: AuthContext,
) -> SessionMessageResponse:
    """Handle non-streaming POST /sessions/{id}/messages (TASK-03, Phase 55 behaviour)."""
    platform = request.app.state.platform

    if platform is None:
        # Verify session exists + belongs to user before returning 503
        async def _check_session() -> bool:
            async with async_session_scope() as db:
                rec = await db.get(SessionRecord, session_id)
                return rec is not None and rec.user_id == auth.user_id

        exists = await _check_session()
        if not exists:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session '{session_id}' not found or belongs to another user -- verify the session_id via POST /sessions")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- check server logs for startup errors and restart the API server",
        )

    async def _handle() -> SessionMessageRecord:
        async with async_session_scope() as db:
            sess_record = await db.get(SessionRecord, session_id)
            if sess_record is None or sess_record.user_id != auth.user_id:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Session '{session_id}' not found or belongs to another user -- verify the session_id via POST /sessions",
                )

            user_msg = SessionMessageRecord(
                session_id=session_id,
                role="user",
                content=req.content,
                run_id=None,
            )
            db.add(user_msg)
            await db.commit()

            try:
                platform_response = platform.handle(query=req.content)
                response_text = str(getattr(platform_response, "summary", "") or req.content)
                response_run_id = getattr(platform_response, "run_id", None)
            except Exception:
                _log.exception("Platform handle() failed for session %s", session_id)
                response_text = "I encountered an error processing your request."
                response_run_id = None

            asst_msg = SessionMessageRecord(
                session_id=session_id,
                role="assistant",
                content=response_text,
                run_id=response_run_id,  # TASK-06: inline scan run_id if triggered
            )
            db.add(asst_msg)
            await db.commit()
            await db.refresh(asst_msg)
            record_audit_event(
                db,
                run_id=session_id,
                stage=AUDIT_STAGE_SESSION,
                action=AUDIT_ACTION_SESSION_MESSAGE,
                status=AUDIT_STATUS_COMPLETED,
                target=session_id,
                user_id=auth.user_id,
                details={"message_id": asst_msg.id},
            )
            await db.commit()
            await db.refresh(asst_msg)
            return asst_msg

    asst_msg = await _handle()
    return _message_to_response(asst_msg)


async def _stream_message(
    session_id: str,
    req: SessionMessageRequest,
    request: Request,
    auth: AuthContext,
) -> StreamingResponse:
    """Stream assistant response tokens via SSE (TASK-04, D-06 through D-14)."""
    platform = request.app.state.platform

    async def _check_session() -> bool:
        async with async_session_scope() as db:
            rec = await db.get(SessionRecord, session_id)
            return rec is not None and rec.user_id == auth.user_id

    exists = await _check_session()
    if not exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Session '{session_id}' not found or belongs to another user -- verify the session_id via POST /sessions")

    if platform is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- check server logs for startup errors and restart the API server",
        )

    async def _add_user_msg() -> None:
        async with async_session_scope() as db:
            user_msg = SessionMessageRecord(
                session_id=session_id,
                role="user",
                content=req.content,
                run_id=None,
            )
            db.add(user_msg)
            # #52-3.2: stage the audit row inside the SAME transaction as
            # the message insert. Previously the message committed first
            # and the audit row was written in a second transaction, so a
            # crash between the two lost the audit trail for the streaming
            # user turn.
            record_audit_event(
                db,
                run_id=session_id,
                stage=AUDIT_STAGE_SESSION,
                action=AUDIT_ACTION_SESSION_MESSAGE,
                status=AUDIT_STATUS_COMPLETED,
                target=session_id,
                user_id=auth.user_id,
                details={"streaming": True},
            )
            await db.commit()

    await _add_user_msg()

    async def _stream_generator() -> AsyncGenerator[str, None]:
        loop = asyncio.get_running_loop()
        token_queue: asyncio.Queue[str | None] = asyncio.Queue()
        response_text: list[str] = []
        response_run_id: list[str | None] = [None]

        def _sync_worker() -> None:
            try:
                def _token_cb(token: str) -> None:
                    response_text.append(token)
                    loop.call_soon_threadsafe(token_queue.put_nowait, token)

                # platform.handle() is sync (D-03); call in this thread
                # If platform.handle() does not support token_callback, tokens are not
                # streamed individually -- the full response is buffered and emitted as
                # a single token after completion (graceful fallback).
                try:
                    result = platform.handle(query=req.content, token_callback=_token_cb)
                except TypeError:
                    # platform.handle() does not accept token_callback -- fallback: buffer
                    result = platform.handle(query=req.content)
                    summary = str(getattr(result, "summary", "") or req.content)
                    response_text.clear()
                    response_text.append(summary)
                    loop.call_soon_threadsafe(token_queue.put_nowait, summary)

                response_run_id[0] = getattr(result, "run_id", None)
            except Exception as exc:
                _log.exception("Platform error during SSE streaming: %s", exc)
                err_text = f"Error: {exc}"
                response_text.append(err_text)
                loop.call_soon_threadsafe(token_queue.put_nowait, err_text)
            finally:
                # Sentinel: signals end of stream (D-14)
                loop.call_soon_threadsafe(token_queue.put_nowait, None)

        task = asyncio.create_task(asyncio.to_thread(_sync_worker))

        cancelled = False
        try:
            while True:
                token = await token_queue.get()
                if token is None:  # D-14: sentinel → close stream
                    break
                yield f"data: {json.dumps({'token': token, 'type': 'token'})}\n\n"
        except asyncio.CancelledError:
            # D-09: client disconnected -- cancel background task, discard queue
            task.cancel()
            cancelled = True
            raise
        finally:
            try:
                await task
            except asyncio.CancelledError:
                pass  # Expected: task was cancelled by client disconnect
            except Exception:
                _log.debug("SSE background task raised during cleanup", exc_info=True)

            # D-07: persist complete assistant message after stream finishes
            full_text = "".join(response_text)
            run_id_val = response_run_id[0]

            async def _persist_response() -> None:
                async with async_session_scope() as db:
                    asst_msg = SessionMessageRecord(
                        session_id=session_id,
                        role="assistant",
                        content=full_text,
                        run_id=run_id_val,
                    )
                    db.add(asst_msg)
                    await db.commit()

            await _persist_response()

        # Done sentinel emitted OUTSIDE finally -- only on normal completion
        if not cancelled:
            yield f"data: {json.dumps({'type': 'done', 'run_id': run_id_val})}\n\n"

    return StreamingResponse(
        _stream_generator(),
        media_type=MEDIA_TYPE_SSE,
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/{session_id}/messages", response_model=SessionMessagesResponse,
            summary="Get session message history")
async def get_messages(
    session_id: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> SessionMessagesResponse:
    """Return full message history for a session, ordered by created_at asc (TASK-05).

    Returns 404 if session not found or belongs to another user (D-25).
    """
    from sqlmodel import select

    async def _query() -> tuple[bool, list[SessionMessageRecord]]:
        async with async_session_scope() as db:
            sess_record = await db.get(SessionRecord, session_id)
            if sess_record is None or sess_record.user_id != auth.user_id:
                return False, []
            stmt = (
                select(SessionMessageRecord)
                .where(SessionMessageRecord.session_id == session_id)
                .order_by(SessionMessageRecord.created_at)  # type: ignore[arg-type]  # SQLModel column expression
            )
            return True, list((await db.exec(stmt)).all())

    found, rows = await _query()
    if not found:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Session '{session_id}' not found or belongs to another user -- verify the session_id via POST /sessions",
        )

    total = len(rows)
    offset = (page - 1) * page_size
    page_rows = rows[offset : offset + page_size]
    return SessionMessagesResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
        items=[_message_to_response(r) for r in page_rows],
    )
