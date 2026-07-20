"""SSE events router -- GET /events/stream.

Streams platform events to authenticated users via Server-Sent Events.

One persistent connection per user. Pings every 15 seconds.
Max connection lifetime: 5 minutes (client auto-reconnects via the frontend
``useSSE`` hook with exponential back-off).

Per D-04: endpoint is at ``/events/stream``.
Per D-17: rate-limited to 10 connection attempts per user per minute.
Per D-13: connection closes after MAX_CONNECTION_S and client reconnects.
Per D-19: ping keepalive sent every PING_INTERVAL_S.
"""
from __future__ import annotations

__all__ = ["router"]

import asyncio
import json
import logging
from collections.abc import AsyncGenerator

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.events import get_user_queue, release_user_queue
from aila.api.limiter import limiter
from aila.api.metrics import ACTIVE_SSE

router = APIRouter(prefix="/events", tags=["events"], dependencies=[Depends(require_user_or_api_key)])
_log = logging.getLogger(__name__)

MEDIA_TYPE_SSE = "text/event-stream"
PING_INTERVAL_S: int = 15
MAX_CONNECTION_S: int = 300  # 5 minutes


@router.get(
    "/stream",
    response_class=StreamingResponse,
    summary="SSE event stream for authenticated user (RT-01)",
    responses={
        200: {
            "description": "SSE event stream with platform events",
            "content": {
                "text/event-stream": {
                    "schema": {
                        "type": "string",
                        "description": (
                            "Server-Sent Events stream. Each frame has an "
                            "``event:`` line (the event type) and a ``data:`` "
                            "line (JSON payload with keys: type, data, user_id, "
                            "timestamp). Comment lines ``: ping`` are keepalives."
                        ),
                    },
                },
            },
        },
    },
)
@limiter.limit("10/minute")
async def stream_events(
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> StreamingResponse:
    """Stream platform events for the authenticated user via SSE.

    Opens one queue-backed SSE stream per user. Events are emitted by
    ``emit_platform_event()`` from any part of the platform (scan worker,
    findings upsert, SbD task completion, etc.).

    Connection lifecycle:
    - Pings every PING_INTERVAL_S seconds to prevent proxy timeout.
    - Closes after MAX_CONNECTION_S (5 min) -- client reconnects automatically.
    - On client disconnect, cleans up the in-process queue.

    Event frame format::

        event: scan_complete
        data: {"type": "scan_complete", "data": {...}, "user_id": "...", "timestamp": "..."}

    Keepalive frame format::

        : ping

    Per D-04, D-13, D-17, D-19.
    """

    async def _generator() -> AsyncGenerator[str, None]:
        # 60-6: ACTIVE_SSE gauge tracks live SSE connections. The outer
        # try/finally guarantees .dec() runs on every exit path (normal
        # completion, client disconnect, or an exception raised by
        # get_user_queue before the inner try is entered).
        ACTIVE_SSE.inc()
        elapsed = 0.0
        try:
            queue = await get_user_queue(auth.user_id)
            next_ping = float(PING_INTERVAL_S)

            try:
                while elapsed < MAX_CONNECTION_S:
                    # Check if client disconnected
                    if await request.is_disconnected():
                        break

                    # Drain all available events without blocking
                    while True:
                        try:
                            raw_payload = queue.get_nowait()
                        except asyncio.QueueEmpty:
                            break
                        try:
                            parsed = json.loads(raw_payload)
                            event_type = parsed.get("type", "message")
                            yield f"event: {event_type}\ndata: {raw_payload}\n\n"
                        except (json.JSONDecodeError, TypeError) as exc:
                            _log.warning("Malformed event payload dropped: %s", exc)

                    # Wait 1 second before checking again
                    await asyncio.sleep(1.0)
                    elapsed += 1.0

                    # Send ping keepalive
                    if elapsed >= next_ping:
                        yield ": ping\n\n"
                        next_ping += PING_INTERVAL_S

            except asyncio.CancelledError:
                # Client disconnected mid-stream -- clean exit
                pass
            finally:
                await release_user_queue(auth.user_id)
                _log.debug("SSE stream closed for user %s (elapsed=%.0fs)", auth.user_id, elapsed)
        finally:
            ACTIVE_SSE.dec()

    return StreamingResponse(
        _generator(),
        media_type=MEDIA_TYPE_SSE,
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
