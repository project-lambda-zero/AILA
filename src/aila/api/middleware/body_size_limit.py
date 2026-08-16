"""Streaming request-body size guard (issue #115).

The previous guard only inspected the ``Content-Length`` header, so a
chunked-transfer request (which never sends one) or a lying header bypassed
the limit and let a caller push an unbounded body into worker memory before
FastAPI ever parsed it.

This ASGI middleware counts the actual bytes drained from the ASGI
``receive`` channel and rejects with ``413 Payload Too Large`` the moment
the running total crosses the configured maximum -- whether or not
``Content-Length`` was accurate. The ``Content-Length`` header, when
present and numeric, is still fast-rejected before the app is invoked so a
truthful oversized upload never hits the read loop.

The 413 body uses the standard :class:`~aila.api.errors.envelope.ErrorEnvelope`
shape (``{code, message, hint, trace_id}``) with code ``PAYLOAD_TOO_LARGE``.
"""
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from aila.api.errors.hints import ERROR_HINTS

__all__ = ["BodySizeLimitMiddleware"]


ASGIMessage = dict[str, Any]
ASGIScope = dict[str, Any]
ASGIReceive = Callable[[], Awaitable[ASGIMessage]]
ASGISend = Callable[[ASGIMessage], Awaitable[None]]


def _current_trace_id() -> str | None:
    """Return the request's correlation_id if the structlog contextvar is bound.

    Mirrors :func:`aila.api.errors.handlers._current_trace_id`. Kept local
    (rather than imported) so the guard has no import-time coupling to the
    error-handler module. Degrades to ``None`` when the contextvar isn't set
    (this middleware can run outside :class:`CorrelationIdMiddleware`).
    """
    ctx = structlog.contextvars.get_contextvars() or {}
    value = ctx.get("correlation_id")
    if value is None:
        return None
    return str(value)


class BodySizeLimitMiddleware:
    """Pure-ASGI middleware that caps request body size at ``max_bytes``.

    Enforcement is done in two layers:

    1. **Fast reject on ``Content-Length``.** If the header is present,
       numeric, and larger than ``max_bytes`` the middleware returns 413
       without ever invoking the downstream app. Non-numeric or missing
       headers are ignored here (they may still be caught by the ASGI
       server or by the streaming counter below).
    2. **Streaming byte counter.** The middleware wraps the ASGI
       ``receive`` channel so every ``http.request`` body chunk drained by
       the app increments a running total. When the total crosses
       ``max_bytes`` the wrapped ``receive`` yields ``http.disconnect``
       and the middleware sends a 413 in place of whatever response the
       app was about to emit. This closes the chunked-transfer bypass
       flagged by issue #115 -- a client that omits ``Content-Length`` and
       streams past the cap is stopped after ``max_bytes + one chunk``.

    Non-HTTP scopes (``lifespan``, ``websocket``) pass through untouched.
    """

    def __init__(self, app: Any, *, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = int(max_bytes)
        # Pre-compute the operator-facing MB label for the message. Rounded
        # up so a cap of 200 MB advertises "200 MB", not "199 MB".
        self._max_mb = (self.max_bytes + (1024 * 1024) - 1) // (1024 * 1024)

    async def __call__(
        self, scope: ASGIScope, receive: ASGIReceive, send: ASGISend
    ) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return

        # ── Layer 1: Content-Length fast reject ─────────────────────────
        for name, value in scope.get("headers", ()):  # ASGI: list[(bytes,bytes)]
            if name == b"content-length":
                try:
                    declared = int(value.decode("latin-1"))
                except (ValueError, UnicodeDecodeError):
                    declared = None  # non-numeric: let layer 2 catch it
                if declared is not None and declared > self.max_bytes:
                    await self._send_413(send)
                    return
                break  # only one Content-Length; stop scanning

        # ── Layer 2: streaming counter ──────────────────────────────────
        state = {
            "total": 0,
            "overflow": False,
            "response_started": False,
        }

        async def counting_receive() -> ASGIMessage:
            message = await receive()
            if state["overflow"]:
                # Once we've decided to reject, any further receive() must
                # look like a client disconnect so the app aborts reading
                # and does not block waiting for more_body.
                return {"type": "http.disconnect"}
            if message["type"] == "http.request":
                body = message.get("body", b"")
                state["total"] += len(body)
                if state["total"] > self.max_bytes:
                    state["overflow"] = True
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: ASGIMessage) -> None:
            # Overflow discovered mid-request: replace whatever the app is
            # trying to send with the 413. This handles two cases:
            #   * app noticed the disconnect and is emitting an error 500;
            #   * app finished with a valid response before disconnect
            #     propagated (unlikely once we started returning disconnect,
            #     but harmless to intercept).
            if state["overflow"]:
                if not state["response_started"]:
                    state["response_started"] = True
                    await self._send_413(send)
                # After response.start we can never rewrite the status; just
                # swallow the rest so we don't double-write to the socket.
                return
            if message["type"] == "http.response.start":
                state["response_started"] = True
            await send(message)

        try:
            await self.app(scope, counting_receive, guarded_send)
        except Exception:
            # Any exception raised after we've forced a disconnect is
            # attributable to the truncation, not a real app fault -- the
            # app was mid-parse when its body vanished. Suppress it and
            # emit the 413 below. Real (non-overflow) exceptions propagate.
            if not state["overflow"]:
                raise

        if state["overflow"] and not state["response_started"]:
            await self._send_413(send)

    async def _send_413(self, send: ASGISend) -> None:
        payload = {
            "code": "PAYLOAD_TOO_LARGE",
            "message": (
                f"Request body exceeds the configured maximum of "
                f"{self._max_mb} MB."
            ),
            "hint": ERROR_HINTS.get("PAYLOAD_TOO_LARGE")
            or ERROR_HINTS["DEFAULT"],
            "trace_id": _current_trace_id(),
        }
        body = json.dumps(payload).encode("utf-8")
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
