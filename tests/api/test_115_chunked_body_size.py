"""Focused regression test for issue #115.

The previous request-size guard only checked ``Content-Length``. A
chunked-transfer body that omits the header slipped past and let a caller
buffer an unbounded body in worker memory before FastAPI parsed it.

:class:`aila.api.middleware.BodySizeLimitMiddleware` now streams the
receive channel and rejects the moment the running byte total crosses the
configured maximum, regardless of what ``Content-Length`` said.

This test wraps a bare Starlette app in the middleware (no DB, no auth, no
fixtures) so it exercises the guard in isolation. Two assertions:

1. A body that exceeds the cap and is sent WITHOUT a truthful
   ``Content-Length`` (chunked transfer, driven by httpx passing an async
   iterator as ``content``) is rejected with 413.
2. The 413 body is the standard :class:`ErrorEnvelope` shape
   (``code=PAYLOAD_TOO_LARGE``).
"""
from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from aila.api.middleware import BodySizeLimitMiddleware

pytestmark = pytest.mark.asyncio


async def _echo_body_size(request: Request) -> JSONResponse:
    body = await request.body()
    return JSONResponse({"received_bytes": len(body)})


def _make_client(max_bytes: int) -> AsyncClient:
    app = Starlette(routes=[Route("/echo", _echo_body_size, methods=["POST"])])
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_bytes)
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    )


async def _chunked_stream(total_bytes: int, chunk: int = 8192) -> AsyncIterator[bytes]:
    """Yield ``total_bytes`` bytes in ``chunk``-sized pieces.

    httpx sends an async iterator using chunked transfer encoding with no
    ``Content-Length`` header, which is precisely the bypass path from
    issue #115.
    """
    payload = b"x" * chunk
    sent = 0
    while sent < total_bytes:
        take = min(chunk, total_bytes - sent)
        yield payload[:take]
        sent += take


async def test_chunked_body_over_limit_rejected_413() -> None:
    """A chunked body over the cap is rejected with 413 + ErrorEnvelope.

    Cap is set well below the payload size so the streaming counter is the
    only line of defense (no Content-Length is sent).
    """
    max_bytes = 32 * 1024  # 32 KiB
    async with _make_client(max_bytes) as client:
        resp = await client.post(
            "/echo",
            content=_chunked_stream(total_bytes=max_bytes * 4),
            headers={"Content-Type": "application/octet-stream"},
        )

    assert resp.status_code == 413, (
        f"Chunked body over the cap must be rejected with 413, got "
        f"{resp.status_code} -- streaming byte counter is not enforcing"
    )
    data = resp.json()
    assert data.get("code") == "PAYLOAD_TOO_LARGE"
    assert "message" in data and data["message"], "envelope missing message"
    assert "hint" in data, "envelope missing hint key"
    assert "trace_id" in data, "envelope missing trace_id key"


async def test_body_under_limit_passes_through() -> None:
    """A body under the cap reaches the app untouched."""
    max_bytes = 32 * 1024
    async with _make_client(max_bytes) as client:
        resp = await client.post(
            "/echo",
            content=_chunked_stream(total_bytes=max_bytes // 2),
            headers={"Content-Type": "application/octet-stream"},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["received_bytes"] == max_bytes // 2


async def test_lying_content_length_still_caught_by_stream_counter() -> None:
    """A body that CLAIMS to be small but streams more is caught mid-stream.

    Sends a ``Content-Length`` header UNDER the cap (fast-reject passes)
    while the actual chunked body drains past the cap. This is the
    second flavor of the #115 bypass: a lying header. The streaming
    counter must still fire.
    """
    max_bytes = 16 * 1024
    async with _make_client(max_bytes) as client:
        # httpx will honor the explicit Content-Length header we set even
        # though we're streaming content; the streaming counter is what
        # has to catch the overrun.
        resp = await client.post(
            "/echo",
            content=b"x" * (max_bytes * 3),
            headers={
                "Content-Type": "application/octet-stream",
                "Content-Length": str(max_bytes // 2),
            },
        )

    assert resp.status_code == 413
    assert resp.json().get("code") == "PAYLOAD_TOO_LARGE"
