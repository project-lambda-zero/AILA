"""Redis-backed Idempotency-Key middleware (Stripe pattern).

POST requests bearing an ``Idempotency-Key`` header are cached in Redis so that
duplicate submissions return the original response without re-executing the
handler.  Graceful degradation: if Redis is unavailable or the header is absent,
the request is processed normally.

Cache key format: ``IDEM:{idempotency_key}``
TTL: 24 hours (86 400 seconds)

Connection management: Uses the shared async Redis pool from
``aila.platform.services.redis_pool`` (OPS-01).
"""

from __future__ import annotations

import json
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from aila.api.metrics import SILENT_FAILURE_TOTAL
from aila.platform.services.redis_pool import get_redis, pool_available

__all__ = ["IdempotencyMiddleware"]

_log = logging.getLogger(__name__)
_IDEMPOTENCY_TTL = 86_400  # 24 hours
_IDEMPOTENCY_PREFIX = "IDEM:"


class IdempotencyMiddleware(BaseHTTPMiddleware):
    """Replay cached responses for duplicate POST requests bearing an Idempotency-Key header."""

    def __init__(self, app) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        # Only cache POST requests
        if request.method != "POST":
            return await call_next(request)

        idem_key = request.headers.get("Idempotency-Key")
        if not idem_key:
            return await call_next(request)

        if not pool_available():
            return await call_next(request)

        cache_key = f"{_IDEMPOTENCY_PREFIX}{idem_key}"

        # Check cache
        try:
            async with get_redis() as client:
                cached = await client.get(cache_key)
        except Exception:
            _log.debug("Idempotency middleware: Redis read failed, passing through")
            SILENT_FAILURE_TOTAL.labels(component="redis_idempotency").inc()
            return await call_next(request)

        if cached is not None:
            data = json.loads(cached)
            return Response(
                content=data["body"],
                status_code=data["status_code"],
                media_type=data.get("content_type", "application/json"),
                headers={"X-Idempotency-Replayed": "true"},
            )

        # Process request and cache response
        response = await call_next(request)
        body_chunks: list[bytes] = []
        async for chunk in response.body_iterator:
            if isinstance(chunk, str):
                body_chunks.append(chunk.encode("utf-8"))
            else:
                body_chunks.append(chunk)
        body_bytes = b"".join(body_chunks)

        try:
            async with get_redis() as client:
                await client.setex(
                    cache_key,
                    _IDEMPOTENCY_TTL,
                    json.dumps({
                        "status_code": response.status_code,
                        "body": body_bytes.decode("utf-8"),
                        "content_type": response.media_type or "application/json",
                    }),
                )
        except Exception:
            _log.debug("Idempotency middleware: Redis write failed, response still served")
            SILENT_FAILURE_TOTAL.labels(component="redis_idempotency").inc()

        return Response(
            content=body_bytes,
            status_code=response.status_code,
            headers=dict(response.headers),
            media_type=response.media_type,
        )
