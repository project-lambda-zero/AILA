"""HTTP middleware for the AILA REST API.

CorrelationIdMiddleware per D-45:
- Reads X-Correlation-ID from incoming request headers
- Generates a new UUID4 correlation ID if none is present
- Binds correlation_id, path, and method to structlog contextvars
- Sets X-Correlation-ID on the response so callers can trace requests
"""
from __future__ import annotations

from uuid import uuid4

import structlog
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

__all__ = ["CorrelationIdMiddleware", "IdempotencyMiddleware"]

from aila.api.middleware.idempotency import IdempotencyMiddleware


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Attach a correlation ID to every request/response pair.

    The correlation ID is sourced from the incoming X-Correlation-ID header
    or generated fresh as a UUID4. It is bound to structlog's contextvars
    so every log statement within the request handler automatically includes
    the correlation_id, path, and method fields.

    The same correlation ID is echoed back in the X-Correlation-ID response
    header so clients can correlate their requests to server-side logs.
    """

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        correlation_id = request.headers.get("X-Correlation-ID") or str(uuid4())

        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            correlation_id=correlation_id,
            path=request.url.path,
            method=request.method,
        )

        response: Response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id
        return response
