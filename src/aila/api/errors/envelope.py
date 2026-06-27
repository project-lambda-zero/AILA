"""ErrorEnvelope -- uniform error response body for the AILA REST API (Phase 176a).

Every non-2xx response emitted by :func:`register_error_handlers` uses this
shape (D-10a). The ``trace_id`` field is populated from structlog's
``correlation_id`` contextvar (preflight BE-F); it may be ``None`` when an
exception fires before CorrelationIdMiddleware has bound the context (D-26).
"""
from __future__ import annotations

from aila.api.schemas.common import APIModel

__all__ = ["ErrorEnvelope"]


class ErrorEnvelope(APIModel):
    """Canonical four-field error envelope returned for every non-2xx response.

    Fields:
        code: Stable machine-readable error code (e.g. ``"MISSING_API_KEY"``).
        message: Human-readable error description -- safe for display. Never
            contains a stack trace or raw ``str(exc)``.
        hint: Operator-facing prescriptive next step sourced from
            :mod:`aila.api.errors.hints`. ``None`` only if no hint is mapped.
        trace_id: Correlation ID from structlog contextvars. ``None`` when the
            exception fires outside a request context.
    """

    code: str
    message: str
    hint: str | None = None
    trace_id: str | None = None
