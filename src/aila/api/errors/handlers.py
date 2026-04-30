"""FastAPI exception handlers emitting the standardized ErrorEnvelope (Phase 176a).

Three handlers are registered via :func:`register_error_handlers`:

* :func:`typed_error_handler` — catches every :class:`AILAError` subclass.
  Reads ``code`` + ``http_status`` as :class:`~typing.ClassVar` attributes when
  present (new Phase 176a taxonomy) and falls back to a 500 status plus a
  class-name-derived code for pre-existing subclasses that predate the
  ClassVar convention (preflight BE-E).
* :func:`validation_error_handler` — catches FastAPI's
  :class:`RequestValidationError` and emits envelope with
  ``code="VALIDATION_ERROR"``, HTTP 422.
* :func:`generic_error_handler` — catches any otherwise-unhandled
  :class:`Exception`. Emits envelope with ``code="INTERNAL_ERROR"``, HTTP 500.
  The ``message`` field is a static safe string — never ``str(exc)`` — so
  stack traces and internal paths never reach the client.

``trace_id`` is read from structlog's ``correlation_id`` contextvar
(preflight BE-F terminology bridge). If the contextvar is absent — e.g. an
exception fires before :class:`CorrelationIdMiddleware` has bound the
request — ``trace_id`` is ``None`` and the frontend treats it per D-26.
"""
from __future__ import annotations

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from aila.api.errors.envelope import ErrorEnvelope
from aila.api.errors.hints import ERROR_HINTS
from aila.api.metrics import AILA_API_ERROR_ENVELOPE_COUNTER
from aila.platform.exceptions import AILAError

__all__ = [
    "generic_error_handler",
    "register_error_handlers",
    "typed_error_handler",
    "validation_error_handler",
]

log = structlog.get_logger(__name__)


def _derive_module_label(exc: BaseException) -> str:
    """Map ``exc.__module__`` to a short module-bucket label for metrics.

    Algorithm:

    1. Split ``exc.__module__`` on ``.``.
    2. Locate the ``aila`` segment. If absent, return ``"platform"``.
    3. Examine the segment immediately after ``aila``:
       * if it is ``"modules"`` and a further segment exists, return that
         further segment (e.g. ``aila.modules.vulnerability.services.reports``
         → ``"vulnerability"``).
       * otherwise return the segment directly (e.g. ``aila.platform.llm.client``
         → ``"platform"``; ``aila.api.routers.foo`` → ``"api"``).
    4. If no segment follows ``aila``, return ``"platform"`` as a safe default.
    """
    parts = (getattr(exc, "__module__", "") or "").split(".")
    try:
        idx = parts.index("aila")
    except ValueError:
        return "platform"
    if idx + 1 >= len(parts):
        return "platform"
    after = parts[idx + 1]
    if after == "modules" and idx + 2 < len(parts):
        return parts[idx + 2]
    return after


def _current_trace_id() -> str | None:
    """Return the current request's correlation_id, or None if unbound.

    Preflight BE-F: middleware binds ``correlation_id``; the envelope exposes
    it as ``trace_id``. Safe under missing middleware — returns None rather
    than raising when contextvars are empty.
    """
    ctx = structlog.contextvars.get_contextvars() or {}
    value = ctx.get("correlation_id")
    if value is None:
        return None
    return str(value)


def _derive_code_for_legacy(exc: AILAError) -> str:
    """Derive a code string for a pre-existing AILAError subclass without ClassVar.

    Falls back to ``INTERNAL_ERROR`` when the class name isn't a useful
    machine-readable label.
    """
    cls_name = type(exc).__name__
    if not cls_name or cls_name == "AILAError":
        return "INTERNAL_ERROR"
    # Convert "SomeXyzError" → "SOME_XYZ_ERROR"-ish: upper-case + strip "Error"
    # into a stable "_ERROR" suffix.
    base = cls_name
    if base.endswith("Error"):
        base = base[: -len("Error")]
    # Camel-case split: insert "_" between lower→upper transitions.
    chars: list[str] = []
    for i, ch in enumerate(base):
        if i > 0 and ch.isupper() and base[i - 1].islower():
            chars.append("_")
        chars.append(ch.upper())
    code = "".join(chars) + "_ERROR" if chars else "INTERNAL_ERROR"
    return code


async def typed_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Envelope handler for every :class:`AILAError` (including legacy subclasses).

    New Phase 176a subclasses expose ClassVar ``code`` + ``http_status``.
    Pre-existing subclasses (AuthenticationError, NotFoundError, …) lack the
    ClassVar pair — this handler detects that, derives a code from the class
    name, and returns HTTP 500 as the safe fallback (preflight BE-E).
    """
    del request  # Unused; FastAPI passes it for signature compatibility.
    if not isinstance(exc, AILAError):
        log.error("error_handler.non_aila_error_routed", exc_type=type(exc).__name__)
        return JSONResponse(
            status_code=500,
            content={"error": {"code": "internal_error", "message": "An unexpected error occurred"}},
        )
    cls = type(exc)
    # hasattr respects inheritance so subclasses of the new typed taxonomy
    # inherit their code/http_status even without redefining them. AILAError
    # itself and the pre-existing subclasses do NOT declare these attributes
    # anywhere in their MRO — hasattr returns False and the handler falls
    # back to derive-from-class-name + 500 (preflight BE-E).
    has_classvar_code = hasattr(cls, "code")
    has_classvar_status = hasattr(cls, "http_status")

    if has_classvar_code:
        code = str(getattr(cls, "code"))
    else:
        code = _derive_code_for_legacy(exc)
    status = int(getattr(cls, "http_status")) if has_classvar_status else 500

    hint = ERROR_HINTS.get(code) or ERROR_HINTS.get("DEFAULT")
    module_label = _derive_module_label(exc)

    # message field is ALWAYS a safe static string. Typed D-20 errors define a
    # ClassVar ``user_message`` authored for external consumption; legacy
    # subclasses fall back to the generic internal-error string. ``str(exc)``
    # is NEVER surfaced to clients — it is only logged server-side because it
    # can leak file paths, provider identifiers, or other caller-supplied
    # context (S1).
    if status == 500 or not has_classvar_code:
        message = "An internal error occurred."
    else:
        message = getattr(cls, "user_message", "An error occurred.")

    envelope = ErrorEnvelope(
        code=code,
        message=message,
        hint=hint,
        trace_id=_current_trace_id(),
    )
    AILA_API_ERROR_ENVELOPE_COUNTER.labels(
        code=code, status=str(status), module=module_label
    ).inc()
    log.warning(
        "api_error_envelope",
        code=code,
        status=status,
        module=module_label,
        exc_class=cls.__name__,
        exc_message=str(exc),
    )
    return JSONResponse(status_code=status, content=envelope.model_dump())


async def validation_error_handler(
    request: Request, exc: Exception
) -> JSONResponse:
    """Envelope handler for FastAPI :class:`RequestValidationError` (HTTP 422)."""
    log.warning(
        "api_validation_error",
        path=request.url.path,
        method=request.method,
        errors=exc.errors() if hasattr(exc, "errors") else str(exc),
        client=request.client.host if request.client else None,
    )
    envelope = ErrorEnvelope(
        code="VALIDATION_ERROR",
        message="Request validation failed",
        hint=ERROR_HINTS.get("VALIDATION_ERROR")
        or ERROR_HINTS.get("DEFAULT", "Fix the input and retry."),
        trace_id=_current_trace_id(),
    )
    AILA_API_ERROR_ENVELOPE_COUNTER.labels(
        code="VALIDATION_ERROR", status="422", module="api"
    ).inc()
    return JSONResponse(status_code=422, content=envelope.model_dump())


async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Envelope handler for any otherwise-unhandled :class:`Exception`.

    ``message`` is a static safe string — never ``str(exc)`` — so stack traces
    and internal paths cannot leak to clients.
    """
    del request  # Unused; FastAPI passes it for signature compatibility.
    log.exception("api_unhandled_exception", exc_class=type(exc).__name__)
    envelope = ErrorEnvelope(
        code="INTERNAL_ERROR",
        message="An internal error occurred.",
        hint=ERROR_HINTS.get("INTERNAL_ERROR") or ERROR_HINTS["DEFAULT"],
        trace_id=_current_trace_id(),
    )
    AILA_API_ERROR_ENVELOPE_COUNTER.labels(
        code="INTERNAL_ERROR",
        status="500",
        module=_derive_module_label(exc),
    ).inc()
    return JSONResponse(status_code=500, content=envelope.model_dump())


def register_error_handlers(app: FastAPI) -> None:
    """Wire the three envelope handlers onto a FastAPI app.

    Call once, from the app factory, after middleware but before router mounts.
    Registers handlers for :class:`AILAError`, :class:`RequestValidationError`,
    and the bare :class:`Exception`. The final ``Exception`` handler does NOT
    intercept :class:`fastapi.HTTPException` (FastAPI keeps its own handler
    chain for that class).
    """
    app.add_exception_handler(AILAError, typed_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(Exception, generic_error_handler)
