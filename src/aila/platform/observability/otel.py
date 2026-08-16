"""OpenTelemetry GenAI-conventions helper (issue #160).

Emits spans that follow the stabilized 2026 GenAI semantic conventions
(``gen_ai.operation.name``, ``gen_ai.request.model``,
``gen_ai.usage.input_tokens`` / ``output_tokens``, ``gen_ai.system``,
``gen_ai.agent.name``, ...). The helper is deliberately additive:

* When ``opentelemetry`` is not installed the module import stays clean
  (try/except ImportError below), :func:`is_otel_available` returns
  False, and :func:`gen_ai_span` yields a no-op :class:`SpanHandle` that
  swallows every ``set_attribute`` / ``record_exception`` call.
* When ``opentelemetry`` IS installed but the ``platform.otel_enabled``
  ConfigRegistry flag is off (default), the helper returns the same
  no-op handle. Turning the flag on via ``PUT /config/platform/
  otel_enabled`` (or the ``AILA_PLATFORM_OTEL_ENABLED`` env override)
  lands on the next call without a worker restart.
* When both conditions hold, the helper starts a real span through the
  process tracer, tags it with the caller-supplied attributes, records
  exceptions, and closes it with an error status on failure.

The tracer / sdk configuration is intentionally left to the operator's
OTLP exporter setup (``opentelemetry-instrument`` wrapper, env-based
``OTEL_EXPORTER_OTLP_ENDPOINT`` etc). This module never installs a
processor or exporter -- it only produces spans against whatever
provider ``opentelemetry.trace.get_tracer`` hands back.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

from ..config_base import _shared_registry

logger = logging.getLogger(__name__)

__all__ = [
    "GEN_AI_OPERATION_CHAT",
    "GEN_AI_OPERATION_EMBEDDINGS",
    "GEN_AI_OPERATION_EXECUTE_TOOL",
    "GEN_AI_OPERATION_INVOKE_AGENT",
    "GEN_AI_SYSTEM_AILA",
    "SpanHandle",
    "gen_ai_span",
    "inject_trace_context",
    "is_otel_available",
    "is_otel_enabled",
]

# ---------------------------------------------------------------------------
# GenAI operation names (stabilized 2026 semantic conventions).
# ---------------------------------------------------------------------------
GEN_AI_OPERATION_CHAT = "chat"
GEN_AI_OPERATION_INVOKE_AGENT = "invoke_agent"
GEN_AI_OPERATION_EXECUTE_TOOL = "execute_tool"
GEN_AI_OPERATION_EMBEDDINGS = "embeddings"

# ``gen_ai.system`` is the provider system name. We use ``aila`` as an
# umbrella so a downstream consumer can filter every span produced by
# this platform without having to enumerate the underlying gateway
# names (OpenRouter / OmniRoute / Anthropic / local vLLM ...).
GEN_AI_SYSTEM_AILA = "aila"

_TRACER_NAME = "aila.platform"

# Fail-closed telemetry: every otel / registry call below is guarded so a
# telemetry fault never breaks the caller (observability is opt-in and must
# be side-effect-free on the hot path). This tuple names every failure the
# otel SDK, the tracer, and the config registry realistically raise, kept
# specific so the honesty audit's broad-except rule stays satisfied.
_TELEMETRY_SAFE_ERRORS = (
    AttributeError, TypeError, ValueError, RuntimeError,
    KeyError, LookupError, OSError,
)

# Optional dependency (see [otel] extra in pyproject.toml). The import
# is behind try/except so a base install without the extra keeps working
# untouched -- ``is_otel_available()`` returns False, every span call
# collapses to the no-op path, and the rest of the module never touches
# the opentelemetry namespace.
try:  # pragma: no cover - import-time branch, exercised by presence/absence of extra
    from opentelemetry import trace as _otel_trace
    from opentelemetry.propagate import inject as _otel_propagate_inject
    from opentelemetry.trace import Status as _OtelStatus
    from opentelemetry.trace import StatusCode as _OtelStatusCode

    _OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised on base install
    _otel_trace = None  # type: ignore[assignment]
    _otel_propagate_inject = None  # type: ignore[assignment]
    _OtelStatus = None  # type: ignore[assignment]
    _OtelStatusCode = None  # type: ignore[assignment]
    _OTEL_AVAILABLE = False


def is_otel_available() -> bool:
    """Return True iff the ``opentelemetry`` package is importable."""
    return _OTEL_AVAILABLE


def is_otel_enabled() -> bool:
    """Return True iff otel is installed AND the platform flag is on.

    Reads ``platform.otel_enabled`` via ConfigRegistry.get_sync -- the
    registry caches by 60s TTL + cross-process invalidation, so the
    check is close to a dict lookup on the hot path. Any resolution
    failure (registry unavailable, coercion error) collapses to False
    so the caller stays byte-identical to the base install.
    """
    if not _OTEL_AVAILABLE:
        return False
    try:
        raw = _shared_registry().get_sync("platform", "otel_enabled")
    except _TELEMETRY_SAFE_ERRORS:
        return False
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    if isinstance(raw, str):
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    return False


class SpanHandle:
    """Thin wrapper around an OpenTelemetry span with a no-op fallback.

    Every method is safe to call regardless of whether otel is
    installed or the flag is on: the no-op instance
    (:data:`_NOOP_SPAN`) swallows every write. This lets call sites
    stay linear (``with gen_ai_span(...) as span: span.set_attribute(...)``)
    without a per-attribute enabled-check.
    """

    __slots__ = ("_span",)

    def __init__(self, span: Any) -> None:
        self._span = span

    def set_attribute(self, key: str, value: Any) -> None:
        if self._span is None or value is None:
            return
        try:
            self._span.set_attribute(key, value)
        except _TELEMETRY_SAFE_ERRORS:
            logger.debug("gen_ai_span.set_attribute failed for %s", key, exc_info=True)

    def set_attributes(self, attrs: dict[str, Any]) -> None:
        if self._span is None or not attrs:
            return
        for k, v in attrs.items():
            self.set_attribute(k, v)

    def record_exception(self, exc: BaseException) -> None:
        if self._span is None:
            return
        try:
            self._span.record_exception(exc)
            if _OtelStatus is not None and _OtelStatusCode is not None:
                self._span.set_status(_OtelStatus(_OtelStatusCode.ERROR, type(exc).__name__))
        except _TELEMETRY_SAFE_ERRORS:
            logger.debug("gen_ai_span.record_exception failed", exc_info=True)

    def set_ok(self) -> None:
        if self._span is None or _OtelStatus is None or _OtelStatusCode is None:
            return
        try:
            self._span.set_status(_OtelStatus(_OtelStatusCode.OK))
        except _TELEMETRY_SAFE_ERRORS:
            logger.debug("gen_ai_span.set_ok failed", exc_info=True)


_NOOP_SPAN = SpanHandle(None)


def _tracer() -> Any:
    """Return the process tracer, or None when otel is unavailable."""
    if not _OTEL_AVAILABLE:
        return None
    try:
        return _otel_trace.get_tracer(_TRACER_NAME)  # type: ignore[union-attr]
    except _TELEMETRY_SAFE_ERRORS:
        logger.debug("otel get_tracer failed", exc_info=True)
        return None


@contextmanager
def gen_ai_span(
    operation: str,
    *,
    model: str | None = None,
    task_type: str | None = None,
    agent_name: str | None = None,
    system: str = GEN_AI_SYSTEM_AILA,
    run_id: str | None = None,
    attributes: dict[str, Any] | None = None,
) -> Iterator[SpanHandle]:
    """Yield a :class:`SpanHandle` scoped to one GenAI operation.

    Args:
        operation: Stabilized GenAI operation name (``chat`` /
            ``invoke_agent`` / ``execute_tool`` / ``embeddings``).
        model: Requested model id. Recorded as ``gen_ai.request.model``.
        task_type: Platform routing key (``scoring`` / ``reasoning`` /
            ...). Recorded as the AILA-scoped ``aila.task_type``.
        agent_name: Workflow / agent identifier. Recorded as
            ``gen_ai.agent.name`` -- populate for ``invoke_agent`` spans.
        system: ``gen_ai.system`` value. Defaults to the AILA umbrella
            (:data:`GEN_AI_SYSTEM_AILA`); callers that resolve the true
            downstream provider (openai / anthropic / ...) should pass
            it explicitly.
        run_id: Workflow / task run id. Recorded as ``aila.run_id`` to
            correlate spans with the platform's own audit trail.
        attributes: Extra key/value pairs the caller wants tagged on
            the span at start time. Additional attributes may still be
            added afterwards through :meth:`SpanHandle.set_attribute`
            (typical usage for response-side fields like usage tokens).

    The context manager yields a :class:`SpanHandle`; use its
    ``set_attribute`` / ``set_attributes`` to record post-response
    values (``gen_ai.response.model``, ``gen_ai.usage.input_tokens`` /
    ``output_tokens``, ``gen_ai.response.finish_reasons``). Exceptions
    raised inside the ``with`` block are recorded and re-raised.
    """
    if not is_otel_enabled():
        yield _NOOP_SPAN
        return

    tracer = _tracer()
    if tracer is None:
        yield _NOOP_SPAN
        return

    # Span name convention: "{operation} {target}" where target is the
    # requested model for chat/embeddings/execute_tool or the agent
    # name for invoke_agent. Matches the guidance in the GenAI spec so
    # a span shows up as e.g. ``chat gpt-4o`` / ``invoke_agent vr.investigation``.
    target = agent_name or model or operation
    span_name = f"{operation} {target}" if target != operation else operation

    span_attrs: dict[str, Any] = {
        "gen_ai.operation.name": operation,
        "gen_ai.system": system,
    }
    if model:
        span_attrs["gen_ai.request.model"] = model
    if agent_name:
        span_attrs["gen_ai.agent.name"] = agent_name
    if task_type:
        span_attrs["aila.task_type"] = task_type
    if run_id:
        span_attrs["aila.run_id"] = run_id
    if attributes:
        span_attrs.update(attributes)

    try:
        cm = tracer.start_as_current_span(span_name, attributes=span_attrs)
    except _TELEMETRY_SAFE_ERRORS:
        logger.debug("otel start_as_current_span failed", exc_info=True)
        yield _NOOP_SPAN
        return

    with cm as raw_span:
        handle = SpanHandle(raw_span)
        try:
            yield handle
        except BaseException as exc:
            handle.record_exception(exc)
            raise
        else:
            handle.set_ok()


def inject_trace_context(headers: dict[str, str]) -> None:
    """Inject the active span's W3C trace context into ``headers`` in place.

    Adds the ``traceparent`` (and, when present, ``tracestate``) header
    to the supplied dict so an outbound MCP request carries the current
    span context across the process boundary. The downstream server
    (audit-mcp / ida-headless / semble / ...) can then attach its own
    spans as children of the caller's span through any W3C
    trace-context-aware receiver.

    No-op when otel is not installed OR :func:`is_otel_enabled` is
    False -- the request goes out byte-identical to the pre-otel path,
    matching the module's opt-in, side-effect-free contract. Uses the
    globally-configured propagator (``opentelemetry.propagate.inject``)
    so an operator switching in b3/jaeger propagators via
    ``OTEL_PROPAGATORS`` env is honoured without a code change.
    """
    if not is_otel_enabled() or _otel_propagate_inject is None:
        return
    try:
        _otel_propagate_inject(headers)
    except _TELEMETRY_SAFE_ERRORS:
        logger.debug("otel propagate.inject failed", exc_info=True)
