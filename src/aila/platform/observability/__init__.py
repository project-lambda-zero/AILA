"""Platform observability helpers.

Currently exposes the OpenTelemetry GenAI-conventions helper used by
LLM + workflow surfaces (issue #160). The rest of the platform imports
:func:`gen_ai_span` and treats it as a zero-cost no-op when either
opentelemetry is not installed or the ``platform.otel_enabled`` flag
is off. Turning both on makes the same context manager emit spans
named ``chat`` / ``invoke_agent`` / ``execute_tool`` with the
stabilized 2026 GenAI attribute names (``gen_ai.operation.name``,
``gen_ai.request.model``, ``gen_ai.usage.input_tokens`` ...).

The heavy import lives in :mod:`aila.platform.observability.otel` so
this package's import path stays free of any opentelemetry hard
dependency.
"""

from __future__ import annotations

from .otel import (
    GEN_AI_OPERATION_CHAT,
    GEN_AI_OPERATION_EMBEDDINGS,
    GEN_AI_OPERATION_EXECUTE_TOOL,
    GEN_AI_OPERATION_INVOKE_AGENT,
    GEN_AI_SYSTEM_AILA,
    SpanHandle,
    gen_ai_span,
    is_otel_available,
    is_otel_enabled,
)

__all__ = [
    "GEN_AI_OPERATION_CHAT",
    "GEN_AI_OPERATION_EMBEDDINGS",
    "GEN_AI_OPERATION_EXECUTE_TOOL",
    "GEN_AI_OPERATION_INVOKE_AGENT",
    "GEN_AI_SYSTEM_AILA",
    "SpanHandle",
    "gen_ai_span",
    "is_otel_available",
    "is_otel_enabled",
]
