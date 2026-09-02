"""Async LLM client for the AILA platform.

Provides chat(), chat_json(), chat_structured() async methods and their
sync wrappers.  Built on openai.AsyncOpenAI -- talks to OpenRouter, direct
OpenAI, or local endpoints via configurable base_url.

Callers pass task_type (e.g. "scoring"), the client resolves the model
internally from ConfigRegistry.  Callers never know which model is used.

Sync wrappers use asyncio.run() -- safe because sync call sites run inside
asyncio.to_thread from FastAPI (clean thread, no event loop) (per D-03).

Tool calling (per D-05-new):
  When tools=[...] is passed, client runs an async loop:
  call -> tool_use -> execute -> tool_result -> call -> ... -> final response.
  When no tools, it's one-shot.  Same method, not a separate API.
  max_steps is configurable per task_type via ConfigRegistry (per D-20).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time as _time_mod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import sqlalchemy.exc
from openai import (
    APIConnectionError,
    APITimeoutError,
    AsyncOpenAI,
    RateLimitError,
)
from pydantic import BaseModel, ValidationError

from ..config_base import _shared_registry
from ..exceptions import AILAError
from ..observability import GEN_AI_OPERATION_CHAT, gen_ai_span
from .cancellation import LLMCancelledError, is_run_cancelled
from .config import LLMConfigProvider
from .errors import LLMError
from .pipeline import PipelineRunner

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry
    from ...storage.secrets import SecretStore

logger = logging.getLogger(__name__)

# Best-effort cost / telemetry recording runs AFTER a successful LLM call. A
# failure in any of those steps must never propagate into the provider-retry
# loop and turn a good response into a retried LLMError, so each step swallows
# this realistic leak set independently (DB, arithmetic, missing metrics import,
# platform errors) while still logging.
_COST_TELEMETRY_ERRORS: tuple[type[BaseException], ...] = (
    ValueError,
    TypeError,
    RuntimeError,
    OSError,
    AttributeError,
    ImportError,
    sqlalchemy.exc.SQLAlchemyError,
    AILAError,
)

# ── LLM endpoint health tracking ─────────────────────────────────────
#
# Per-process globals updated on every LLM call. Consumed by the masvs
# parent_reconciler to gate stale-branch abandonment: when the LLM
# endpoint has been unhealthy in the recent past, branches sitting
# idle on retry-loops are NOT "stalled" by their own fault -- they're
# waiting on the LLM. Abandoning them in that window destroys real
# progress and is operator-prohibited.
#
# We update _LAST_LLM_ERROR_AT on every retryable exception even when
# a later retry succeeds -- the failure window is still real, the
# branch did spend wall-clock time waiting, and any concurrent
# branches may have hit the same outage.
_LAST_LLM_OK_AT: float = 0.0
_LAST_LLM_ERROR_AT: float = 0.0


def _record_llm_ok(url: str | None = None) -> None:
    """Update the last-OK timestamp and clear per-URL infra-health.

    Called inside the retry success path. ``url`` is optional so pre-
    RFC-07 callers that never learned the routed URL still work; the
    per-URL health branch skips when no URL is supplied so the router
    stays inert for those paths.
    """
    global _LAST_LLM_OK_AT
    _LAST_LLM_OK_AT = _time_mod.monotonic()
    if url:
        # Deferred import: health_router imports nothing from this
        # module, so a plain top-level import would be fine -- keeping
        # it inline keeps the health-router hook one grep away from
        # its call site and matches how the drift + cost hooks below
        # thread their imports.
        from .health_router import get_default_health_router
        get_default_health_router().record_success(url)


def _record_llm_error(
    url: str | None = None,
    *,
    kind: str = "unknown",
) -> None:
    """Update the last-error timestamp and mark ``url`` infra-unhealthy.

    Called inside every retry catch. ``url`` and ``kind`` are optional so
    pre-RFC-07 callers keep working; the per-URL router only wakes when
    both are supplied. ``kind`` classifies the infra failure (timeout,
    connect_refused, http_5xx, unknown); the router records every kind
    as unhealthy but retains the label for diagnostics.
    """
    global _LAST_LLM_ERROR_AT
    _LAST_LLM_ERROR_AT = _time_mod.monotonic()
    if url:
        from .health_router import get_default_health_router
        get_default_health_router().record_infra_failure(url, kind)  # type: ignore[arg-type]


def is_llm_recently_unhealthy(window_s: float = 600.0) -> bool:
    """Return True iff the LLM had any error in the trailing window AND
    has not had a more recent success.

    Used by reconciler step 5 to gate stale-branch abandonment. A
    branch that has been idle through an LLM outage is waiting for
    work, not stalled -- abandoning it would destroy real progress.

    Args:
        window_s: How far back to look for the last error. Default 10
            minutes -- matches the worker's typical retry-window times
            (5-10 retries with exponential backoff cap at 60s each).
    """
    if _LAST_LLM_ERROR_AT == 0.0:
        return False
    now = _time_mod.monotonic()
    if (now - _LAST_LLM_ERROR_AT) > window_s:
        return False
    # Error within window -- only "healthy" if a success has happened
    # strictly after the most recent error.
    return _LAST_LLM_OK_AT <= _LAST_LLM_ERROR_AT


def get_llm_health_snapshot() -> dict[str, float | bool]:
    """Expose health timestamps for diagnostics + logging."""
    now = _time_mod.monotonic()
    return {
        "last_ok_age_s": (now - _LAST_LLM_OK_AT) if _LAST_LLM_OK_AT else -1.0,
        "last_error_age_s": (now - _LAST_LLM_ERROR_AT) if _LAST_LLM_ERROR_AT else -1.0,
        "recently_unhealthy_10min": is_llm_recently_unhealthy(600.0),
    }


# Models that reject ``temperature`` with 400. Configurable via the env var
# AILA_LLM_MODELS_REJECTING_TEMPERATURE (comma-separated substrings matched
# against the routed model_id). Falls back to a hardcoded list when unset.
_FALLBACK_REJECTION_MARKERS: tuple[str, ...] = (
    "claude-opus-4-6", "claude-4.6-opus",
    "claude-opus-4-7", "claude-4.7-opus",
    "claude-sonnet-4-7", "claude-4.7-sonnet",
    "high-thinking",
    "o1", "o3", "o4",
    "gpt-5", "hadi",
)

_resolved_markers: tuple[str, ...] | None = None


def _get_rejection_markers() -> tuple[str, ...]:
    """Return the active rejection marker list, resolved once per process.

    Resolution order:
      1. ``AILA_LLM_MODELS_REJECTING_TEMPERATURE`` env var (comma-separated)
      2. ``platform.llm_models_rejecting_temperature`` config DB entry (editable at /admin/config)
      3. Hardcoded fallback tuple

    The env var overrides everything. The config DB entry is editable from
    the Config page and takes effect on next worker restart (the value is
    cached for the process lifetime after first read).
    """
    global _resolved_markers
    if _resolved_markers is not None:
        return _resolved_markers
    import os
    # 1. Env var overrides everything
    env_val = os.environ.get("AILA_LLM_MODELS_REJECTING_TEMPERATURE", "").strip()
    if env_val:
        _resolved_markers = tuple(m.strip().lower() for m in env_val.split(",") if m.strip())
        return _resolved_markers
    # 2. Config DB entry
    try:
        from sqlmodel import select

        from aila.storage.database import session_scope
        from aila.storage.db_models import ConfigEntryRecord
        with session_scope() as session:
            row = session.exec(
                select(ConfigEntryRecord).where(
                    ConfigEntryRecord.namespace == "platform",
                    ConfigEntryRecord.key == "llm_models_rejecting_temperature",
                )
            ).first()
            if row is not None and row.value.strip():
                _resolved_markers = tuple(m.strip().lower() for m in row.value.split(",") if m.strip())
                return _resolved_markers
    except (OSError, RuntimeError, ImportError) as exc:
        logger.debug("Config DB read for llm_models_rejecting_temperature failed, using fallback: %s", exc)
    # 3. Hardcoded fallback
    _resolved_markers = _FALLBACK_REJECTION_MARKERS
    return _resolved_markers


def _model_supports_temperature(model_id: str) -> bool:
    """Return False when the routed model is known to reject ``temperature``.

    Markers match on alphanumeric boundaries so a short marker like ``o1`` does
    not spuriously fire inside an unrelated id (``proto1``, ``audio1``); the
    old ``marker in mid`` substring test stripped temperature from those by
    accident (issue #44).
    """
    mid = (model_id or "").lower()
    return not any(
        re.search(rf"(?<![a-z0-9]){re.escape(marker)}(?![a-z0-9])", mid)
        for marker in _get_rejection_markers()
    )


def _strip_json_fences(content: str) -> str:
    """Remove Markdown code fences, thinking tags, and surrounding prose from an LLM JSON response.

    Handles:
    - <think>...</think> reasoning blocks from thinking models (DeepSeek / Qwen / Nemotron).
    - ```json ... ``` code fences anywhere in the response.
    - Direct JSON payloads.
    """
    if not content:
        return content
    text = content.strip()

    # Strip <think>...</think> reasoning blocks if present
    text = re.sub(r"<think>[\s\S]*?</think>", "", text).strip()

    # If wrapped or containing markdown code fence, extract block between fences
    fence_match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    if fence_match:
        text = fence_match.group(1).strip()
    elif text.startswith("```"):
        first_nl = text.find("\n")
        if first_nl != -1:
            text = text[first_nl + 1:]
        if text.rstrip().endswith("```"):
            text = text.rstrip()[:-3].rstrip()

    return text


def _clean_and_repair_json(content: str) -> str:
    """Extract and repair JSON from model output containing reasoning, code fences, or commentary."""
    if not content:
        return content
    cleaned = _strip_json_fences(content)
    try:
        json.loads(cleaned)
        return cleaned
    except json.JSONDecodeError:
        pass

    # Try raw_decode on first { or [
    start_obj = cleaned.find("{")
    start_arr = cleaned.find("[")
    starts = [s for s in (start_obj, start_arr) if s >= 0]
    if starts:
        start = min(starts)
        try:
            parsed, _ = json.JSONDecoder().raw_decode(cleaned[start:])
            return json.dumps(parsed)
        except json.JSONDecodeError:
            pass

    # Try matching outer object { ... }
    if start_obj >= 0:
        end_obj = cleaned.rfind("}")
        if end_obj > start_obj:
            slice_text = cleaned[start_obj : end_obj + 1]
            try:
                parsed = json.loads(slice_text)
                return json.dumps(parsed)
            except json.JSONDecodeError:
                pass

    return cleaned


def _inject_strict_schema_requirements(schema: dict[str, Any]) -> dict[str, Any]:
    """Recursively inject OpenAI strict structured output requirements.

    OpenAI strict mode requires two things on every object in the schema:
    1. additionalProperties: false
    2. required: [...all property names...]

    Pydantic's model_json_schema() omits additionalProperties and only includes
    required for fields without defaults. This function injects both.
    """
    import copy
    schema = copy.deepcopy(schema)

    def _fix(node: dict[str, Any]) -> None:
        if node.get("type") == "object":
            node["additionalProperties"] = False
            # OpenAI strict mode requires all properties listed in required
            props = node.get("properties")
            if isinstance(props, dict) and props:
                node["required"] = sorted(props.keys())
        for key in ("properties", "$defs", "definitions"):
            container = node.get(key)
            if isinstance(container, dict):
                for child in container.values():
                    if isinstance(child, dict):
                        _fix(child)
        for key in ("items", "anyOf", "oneOf", "allOf"):
            val = node.get(key)
            if isinstance(val, dict):
                _fix(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        _fix(item)

    _fix(schema)
    return schema


@dataclass(frozen=True, slots=True)
class LLMResponse:
    """Structured response from an LLM call.

    Attributes:
        content: The text content from the model (empty string if disabled).
        model: The model_id that was used.
        usage: Token usage dict with prompt_tokens, completion_tokens, total_tokens.
        disabled: True if the kill switch was active (content will be the error message).
        finish_reason: The finish_reason from the API (e.g. "stop", "length", "tool_calls").
    """

    content: str
    model: str = ""
    usage: dict[str, int] = field(default_factory=dict)
    disabled: bool = False
    finish_reason: str = ""
    # Pipeline metadata (Phase 116) -- default None, transparent to existing callers.
    # _enrich_response() populates these from the pipeline ctx after the
    # classify / gate / seal steps run. Declaring them is required: the
    # dataclass is frozen + slots, so _enrich_response constructing with these
    # kwargs raised TypeError the moment any step wrote a non-None value
    # (issue #44).
    classification: Any = None
    confidence: Any = None
    seal_id: str | None = None
    pipeline_metadata: dict[str, Any] | None = None


def _annotate_llm_span(span: Any, response: LLMResponse, requested_model: str) -> None:
    """Tag a gen_ai span with response-side attributes.

    Records the resolved model, token usage, and finish reason using the
    stabilized GenAI attribute names. ``span`` is a
    :class:`aila.platform.observability.SpanHandle`; every setter is a
    no-op when otel is disabled, so this helper is cheap on the base
    install path.
    """
    if response.disabled:
        span.set_attribute("aila.llm.disabled", True)
        return
    resolved_model = response.model or requested_model
    if resolved_model:
        span.set_attribute("gen_ai.response.model", resolved_model)
    usage = response.usage or {}
    prompt_tokens = int(usage.get("prompt_tokens") or 0)
    completion_tokens = int(usage.get("completion_tokens") or 0)
    total_tokens = int(usage.get("total_tokens") or 0)
    if prompt_tokens:
        span.set_attribute("gen_ai.usage.input_tokens", prompt_tokens)
    if completion_tokens:
        span.set_attribute("gen_ai.usage.output_tokens", completion_tokens)
    if total_tokens:
        span.set_attribute("gen_ai.usage.total_tokens", total_tokens)
    if response.finish_reason:
        # Spec models this as an array; keep the single-value form here
        # because the platform never surfaces multi-choice completions.
        span.set_attribute(
            "gen_ai.response.finish_reasons", (response.finish_reason,)
        )


# Retry budget -- TIGHT BY DESIGN.
#
# Background (the change shipped on 2026-06-13 after the maddie /
# <inv-uuid-a> stall was diagnosed on inv <inv-uuid-b> et al):
#
# The old budget was max_retries=100 × up-to-30s backoff = ~48 min
# of in-task retry burn. That meant a single worker process would
# pin itself on ONE task's retry loop for nearly an hour during any
# sustained provider degradation (NVIDIA NIM 40 RPM throttling,
# OpenRouter 503, OmniRoute restart). All other queued tasks
# starved behind that worker, which was the observed
# "113 tasks queued, no progress" symptom right after the stall-
# recovery sweep landed.
#
# New model: fail FAST inside the task body, let ARQ retry the
# whole task with its own exponential backoff. ARQ's retry budget
# is per-task-attempt, not per-LLM-call, so it doesn't pin the
# worker on retry-spin. The final raise still carries
# ``retryable=True`` so ARQ knows the task can resume; cursor SSOT
# preserves the workflow state between attempts.
#
# With max_retries=3 and capped 30s backoff:
#   attempts 1-3: 1s, 2s, 4s
# Total in-task budget ≈ 7 seconds. Anything longer is the queue
# layer's job, not the in-call retry loop.
#
# For ``RateLimitError`` specifically: when the provider sends a
# ``Retry-After`` header, honour it (capped at retry_max_delay).
# That lets us delay-and-retry within the existing 3-attempt
# budget instead of failing immediately on a known-recoverable
# 429 with a "try again in N seconds" signal.
#
# fix #132 -- knobs live on ``PlatformConfigSchema`` and are resolved
# through :class:`aila.storage.registry.ConfigRegistry` at each call,
# not read as module-level constants at import time. The env form is
# ``AILA_PLATFORM_LLMmax_retries`` /
# ``AILA_PLATFORM_LLMretry_base_delay_S`` /
# ``AILA_PLATFORM_LLMretry_max_delay_S``, participating in the
# env > DB > default chain so ``PUT /config/platform/llm_max_retries``
# lands on the next call without a worker restart. Defaults match the
# historical fast-fail budget (see the "Retry budget" essay above).
def _resolve_retry_budget() -> tuple[int, float, float]:
    """Return ``(max_retries, base_delay_s, max_delay_s)`` from ConfigRegistry.

    Sync call for hot retry paths. Values are cached inside the registry
    (60s TTL + cross-process invalidation), so repeated resolution is
    close to a dict get. Enforces the same floors the module-level
    reads used to enforce (``max(1, ...)`` for retries; ``max(0.1, ...)``
    for base delay; base <= max delay).
    """
    registry = _shared_registry()
    max_retries = max(1, int(registry.get_sync("platform", "llm_max_retries")))
    base = max(0.1, float(registry.get_sync("platform", "llm_retry_base_delay_s")))
    ceiling = max(base, float(registry.get_sync("platform", "llm_retry_max_delay_s")))
    return max_retries, base, ceiling


def _resolve_structured_json_max_attempts() -> int:
    """Return the chat_structured() correction-loop budget."""
    return max(1, int(
        _shared_registry().get_sync(
            "platform", "llm_structured_json_max_attempts",
        )
    ))


def _resolve_llm_timeout_seconds() -> float:
    """Return the per-call HTTP timeout in seconds."""
    try:
        return float(
            _shared_registry().get_sync("platform", "llm_timeout_seconds")
        )
    except (TypeError, ValueError):
        return 180.0

# chat_structured() correction-loop budget. TIGHT BY DESIGN.
#
# Background: VR reasoning turns feed the model's JSON output straight into
# ``run_turn`` -- a single malformed response used to burn the whole ARQ
# task-attempt because chat_structured() offered exactly ONE correction
# retry before raising ``LLMError(retryable=False)``. Symptom on VR
# investigation timelines: "previous turn produced invalid JSON" followed
# by a cold re-enqueue with the workflow cursor rewound to the last
# durable checkpoint.
#
# The bound stays small (default 3 total attempts) so a truly stuck model
# still fails fast into the outer ARQ retry -- the worker never spins on
# doomed JSON correction. Each retry embeds the verbatim pydantic
# ``ValidationError`` text and, when available, the partial JSON that was
# extracted, so the model sees exactly which field it botched instead of
# a generic "try again" nudge. This is per-call (chat_structured); the
# outer ``llm_max_retries`` still gates provider-side transient failures.
# The value is resolved through ``_resolve_structured_json_max_attempts()``
# above (see fix #132 essay), not read as a module-level constant.

# HTTP status codes that stay retryable even though they land in the 4xx
# range: request-timeout (408), too-early (425), and rate-limit (429).
# Everything else in 4xx (auth, permission, malformed request, not-found,
# unprocessable) will keep failing on repeat and MUST fail fast so the
# worker slot is not burned on doomed backoff sleeps.
_RETRYABLE_4XX_STATUSES: frozenset[int] = frozenset({408, 425, 429})


# 4xx provider-availability markers. When a weighted routing combo rolls
# to an underlying model whose provider is down / unauthenticated / quota-
# exhausted / circuit-broken, the gateway surfaces a 4xx whose message names
# the availability failure rather than a malformed request. A retry re-rolls
# the combo to a different member, so these are retryable even though a raw
# 4xx is normally fatal. A genuine request-validation 4xx (bad parameter or
# schema) does not match and stays non-retryable.
_PROVIDER_AVAILABILITY_MARKERS: tuple[str, ...] = (
    "not supported", "not available", "no credentials", "credits",
    "insufficient", "circuit breaker", "banned", "expired", "unavailable",
    "gone", "no healthy", "quota", "rate limit", "overloaded", "try again",
    "temporarily", "no provider", "all providers",
)
# A weighted-combo routing gateway surfaces an upstream member failure
# with a bracketed HTTP status, e.g. "[410]: ..." / "[cerebras/x] [403]: ...".
# That bracket is the reliable "this rolled-to member is down -- re-roll"
# signature and also catches opaque HTML error bodies the markers miss.
_UPSTREAM_STATUS_RE = re.compile(r"\[\d{3}\]")


def _is_retryable(exc: BaseException) -> bool:
    """Classify a provider or client exception as retryable vs non-retryable.

    Retryable: transient upstream failures where a repeat of the same request
    has a realistic chance of succeeding -- HTTP 429 (rate limit), 5xx
    (server errors), 408 (request timeout), 425 (too early), and network-
    layer failures (connection reset, DNS, wall-clock timeout). Also:
    LLMError instances that self-report as retryable.

    Non-retryable: failures a retry cannot fix -- HTTP 4xx auth (401),
    permission (403), malformed request (400), not-found (404),
    unprocessable entity (422). Also: LLMError instances that self-report
    as non-retryable (classification blocks, schema violations, kill switch).

    Unknown exception types default to retryable so a transient failure from
    an unfamiliar provider client does not silently regress the historical
    retry-everything behaviour. Only recognised non-retryable classes and
    explicit non-retryable HTTP statuses fail fast.
    """
    if isinstance(exc, LLMError):
        return exc.retryable
    # Transport-level provider failures the openai client raises. Listed
    # explicitly so a future release that changes their status_code
    # surface still classifies correctly.
    if isinstance(exc, (APIConnectionError, APITimeoutError, RateLimitError)):
        return True
    # Status-code driven classification. Covers openai.APIStatusError
    # subclasses (AuthenticationError, PermissionDeniedError,
    # BadRequestError, NotFoundError, UnprocessableEntityError,
    # InternalServerError) and any provider client that exposes an
    # HTTP status through the same attribute name.
    status_code = getattr(exc, "status_code", None)
    if isinstance(status_code, int):
        if status_code in _RETRYABLE_4XX_STATUSES:
            return True
        if 500 <= status_code < 600:
            return True
        if 400 <= status_code < 500:
            # A 4xx from a weighted combo usually means the rolled-to member
            # is unavailable, not that the request is malformed. Retry so the
            # next attempt re-rolls to a different (possibly healthy) member;
            # a true request-validation 4xx does not match and stays fatal.
            msg = str(exc).lower()
            if (
                _UPSTREAM_STATUS_RE.search(msg)
                or any(marker in msg for marker in _PROVIDER_AVAILABILITY_MARKERS)
            ):
                return True
            return False
    return True


@dataclass(frozen=True, slots=True)
class _ClientKey:
    api_key_hash: str
    base_url: str
    timeout_s: float


class _AsyncOpenAIPool:
    """Process-local pool of AsyncOpenAI clients keyed by (api_key, base_url,
    timeout).

    Previously every LLM call built a fresh ``AsyncOpenAI`` -- each owning an
    ``httpx.AsyncClient`` connection pool -- and ``_call_with_retry`` never
    closed it, so the file-descriptor count grew unbounded under load (#44).
    Routing is frozen per investigation, so a keyed pool converges to a tiny
    number of long-lived clients whose connections are reused.

    ``AsyncOpenAI`` construction is synchronous, so :meth:`get` has no await
    point and is safe to call from concurrent coroutines on one event loop
    without a lock. :meth:`aclose` closes every pooled client's underlying
    ``httpx.AsyncClient`` and drops the entries; call it once from the
    worker/API shutdown hook so the TLS pool does not leak on process
    teardown (#44).
    """

    def __init__(self) -> None:
        self._pool: dict[_ClientKey, AsyncOpenAI] = {}

    def get(self, *, api_key: str, base_url: str, timeout_s: float) -> AsyncOpenAI:
        key = _ClientKey(
            api_key_hash=hashlib.sha256(api_key.encode()).hexdigest()[:16],
            base_url=base_url,
            timeout_s=timeout_s,
        )
        client = self._pool.get(key)
        if client is None:
            client = AsyncOpenAI(
                api_key=api_key,
                base_url=base_url,
                max_retries=0,  # retries handled in _call_with_retry
                timeout=timeout_s,
            )
            self._pool[key] = client
        return client

    async def aclose(self) -> None:
        """Close every pooled AsyncOpenAI and drop it from the registry.

        Best-effort: a per-client close failure is logged and skipped so
        one bad connection cannot block the rest of the shutdown sweep.
        The pool becomes reusable after this call -- :meth:`get` will
        rebuild any client on next demand -- but the intended use is
        one-shot at process shutdown.
        """
        clients = list(self._pool.values())
        self._pool.clear()
        for client in clients:
            try:
                await client.close()
            except (OSError, RuntimeError, AttributeError) as exc:
                logger.debug("_AsyncOpenAIPool.aclose: close failed: %s", exc)


@dataclass(slots=True)
class _CallState:
    """Per-attempt bookkeeping for the tool-executor idempotency guard.

    ``tools_committed`` is incremented every time :meth:`_tool_loop`
    completes a ``tool_executor()`` call (including the synthetic
    tool-timeout result -- from the model's perspective a side effect
    still "happened": the tool ran, produced observable I/O against the
    MCP bridge, and any partial mutation stands). :meth:`_call_with_retry`
    reads the counter on every exception path: if any tool has committed
    in the current attempt, the retry is disabled and the failure is
    surfaced as non-retryable so a transient upstream error does not
    replay the tool loop against the same investigation and duplicate
    messages / observables / MCP mutations (#44).
    """

    tools_committed: int = 0


class AilaLLMClient:
    """Async-first LLM client with config-based routing and operational controls.

    Not a singleton -- instantiate with registry and secret_store references.
    Each instance owns a keyed :class:`_AsyncOpenAIPool` so repeated calls
    reuse the same ``AsyncOpenAI`` (and therefore the underlying
    ``httpx.AsyncClient`` connection pool). Call :meth:`aclose` on the
    instance at worker/API shutdown to close every pooled connection --
    without that the TLS pool leaks on process teardown (#44).
    """

    def __init__(
        self,
        registry: ConfigRegistry,
        secret_store: SecretStore,
    ) -> None:
        self._config = LLMConfigProvider(registry=registry, secret_store=secret_store)
        self._pipeline = PipelineRunner(config_provider=self._config)
        self.cost_tracker: Any = None  # Set by builder.py to CostTracker instance
        self.bus: Any = None  # DomainEventBus; wired to default_bus() by builder.py (None in bare/test construction)
        # #44: reuse AsyncOpenAI clients across calls instead of building (and
        # leaking) a fresh one per request. Closed via :meth:`aclose` from the
        # worker/API shutdown hooks so the TLS pool does not survive teardown.
        self._client_pool = _AsyncOpenAIPool()

    async def aclose(self) -> None:
        """Close the pooled ``AsyncOpenAI`` clients (#44).

        Safe to call more than once (subsequent calls close nothing) and
        safe to skip in tests that never issued a real call (the pool is
        empty). Wired into ``WorkerSettings.on_shutdown`` and the API
        lifespan shutdown so the underlying ``httpx.AsyncClient``
        connection pool releases its file descriptors and TLS sessions
        instead of leaking until process exit.
        """
        await self._client_pool.aclose()

    @property
    def pipeline(self) -> PipelineRunner:
        """Access pipeline for step registration at platform startup."""
        return self._pipeline

    async def resolve_model(self, task_type: str) -> str:
        """Resolve the model id this client would route ``task_type`` to.

        Delegates to :meth:`LLMConfigProvider.resolve_model` (same routing,
        drift-bias, and fallback logic the chat path uses) so a caller that
        needs the routed model BEFORE the call -- e.g. RFC-09 model-family
        prompt selection -- sees exactly what the turn will run on.
        """
        return await self._config.resolve_model(task_type)

    # ----- async primary API -----

    async def chat(
        self,
        task_type: str,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None = None,
        run_id: str | None = None,
        team_id: str | None = None,
        max_output_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a chat completion request and return text response.

        Args:
            task_type: Routing key (e.g. "scoring") -- resolved to model_id via config.
            messages: OpenAI-format message list.
            tools: Optional list of tool definitions (OpenAI function-calling format).
            tool_executor: Async callable(tool_name, arguments) -> result_string.
                Required when tools is provided.
            run_id: Optional run identifier for cost tracking and budget enforcement.
            team_id: Optional team identifier for cost record scoping (Phase 175).

        Returns:
            LLMResponse with content, model, usage, and finish_reason.

        Raises:
            LLMError: On permanent API errors or configuration issues.
            BudgetExceededError: If budget ceiling exceeded for the run.
        """
        if await self._config.is_disabled():
            return LLMResponse(
                content="LLM disabled by operator",
                disabled=True,
            )

        routing = await self._config.resolve_routing(task_type)
        # §309 -- narrow the routing max_tokens to a per-call ceiling when the
        # caller supplies one; never raise above the operator-configured cap.
        if max_output_tokens is not None and max_output_tokens > 0:
            from dataclasses import replace as _dc_replace
            effective_max = min(int(max_output_tokens), int(routing.max_tokens))
            if effective_max != routing.max_tokens:
                routing = _dc_replace(routing, max_tokens=effective_max)

        with gen_ai_span(
            GEN_AI_OPERATION_CHAT,
            model=routing.model_id,
            task_type=task_type,
            run_id=run_id,
        ) as _span:
            response = await self._call_with_retry(
                routing=routing,
                messages=messages,
                response_format=None,
                tools=tools,
                tool_executor=tool_executor,
                run_id=run_id,
                team_id=team_id,
            )
            _annotate_llm_span(_span, response, routing.model_id)
            return response

    async def chat_json(
        self,
        task_type: str,
        messages: list[dict[str, Any]],
        schema: dict[str, Any],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None = None,
        run_id: str | None = None,
        team_id: str | None = None,
        max_output_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a chat request with JSON schema enforcement.

        Uses OpenAI structured output (json_schema strict mode).  If the model
        does not support strict mode, falls back to client-side parse+validate
        (per D-10 / LLM-06).

        Args:
            task_type: Routing key.
            messages: OpenAI-format message list.
            schema: JSON Schema dict for the expected response shape.
            tools: Optional tool definitions.
            tool_executor: Async tool executor callable.
            run_id: Optional run identifier for cost tracking and budget enforcement.
            team_id: Optional team identifier for cost record scoping (Phase 175).
            max_output_tokens: Optional per-call cap on completion tokens
                that overrides ``routing.max_tokens``. fix §309 -- callers
                with a known-bounded JSON response shape (e.g. PoC
                drafts capped at ~1500 tokens of code + rationale) can
                pass a tight ceiling so a runaway model can't burn 8k
                tokens producing pages of commentary outside the
                schema. None preserves the routing-resolved default.

        Returns:
            LLMResponse where content is a JSON string matching the schema.

        Raises:
            LLMError: On permanent errors, validation failure after fallback, or truncation.
            BudgetExceededError: If budget ceiling exceeded for the run.
        """
        if await self._config.is_disabled():
            return LLMResponse(
                content="LLM disabled by operator",
                disabled=True,
            )

        routing = await self._config.resolve_routing(task_type)
        # fix §309 -- apply per-call ceiling by cloning the frozen
        # LLMRouting dataclass with the smaller max_tokens. Never raise
        # above the routing-resolved cap (operator's configured ceiling
        # is authoritative); only narrow it.
        if max_output_tokens is not None and max_output_tokens > 0:
            from dataclasses import replace as _dc_replace
            effective_max = min(int(max_output_tokens), int(routing.max_tokens))
            if effective_max != routing.max_tokens:
                routing = _dc_replace(routing, max_tokens=effective_max)

        # Try strict json_schema first. Lenient providers accept and enforce it
        # even for schemas with free-form dict fields (observables / payload /
        # edit_patches), producing conforming output. Strict OpenAI-compatible
        # providers reject such a schema outright; only then fall back to
        # json_object mode (shape guided by the system prompt, validated
        # client-side). Falling back unconditionally would discard provider-side
        # enforcement on lenient providers and let weak models emit
        # non-conforming JSON that fails the client parse.
        response_format: dict[str, Any] = {
            "type": "json_schema",
            "json_schema": {
                "name": schema.get("title", "response"),
                "strict": True,
                "schema": _make_strict_schema(schema),
            },
        }
        with gen_ai_span(
            GEN_AI_OPERATION_CHAT,
            model=routing.model_id,
            task_type=task_type,
            run_id=run_id,
            attributes={"gen_ai.request.response_format": "json_schema"},
        ) as _span:
            try:
                resp = await self._call_with_retry(
                    routing=routing,
                    messages=messages,
                    response_format=response_format,
                    tools=tools,
                    tool_executor=tool_executor,
                    run_id=run_id,
                    team_id=team_id,
                )
            except LLMError as exc:
                if not (_schema_has_open_object(schema) and _is_strict_schema_rejection(exc)):
                    raise
                logger.warning(
                    "chat_json: provider rejected strict json_schema (%s) -- "
                    "retrying in json_object mode",
                    str(exc)[:160],
                )
                _span.set_attribute("aila.chat_json.fallback", "json_object")
                # json_object mode has no provider-side enforcement, so a weak model
                # emits non-conforming JSON that fails the client parse. Append the
                # schema to the prompt so the model still has the exact field names,
                # enum values, and required set.
                schema_hint = {
                    "role": "system",
                    "content": (
                        "Respond with a SINGLE JSON object that conforms exactly to "
                        "this JSON schema. Include every required field and use the "
                        "exact field names and enum values. Emit only the JSON "
                        "object, no prose and no code fences.\n"
                        + json.dumps(schema)
                    ),
                }
                resp = await self._call_with_retry(
                    routing=routing,
                    messages=[*messages, schema_hint],
                    response_format={"type": "json_object"},
                    tools=tools,
                    tool_executor=tool_executor,
                    run_id=run_id,
                    team_id=team_id,
                )
            # Some upstream routers (OmniRoute via Anthropic Claude) wrap structured
            # output in Markdown code fences despite response_format=json_schema.
            # Strip fences so downstream json.loads() never chokes on ```json\n...\n```
            if resp.content:
                from dataclasses import replace as _dc_replace
                resp = _dc_replace(resp, content=_strip_json_fences(resp.content))
            _annotate_llm_span(_span, resp, routing.model_id)
            return resp

    async def chat_structured(
        self,
        task_type: str,
        messages: list[dict[str, Any]],
        model_class: type[BaseModel],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None = None,
        run_id: str | None = None,
        team_id: str | None = None,
        max_output_tokens: int | None = None,
    ) -> LLMResponse:
        """Send a chat request and return a validated Pydantic model instance.

        Convenience wrapper around chat_json() that:
        1. Generates JSON schema from the Pydantic model class
        2. Calls chat_json() with that schema
        3. Parses and validates the response into a model instance
        4. Returns LLMResponse with valid JSON as .content

        On parse or schema-validation failure, retries with an escalating
        correction prompt bounded by the
        ``platform.llm_structured_json_max_attempts`` config knob (env
        override ``AILA_PLATFORM_LLMstructured_json_max_attempts``,
        default 3 total attempts, resolved through ConfigRegistry so
        ``PUT /config`` lands on the next call -- fix #132). Every retry after the first embeds the verbatim
        pydantic ``ValidationError`` text and, when the model at least
        produced parseable JSON, the extracted partial payload -- so the
        model sees exactly which field is wrong instead of a generic
        "try again with the schema" nudge.

        Args:
            task_type: Routing key.
            messages: OpenAI-format message list.
            model_class: Pydantic BaseModel subclass to validate against.
            tools: Optional tool definitions.
            tool_executor: Async tool executor callable.
            run_id: Optional run identifier for cost tracking and budget enforcement.
            team_id: Optional team identifier for cost record scoping (Phase 175).
            max_output_tokens: Optional per-call cap on completion tokens
                (passed through to chat_json; never raises above the
                routing-resolved cap). fix \u00a7309.

        Returns:
            LLMResponse where content is valid JSON.

        Raises:
            LLMError: On permanent errors or validation failure after every
                attempt in the bounded correction loop.
            LLMCancelledError: If the run was cancelled between correction
                attempts (#44).
            BudgetExceededError: If budget ceiling exceeded for the run.
        """
        schema = model_class.model_json_schema()
        accumulated_usage: dict[str, int] = {}
        prior_content: str = ""
        prior_error_text: str = ""
        prior_partial_json: str | None = None

        # fix #132 -- resolve the budget through ConfigRegistry so
        # PUT /config lands on the next call, and hoist to a local so
        # every log line + terminal raise reports the SAME cap the
        # loop iterated (a mid-call registry mutation cannot desync
        # the reported cap from the actual iteration count).
        structured_json_max_attempts = _resolve_structured_json_max_attempts()

        # Resolve model up-front for the span attribute; chat_json will
        # resolve it again per attempt but that lookup is cached and
        # cheap. The span here is the parent for every correction
        # attempt so total accumulated usage lands on ONE record.
        _routing = await self._config.resolve_routing(task_type)
        with gen_ai_span(
            GEN_AI_OPERATION_CHAT,
            model=_routing.model_id,
            task_type=task_type,
            run_id=run_id,
            attributes={
                "gen_ai.request.response_format": "json_schema",
                "aila.chat_structured.model_class": model_class.__name__,
                "aila.chat_structured.max_attempts": structured_json_max_attempts,
            },
        ) as _structured_span:
            for attempt in range(structured_json_max_attempts):
                # #44: cancellation peek between correction attempts. chat_json's
                # own retry loop honours the token too; this catches a cancel
                # that flipped between the previous correction call and the
                # next one so the run does not burn a fresh provider round-trip.
                if run_id is not None and is_run_cancelled(run_id):
                    raise LLMCancelledError(
                        f"run {run_id} cancelled during chat_structured "
                        f"(attempt {attempt + 1}/{structured_json_max_attempts})"
                    )

                if attempt == 0:
                    attempt_messages = messages
                else:
                    partial_block = (
                        f"\n\nYour extracted JSON before validation was:\n{prior_partial_json}"
                        if prior_partial_json else ""
                    )
                    correction = (
                        f"Your previous response failed to produce a valid "
                        f"instance of {model_class.__name__}.\n\n"
                        f"Validation error (verbatim):\n{prior_error_text}"
                        f"{partial_block}\n\n"
                        f"Respond with ONLY valid JSON matching this schema:\n"
                        f"{json.dumps(schema, indent=2)}"
                    )
                    attempt_messages = list(messages) + [
                        {"role": "assistant", "content": prior_content},
                        {"role": "user", "content": correction},
                    ]

                response = await self.chat_json(
                    task_type,
                    attempt_messages,
                    schema,
                    tools=tools,
                    tool_executor=tool_executor,
                    run_id=run_id,
                    team_id=team_id,
                    max_output_tokens=max_output_tokens,
                )

                if response.disabled:
                    return response

                accumulated_usage = (
                    _merge_usage(accumulated_usage, response.usage)
                    if accumulated_usage else response.usage
                )

                parsed, error_text, partial_json = self._parse_model_verbose(
                    response.content, model_class
                )
                if parsed is not None:
                    _structured_span.set_attribute(
                        "aila.chat_structured.attempts", attempt + 1
                    )
                    final = LLMResponse(
                        content=parsed.model_dump_json(),
                        model=response.model,
                        usage=accumulated_usage,
                        disabled=False,
                        finish_reason=response.finish_reason,
                    )
                    _annotate_llm_span(_structured_span, final, _routing.model_id)
                    return final

                logger.warning(
                    "chat_structured: attempt %d/%d failed for %s -- %s",
                    attempt + 1, structured_json_max_attempts, model_class.__name__,
                    (error_text or "unparseable").replace("\n", " | ")[:400],
                )

                prior_content = response.content
                prior_error_text = error_text or "response was not valid JSON matching the schema"
                prior_partial_json = partial_json

            raise LLMError(
                f"Failed to parse LLM response into {model_class.__name__} "
                f"after {structured_json_max_attempts} attempts",
                retryable=False,
            )

    # ----- sync wrappers (per D-03) -----

    def chat_sync(
        self,
        task_type: str,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None = None,
        run_id: str | None = None,
        team_id: str | None = None,
    ) -> LLMResponse:
        """Synchronous wrapper for chat(). Uses asyncio.run().

        CLI-only. Do not call from async context.
        Not for use inside an event loop.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            raise RuntimeError(
                "chat_sync() is a CLI-only sync wrapper. "
                "Use await self.chat() from async context."
            )
        return asyncio.run(self.chat(task_type, messages, tools=tools, tool_executor=tool_executor, run_id=run_id, team_id=team_id))

    def chat_json_sync(
        self,
        task_type: str,
        messages: list[dict[str, Any]],
        schema: dict[str, Any],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None = None,
        run_id: str | None = None,
        team_id: str | None = None,
    ) -> LLMResponse:
        """Synchronous wrapper for chat_json(). Uses asyncio.run().

        CLI-only. Do not call from async context.
        Not for use inside an event loop.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            raise RuntimeError(
                "chat_json_sync() is a CLI-only sync wrapper. "
                "Use await self.model.chat_json() from async context."
            )
        return asyncio.run(self.chat_json(task_type, messages, schema, tools=tools, tool_executor=tool_executor, run_id=run_id, team_id=team_id))

    def chat_structured_sync(
        self,
        task_type: str,
        messages: list[dict[str, Any]],
        model_class: type[BaseModel],
        *,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None = None,
        run_id: str | None = None,
        team_id: str | None = None,
    ) -> LLMResponse:
        """Synchronous wrapper for chat_structured(). Uses asyncio.run().

        CLI-only. Do not call from async context.
        Not for use inside an event loop.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is not None:
            raise RuntimeError(
                "chat_structured_sync() is a CLI-only sync wrapper. "
                "Use await self.model.chat_structured() from async context."
            )
        return asyncio.run(self.chat_structured(task_type, messages, model_class, tools=tools, tool_executor=tool_executor, run_id=run_id, team_id=team_id))

    # ----- internal -----

    async def _call_with_retry(
        self,
        *,
        routing: Any,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None,
        tools: list[dict[str, Any]] | None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None,
        run_id: str | None = None,
        team_id: str | None = None,
    ) -> LLMResponse:
        """Execute API call with retry for transient errors.

        The OpenAI SDK has built-in retry, but we add our own layer with
        logging for observability (per D-09).

        Budget check runs BEFORE the retry loop (per Pitfall 5).
        Cost recording runs AFTER each successful call.

        Transient errors: APIConnectionError, APITimeoutError, RateLimitError.
        Everything else is permanent and surfaces immediately.
        """
        # Budget check BEFORE retry loop (Phase 122)
        if self.cost_tracker is not None and run_id is not None:
            await self.cost_tracker.check_budget_async(run_id, routing.task_type)

        # Capture call start time for duration reporting (Phase 175 / D-05)
        _call_start = _time_mod.perf_counter()

        # Per-task timeout: OmniRoute fronts real provider models which can take
        # >60s on a large prompt (observed: 7.5k-char forensic prompts timing
        # out on cc/claude-sonnet-4-6). Default 180s; resolved live through
        # ConfigRegistry (fix #132) so PUT /config/platform/llm_timeout_seconds
        # lands on the next call.
        _timeout_s = _resolve_llm_timeout_seconds()
        client = self._client_pool.get(
            api_key=routing.api_key,
            base_url=routing.base_url,
            timeout_s=_timeout_s,
        )

        # These were module-level constants before fix #132 hoisted them
        # into ConfigRegistry. Locals now, resolved once at call start so
        # every log line / terminal raise reports the SAME cap the loop
        # iterated (a mid-call registry mutation cannot desync the
        # reported cap from the actual iteration count).
        max_retries, retry_base_delay, retry_max_delay = _resolve_retry_budget()

        last_error: Exception | None = None
        # #44: per-attempt idempotency state. Recreated on every retry so
        # attempt N never sees attempt N-1's counter. `_tool_loop`
        # increments ``tools_committed`` after every executor call, and
        # the exception handlers below downgrade any post-tool failure to
        # non-retryable so the outer loop does not replay the tool_loop
        # against the same investigation and duplicate side effects.
        call_state = _CallState()

        for attempt in range(max_retries):
            # #44: abort promptly if the run was cancelled mid-retry. An
            # investigation keys its cancellation token on run_id
            # (== investigation_id) and creates it at the turn-boundary check
            # before this call runs, so the peek sees it here. Non-
            # investigation run_ids have no token, so this is a no-op for them
            # and does not fabricate one. Without this, a pause during a long
            # provider-outage backoff waits out the full retry schedule before
            # the next turn-boundary poll notices the cancellation.
            if run_id is not None and is_run_cancelled(run_id):
                raise LLMCancelledError(
                    f"run {run_id} cancelled during LLM retry (attempt {attempt + 1})"
                )
            # Reset per-attempt idempotency state at the top of each retry
            # iteration so a fresh attempt starts with no committed side
            # effects. The prior attempt either succeeded (already returned)
            # or raised while ``tools_committed == 0`` (see the exception
            # branches below).
            call_state = _CallState()
            try:
                response, ctx = await self._pipeline.run(
                    task_type=routing.task_type,
                    messages=messages,
                    routing=routing,
                    call_fn=self._single_call,
                    call_kwargs={
                        "client": client,
                        "routing": routing,
                        "messages": messages,
                        "response_format": response_format,
                        "tools": tools,
                        "tool_executor": tool_executor,
                        "run_id": run_id,
                        "call_state": call_state,
                    },
                    run_id=run_id or "",
                    team_id=team_id or "",
                )
                # Cost recording AFTER successful call (Phase 122)
                if self.cost_tracker is not None:
                    self.cost_tracker.record(run_id, response.usage)
                    # #155: fold provider-reported cache-token fields into
                    # RunMemory so the /cost/runs/{run_id} surface can
                    # report the cache-hit-rate gauge. Best-effort; the
                    # helper swallows RunMemory backend errors at DEBUG.
                    from aila.platform.llm.prompt_layout import (
                        record_cache_metrics as _record_cache_metrics,
                    )
                    _record_cache_metrics(
                        getattr(self.cost_tracker, "_mem", None),
                        run_id,
                        response.usage,
                    )

                # --- Durable cost recording (Phase 175 / D-05) ---
                _cost_usd = 0.0
                _pricing_configured = False
                _prompt_tokens = response.usage.get("prompt_tokens", 0)
                _completion_tokens = response.usage.get("completion_tokens", 0)
                _call_duration = _time_mod.perf_counter() - _call_start

                # Step 1: Calculate dollar cost (separate try/except)
                try:
                    from aila.platform.llm.cost import calculate_cost_usd
                    _cost_usd, _pricing_configured = await calculate_cost_usd(
                        routing.model_id, _prompt_tokens, _completion_tokens,
                        self._config._registry,  # LLMConfigProvider._registry is ConfigRegistry
                    )
                except _COST_TELEMETRY_ERRORS:
                    import structlog
                    structlog.get_logger(__name__).warning(
                        "cost_calculation_failed", run_id=run_id, model=routing.model_id,
                    )

                # Step 2: Persist to DB (separate try/except, runs even if calculation failed)
                # registry passed so persist_cost_record can trigger budget check (Phase 175 / D-03)
                try:
                    from aila.platform.llm.cost import persist_cost_record
                    # Plan 176e: capture truncated prompt/response + duration for
                    # the admin LLM interaction log. Join only the last user
                    # message so we don't mirror the full system prompt, and
                    # gracefully handle non-string content lists (OpenAI tool
                    # messages) by ignoring them for preview purposes.
                    _last_user_text: str | None = None
                    for _msg in reversed(messages):
                        if not isinstance(_msg, dict):
                            continue
                        if _msg.get("role") == "user":
                            _content = _msg.get("content")
                            if isinstance(_content, str):
                                _last_user_text = _content
                                break
                    _response_text: str | None = None
                    try:
                        _response_text = response.content if isinstance(response.content, str) else None
                    except AttributeError:
                        _response_text = None
                    await persist_cost_record(
                        run_id=run_id,
                        model_id=routing.model_id,
                        task_type=routing.task_type,
                        team_id=team_id,
                        prompt_tokens=_prompt_tokens,
                        completion_tokens=_completion_tokens,
                        cost_usd=_cost_usd,
                        registry=self._config._registry,  # LLMConfigProvider._registry is ConfigRegistry
                        prompt_preview=_last_user_text,
                        response_preview=_response_text,
                        duration_ms=int(_call_duration * 1000),
                        status="ok",
                    )
                except _COST_TELEMETRY_ERRORS:
                    import structlog
                    structlog.get_logger(__name__).warning(
                        "cost_persistence_failed", run_id=run_id, model=routing.model_id,
                    )

                # #39 replay-grade capture: LLMCostRecord stores only 200-char
                # previews, which is enough for the operator interaction list
                # but insufficient to REPLAY a turn. Persist the assembled
                # prompt messages (with any tools spec) and the full response
                # body to the hash-chained platform journal under
                # kind="llm_prompt"/"llm_response". Correlation ids join the
                # rows back to the same investigation/branch/turn as the cost
                # record. Best-effort: replay-trail failure never blocks the
                # LLM call path (record_llm_call_bodies absorbs its own
                # errors and warns).
                try:
                    from aila.platform.services.replay import record_llm_call_bodies

                    await record_llm_call_bodies(
                        run_id=run_id,
                        model_id=routing.model_id,
                        task_type=routing.task_type,
                        team_id=team_id,
                        messages=messages,
                        tools=tools,
                        response_text=_response_text,
                        usage=response.usage,
                        duration_ms=int(_call_duration * 1000),
                        status="ok",
                    )
                except _COST_TELEMETRY_ERRORS:
                    import structlog
                    structlog.get_logger(__name__).warning(
                        "llm_replay_capture_failed",
                        run_id=run_id,
                        model=routing.model_id,
                    )

                # Step 3: Missing pricing warning (separate try/except)
                if not _pricing_configured:
                    try:
                        from aila.platform.llm.cost import emit_missing_pricing_notification
                        await emit_missing_pricing_notification(routing.model_id)
                    except _COST_TELEMETRY_ERRORS:
                        pass  # emit_missing_pricing_notification already swallows; belt-and-suspenders

                # Step 4: Prometheus counter (separate try/except)
                try:
                    from aila.api.metrics import LLM_COST_TOTAL
                    LLM_COST_TOTAL.labels(model=routing.model_id).inc(_cost_usd)
                except _COST_TELEMETRY_ERRORS as exc:
                    # Prometheus counter is best-effort telemetry; never fail the LLM call
                    # because metrics emission failed.
                    logger.debug("LLM cost counter update failed: %s", exc)

                # Step 5: Domain event with real duration (separate try/except)
                try:
                    from aila.platform.events.domain_events import LlmCallCompleted, LlmCallCompletedPayload
                    if self.bus is not None:
                        self.bus.publish(LlmCallCompleted(
                            team_id=team_id,
                            payload=LlmCallCompletedPayload(
                                model=routing.model_id,
                                tokens=_prompt_tokens + _completion_tokens,
                                cost=_cost_usd,
                                duration=_call_duration,
                            ),
                        ))
                except _COST_TELEMETRY_ERRORS:
                    pass

                _record_llm_ok(routing.base_url)
                return _enrich_response(response, ctx)
            except LLMCancelledError:
                # Cancellation surfaces from the tool loop (turn-boundary
                # cancel between tool steps). Propagate as-is: the engine's
                # state handler treats this exit as clean.
                raise
            except RateLimitError as exc:
                # Honour Retry-After when the provider tells us how
                # long to wait. NVIDIA NIM, OpenRouter, OpenAI all send
                # this header on 429s -- it's the most accurate delay we
                # can pick. Fallback to exponential backoff (capped at
                # retry_max_delay) when the header is missing.
                _record_llm_error(routing.base_url, kind="http_5xx")
                if self._commit_gate_blocks_retry(
                    call_state, exc, attempt, routing.model_id
                ):
                    raise self._wrap_non_retryable_after_commit(exc, call_state) from exc
                last_error = exc
                retry_after_s: float | None = None
                resp = getattr(exc, "response", None)
                headers = getattr(resp, "headers", None) if resp is not None else None
                if headers is not None:
                    raw = headers.get("Retry-After") or headers.get("retry-after")
                    if raw is not None:
                        try:
                            retry_after_s = float(raw)
                        except (TypeError, ValueError):
                            retry_after_s = None
                if retry_after_s is not None:
                    delay = min(max(retry_after_s, 0.1), retry_max_delay)
                else:
                    delay = min(retry_base_delay * (2 ** attempt), retry_max_delay)
                logger.warning(
                    "LLM rate-limit (attempt %d/%d): %s -- retrying in %.1fs "
                    "(retry_after_hdr=%s)",
                    attempt + 1,
                    max_retries,
                    type(exc).__name__,
                    delay,
                    retry_after_s,
                )
                await asyncio.sleep(delay)
            except (APIConnectionError, APITimeoutError) as exc:
                _kind = (
                    "timeout" if isinstance(exc, APITimeoutError)
                    else "connect_refused"
                )
                _record_llm_error(routing.base_url, kind=_kind)
                if self._commit_gate_blocks_retry(
                    call_state, exc, attempt, routing.model_id
                ):
                    raise self._wrap_non_retryable_after_commit(exc, call_state) from exc
                last_error = exc
                delay = min(retry_base_delay * (2 ** attempt), retry_max_delay)
                logger.warning(
                    "LLM transient error (attempt %d/%d): %s -- retrying in %.1fs",
                    attempt + 1,
                    max_retries,
                    type(exc).__name__,
                    delay,
                )
                await asyncio.sleep(delay)
            except LLMError as exc:
                if exc.retryable:
                    _record_llm_error(routing.base_url, kind="unknown")
                    if self._commit_gate_blocks_retry(
                        call_state, exc, attempt, routing.model_id
                    ):
                        raise self._wrap_non_retryable_after_commit(exc, call_state) from exc
                    last_error = exc
                    delay = min(retry_base_delay * (2 ** attempt), retry_max_delay)
                    logger.warning(
                        "LLM retryable error (attempt %d/%d): %s -- retrying in %.1fs",
                        attempt + 1,
                        max_retries,
                        exc.message,
                        delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    # Non-retryable LLM errors (ClassificationBlockedError, etc.)
                    raise
            except LLMCancelledError:
                # #44: a cancellation surfaced from inside the pipeline or
                # provider call (not only the pre-attempt peek above) must
                # propagate untouched -- never classified, wrapped, or
                # retried. Guarded here so the broad classifier below can
                # safely catch every provider exception.
                raise
            except Exception as exc:
                # Two-branch classification (issue #44 -- retry reliability):
                # non-retryable provider errors (HTTP 4xx auth/malformed:
                # 400/401/403/404/422) fail fast so a doomed request does not
                # burn the retry budget or block the worker on backoff sleeps.
                # Retryable failures (429, 5xx, connection reset, timeout,
                # DNS) keep the historical retry+backoff behaviour. The catch
                # is broad by design: third-party provider SDKs (Anthropic,
                # Vertex, self-hosted proxies) raise their own exception
                # classes that only carry a status_code attribute, so
                # _is_retryable falls back to that attribute rather than an
                # SDK-specific type. A narrower tuple dropped these agnostic
                # exceptions on the floor (a 503 propagated raw instead of
                # retrying). LLMCancelledError is re-raised by the guard
                # above and asyncio.CancelledError is a BaseException, so
                # neither is swallowed here.
                # Best-effort classification: infer http_5xx from an
                # HTTP status attribute when present so the router
                # tags the failure with a useful label; fall back to
                # ``unknown`` for the general leak set.
                _status = getattr(exc, "status_code", None)
                _kind = (
                    "http_5xx"
                    if isinstance(_status, int) and 500 <= _status < 600
                    else "unknown"
                )
                _record_llm_error(routing.base_url, kind=_kind)
                # Deferred import: aila.platform.services.__init__ pulls in
                # ServiceFactory, which imports back into aila.platform.llm.
                # Loading redact_secrets at runtime sidesteps the cycle.
                from ..services.log_redact import redact_secrets
                if not _is_retryable(exc):
                    status = getattr(exc, "status_code", None)
                    logger.warning(
                        "LLM non-retryable provider error: %s (status=%s): %s -- failing fast",
                        type(exc).__name__,
                        status,
                        redact_secrets(str(exc))[:200],
                    )
                    raise LLMError(
                        f"LLM non-retryable provider error: {type(exc).__name__}: "
                        f"{redact_secrets(str(exc))}",
                        retryable=False,
                    ) from exc
                if self._commit_gate_blocks_retry(
                    call_state, exc, attempt, routing.model_id
                ):
                    raise self._wrap_non_retryable_after_commit(exc, call_state) from exc
                last_error = exc
                delay = min(retry_base_delay * (2 ** attempt), retry_max_delay)
                logger.warning(
                    "LLM provider error (attempt %d/%d): %s: %s -- retrying in %.1fs",
                    attempt + 1,
                    max_retries,
                    type(exc).__name__,
                    redact_secrets(str(exc))[:200],
                    delay,
                )
                await asyncio.sleep(delay)

        # Deferred import: see the provider-error branch above for why
        # redact_secrets is imported at runtime rather than at module load.
        from ..services.log_redact import redact_secrets
        raise LLMError(
            f"LLM API failed after {max_retries} retries: "
            f"{redact_secrets(str(last_error))}",
            retryable=True,
        )

    @staticmethod
    def _commit_gate_blocks_retry(
        call_state: _CallState,
        exc: BaseException,
        attempt: int,
        model_id: str,
    ) -> bool:
        """Decide whether an exception at retry-attempt ``attempt`` may retry (#44).

        Retrying is prohibited the moment ``call_state.tools_committed > 0``:
        replaying the outer call rewinds to the first LLM turn, which
        re-executes whatever tool_calls the model produces on that turn,
        which duplicates MCP mutations / audit events / observables against
        the same investigation. Callers translate a True return into a
        non-retryable :class:`LLMError` via
        :meth:`_wrap_non_retryable_after_commit` so the outer engine sees
        a clean fail-fast and can decide (via cursor SSOT) whether the
        whole task is retried at the queue layer.
        """
        if call_state.tools_committed <= 0:
            return False
        logger.warning(
            "LLM idempotency guard: %d tool call(s) already committed in "
            "attempt %d (model=%s, error=%s) -- refusing to replay the tool "
            "loop; failing fast",
            call_state.tools_committed,
            attempt + 1,
            model_id,
            type(exc).__name__,
        )
        return True

    @staticmethod
    def _wrap_non_retryable_after_commit(
        exc: BaseException, call_state: _CallState,
    ) -> LLMError:
        """Build the non-retryable :class:`LLMError` raised when a retry is
        blocked by :meth:`_commit_gate_blocks_retry`.

        ``retryable=False`` deliberately -- the tool loop's side effects
        already committed, so replaying the outer call would duplicate
        them. The queue layer can still restart the whole task via ARQ
        job retry + workflow cursor SSOT if it wants to, but that path
        replays messages fresh (no cached model output), which is the
        correct recovery shape.
        """
        return LLMError(
            f"LLM call failed after {call_state.tools_committed} tool call(s) "
            f"already committed side effects: {type(exc).__name__}: {exc}",
            retryable=False,
        )

    async def _inner_call(
        self,
        *,
        routing: Any,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None = None,
        tools: list[dict[str, Any]] | None = None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None = None,
        run_id: str | None = None,
        team_id: str | None = None,
    ) -> LLMResponse:
        """Execute one API call WITHOUT pipeline recursion.

        Used by gate consensus retries (§101) and verify second-model
        calls (§100) -- both must bypass the pipeline (would recurse into
        themselves) but still accumulate cost against the operator's
        run budget. Previously each step constructed its own
        ``AsyncOpenAI`` directly and the tokens were invisible to the
        cost tracker / persist_cost_record / Prometheus pipeline. Now
        the platform builds the inner client the same way
        :meth:`_call_with_retry` does and records the same cost ledger.

        Pipeline recursion is avoided structurally -- we call
        :meth:`_single_call` directly instead of routing through
        :class:`PipelineRunner`.
        """
        # #38-3.2: budget check BEFORE the provider call, mirroring the
        # pre-flight in :meth:`_call_with_retry` above (see :~810). Consensus
        # (gate.py) and verify (verify.py) retries route their token spend
        # through this method; without the seed, a run that already exceeded
        # its ceiling still spent on every retry because the check only ran
        # once on the primary path. check_budget_async seeds the in-memory
        # totals from the durable ledger and raises BudgetExceededError when
        # the per-run token ceiling is already crossed -- fail fast, no spend.
        if self.cost_tracker is not None and run_id is not None:
            await self.cost_tracker.check_budget_async(run_id, routing.task_type)

        # fix #132 -- ConfigRegistry-backed HTTP timeout (see essay above).
        _timeout_s = _resolve_llm_timeout_seconds()
        client = self._client_pool.get(
            api_key=routing.api_key,
            base_url=routing.base_url,
            timeout_s=_timeout_s,
        )
        _call_start = _time_mod.perf_counter()
        response = await self._single_call(
            client=client,
            routing=routing,
            messages=messages,
            response_format=response_format,
            tools=tools,
            tool_executor=tool_executor,
        )

        # Cost recording -- same shape as :meth:`_call_with_retry` so
        # consensus / verify tokens land in the same per-run budget
        # and the operator's spend reports tell the truth (fix §100).
        try:
            if self.cost_tracker is not None:
                self.cost_tracker.record(run_id, response.usage)
                # #155: mirror the /_call_with_retry/ cache-metrics
                # fold so consensus / verify calls contribute to the
                # per-run cache-hit-rate gauge too.
                from aila.platform.llm.prompt_layout import (
                    record_cache_metrics as _record_cache_metrics,
                )
                _record_cache_metrics(
                    getattr(self.cost_tracker, "_mem", None),
                    run_id,
                    response.usage,
                )
        except Exception as exc:
            logger.debug("inner_call cost_tracker.record failed: %s", exc)

        try:
            from aila.platform.llm.cost import (
                calculate_cost_usd,
                persist_cost_record,
            )
            _prompt_tokens = response.usage.get("prompt_tokens", 0)
            _completion_tokens = response.usage.get("completion_tokens", 0)
            _cost_usd, _ = await calculate_cost_usd(
                routing.model_id, _prompt_tokens, _completion_tokens,
                self._config._registry,
            )
            _duration_ms = int(
                (_time_mod.perf_counter() - _call_start) * 1000,
            )
            await persist_cost_record(
                run_id=run_id,
                model_id=routing.model_id,
                task_type=routing.task_type,
                team_id=team_id,
                prompt_tokens=_prompt_tokens,
                completion_tokens=_completion_tokens,
                cost_usd=_cost_usd,
                registry=self._config._registry,
                prompt_preview=None,
                response_preview=(
                    response.content
                    if isinstance(response.content, str) else None
                ),
                duration_ms=_duration_ms,
                status="ok",
            )
        except (
            ValueError, sqlalchemy.exc.SQLAlchemyError, AttributeError,
        ) as exc:
            logger.debug(
                "inner_call cost persistence failed: %s",
                exc,
            )

        return response

    async def _single_call(
        self,
        *,
        client: AsyncOpenAI,
        routing: Any,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None,
        tools: list[dict[str, Any]] | None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None,
        run_id: str | None = None,
        call_state: _CallState | None = None,
    ) -> LLMResponse:
        """Execute a single API call, with optional tool loop.

        When tools are provided and the model responds with tool_calls,
        executes the tool loop up to routing.max_tool_steps iterations.

        ``run_id`` and ``call_state`` are threaded through to :meth:`_tool_loop`
        so the loop can (a) honour a mid-turn cancellation between tool steps
        and (b) mark side-effect commitment for the outer
        :meth:`_call_with_retry` idempotency guard (#44). Both default to None
        for callers that bypass the pipeline (``_inner_call``), where no
        outer-loop retry exists and side-effect replay is not a concern.
        """
        kwargs: dict[str, Any] = {
            "model": routing.model_id,
            "messages": messages,
            "max_tokens": routing.max_tokens,
        }
        if _model_supports_temperature(routing.model_id):
            kwargs["temperature"] = routing.temperature

        if response_format is not None:
            kwargs["response_format"] = response_format

        if tools:
            kwargs["tools"] = tools

        # OBS-02: Instrument the core LLM API call with Prometheus metrics.
        from aila.api.metrics import LLM_CALL_DURATION, LLM_CALL_TOTAL, LLM_TOKENS_TOTAL

        _metrics_start = _time_mod.perf_counter()
        try:
            completion = await client.chat.completions.create(**kwargs)
        except Exception:
            _metrics_duration = _time_mod.perf_counter() - _metrics_start
            LLM_CALL_TOTAL.labels(model=routing.model_id, method="chat", status="error").inc()
            LLM_CALL_DURATION.labels(model=routing.model_id, method="chat").observe(_metrics_duration)
            raise

        _metrics_duration = _time_mod.perf_counter() - _metrics_start
        LLM_CALL_TOTAL.labels(model=routing.model_id, method="chat", status="success").inc()
        LLM_CALL_DURATION.labels(model=routing.model_id, method="chat").observe(_metrics_duration)
        if completion.usage:
            LLM_TOKENS_TOTAL.labels(model=routing.model_id, type="prompt").inc(
                completion.usage.prompt_tokens or 0
            )
            LLM_TOKENS_TOTAL.labels(model=routing.model_id, type="completion").inc(
                completion.usage.completion_tokens or 0
            )
            _emit_cache_metrics(
                routing.model_id, _extract_usage(completion),
            )

        choice = _require_choice(completion, routing.model_id)

        # Tool calling loop (per D-05-new)
        if tools and tool_executor and choice.finish_reason == "tool_calls":
            # #44: cancellation check on the boundary between the first LLM
            # turn and the tool loop. The retry-loop check ran before this
            # call; a cancellation flipped during the provider round trip
            # would otherwise proceed into tool execution and burn credits.
            if run_id is not None and is_run_cancelled(run_id):
                raise LLMCancelledError(
                    f"run {run_id} cancelled before tool loop entry"
                )
            return await self._tool_loop(
                client=client,
                routing=routing,
                messages=list(messages),
                response_format=response_format,
                tools=tools,
                tool_executor=tool_executor,
                initial_choice=choice,
                initial_usage=_extract_usage(completion),
                run_id=run_id,
                call_state=call_state,
            )

        content = choice.message.content or ""
        finish_reason = choice.finish_reason or ""
        usage = _extract_usage(completion)

        # Truncation detection (LLM-07)
        if finish_reason == "length" and response_format is not None:
            self._check_truncation(content)

        # Pydantic fallback validation (LLM-06 / D-10)
        if response_format is not None and content:
            content = self._validate_json_or_fallback(content)

        return LLMResponse(
            content=content,
            model=routing.model_id,
            usage=usage,
            disabled=False,
            finish_reason=finish_reason,
        )

    async def _tool_loop(
        self,
        *,
        client: AsyncOpenAI,
        routing: Any,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None,
        tools: list[dict[str, Any]],
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]],
        initial_choice: Any,
        initial_usage: dict[str, int],
        run_id: str | None = None,
        call_state: _CallState | None = None,
    ) -> LLMResponse:
        """Run the tool-calling loop until the model stops calling tools.

        Max iterations = routing.max_tool_steps.  If max_tool_steps is 0 or
        not set, tool calling is disabled -- returns whatever the model said.

        ``run_id`` scopes the cancellation-token peek between steps so a
        pause during a long tool chain aborts before the next tool fires
        (#44). ``call_state`` records every completed executor call so the
        outer retry loop refuses to replay tools whose side effects already
        committed against the investigation (#44).
        """
        # Deferred import mirrors the sanitize_output pattern at the
        # bottom of this file -- keeps this module free of a top-level
        # dependency on the sanitize submodules and matches the file's
        # existing PLC0415 convention.
        from .untrusted import sanitize_untrusted

        max_steps = routing.max_tool_steps
        if max_steps <= 0:
            # Tool calling disabled for this task_type
            content = initial_choice.message.content or ""
            return LLMResponse(
                content=content,
                model=routing.model_id,
                usage=initial_usage,
                disabled=False,
                finish_reason=initial_choice.finish_reason or "",
            )

        accumulated_usage = dict(initial_usage)
        choice = initial_choice

        for step in range(max_steps):
            # #44: cancellation check between tool-loop steps. The retry-loop
            # check catches a cancel before the LLM call; this check catches
            # one flipped between the response landing and the next round of
            # tool execution, so a paused investigation stops burning credits
            # and does not commit further side effects.
            if run_id is not None and is_run_cancelled(run_id):
                raise LLMCancelledError(
                    f"run {run_id} cancelled during tool loop (step {step + 1})"
                )
            # Append assistant message with tool_calls
            assistant_msg: dict[str, Any] = {
                "role": "assistant",
                "content": choice.message.content or "",
            }
            if choice.message.tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in choice.message.tool_calls
                ]
            messages.append(assistant_msg)

            # Execute each tool call
            for tc in choice.message.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {}
                logger.info(
                    "Tool call step %d: %s(%s)",
                    step + 1,
                    tc.function.name,
                    json.dumps(args, default=str)[:200],
                )
                # #44: bound each tool execution so one hung tool (e.g. an
                # audit-mcp cold build) cannot block the whole LLM turn. A
                # timeout is surfaced to the model as a domain-level tool
                # failure -- the loop continues so the model can react; the LLM
                # call is NOT retried from scratch.
                tool_timeout_s = getattr(routing, "tool_timeout_s", None) or 300.0
                try:
                    raw_result = await asyncio.wait_for(
                        tool_executor(tc.function.name, args),
                        timeout=tool_timeout_s,
                    )
                    # #43-1: tool output is third-party content (MCP bridge,
                    # HTTP, SSH). Fence-wrap it before appending to the
                    # message list so injected instructions in the payload
                    # cannot steer the next model turn -- the wrapper marks
                    # the block as quoted data and escapes any occurrence
                    # of the fence sentinel inside the payload.
                    tool_content = sanitize_untrusted(
                        str(raw_result),
                        source=f"tool:{tc.function.name}",
                    )
                except TimeoutError:
                    logger.warning(
                        "tool executor timeout: tool=%s timeout_s=%.1f",
                        tc.function.name,
                        tool_timeout_s,
                    )
                    # Platform-generated timeout notice; not third-party
                    # content, so no fence needed. From the outer retry
                    # loop's perspective a tool timeout still "committed" --
                    # a partial MCP call may have already mutated remote
                    # state, so ``call_state.tools_committed`` still ticks.
                    tool_content = json.dumps({
                        "error": "tool_timeout",
                        "tool": tc.function.name,
                        "timeout_s": tool_timeout_s,
                    })
                # #44: mark side-effect commitment so a subsequent LLM
                # failure in the same attempt cannot be retried without
                # replaying this tool. ``call_state`` is None only for
                # pipeline-bypass callers (``_inner_call`` -- gate consensus
                # / verify second-model), where the outer retry loop does
                # not run and replay is impossible by construction.
                if call_state is not None:
                    call_state.tools_committed += 1
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": tool_content,
                })

            # Call the model again
            kwargs: dict[str, Any] = {
                "model": routing.model_id,
                "messages": messages,
                "max_tokens": routing.max_tokens,
                "tools": tools,
            }
            if _model_supports_temperature(routing.model_id):
                kwargs["temperature"] = routing.temperature
            if response_format is not None:
                kwargs["response_format"] = response_format

            # OBS-02: Instrument tool-loop LLM calls with Prometheus metrics.
            from aila.api.metrics import LLM_CALL_DURATION, LLM_CALL_TOTAL, LLM_TOKENS_TOTAL

            _tl_start = _time_mod.perf_counter()
            try:
                completion = await client.chat.completions.create(**kwargs)
            except Exception:
                _tl_duration = _time_mod.perf_counter() - _tl_start
                LLM_CALL_TOTAL.labels(model=routing.model_id, method="chat", status="error").inc()
                LLM_CALL_DURATION.labels(model=routing.model_id, method="chat").observe(_tl_duration)
                raise

            _tl_duration = _time_mod.perf_counter() - _tl_start
            LLM_CALL_TOTAL.labels(model=routing.model_id, method="chat", status="success").inc()
            LLM_CALL_DURATION.labels(model=routing.model_id, method="chat").observe(_tl_duration)
            if completion.usage:
                LLM_TOKENS_TOTAL.labels(model=routing.model_id, type="prompt").inc(
                    completion.usage.prompt_tokens or 0
                )
                LLM_TOKENS_TOTAL.labels(model=routing.model_id, type="completion").inc(
                    completion.usage.completion_tokens or 0
                )

            choice = _require_choice(completion, routing.model_id)
            step_usage = _extract_usage(completion)
            accumulated_usage = _merge_usage(accumulated_usage, step_usage)
            _emit_cache_metrics(routing.model_id, step_usage)

            if choice.finish_reason != "tool_calls":
                break

        content = choice.message.content or ""
        finish_reason = choice.finish_reason or ""

        # Truncation detection (LLM-07)
        if finish_reason == "length" and response_format is not None:
            self._check_truncation(content)

        # Pydantic fallback (LLM-06)
        if response_format is not None and content:
            content = self._validate_json_or_fallback(content)

        return LLMResponse(
            content=content,
            model=routing.model_id,
            usage=accumulated_usage,
            disabled=False,
            finish_reason=finish_reason,
        )

    @staticmethod
    def _check_truncation(content: str) -> None:
        """Detect truncated JSON from max_tokens hit (LLM-07 / D-11).

        When finish_reason is "length" and we expected JSON, check if
        the content is valid JSON.  If not, it was truncated.
        """
        try:
            json.loads(content)
        except json.JSONDecodeError:
            raise LLMError(
                "LLM response was truncated (max_tokens hit) -- "
                "incomplete JSON received. Increase max_tokens for this task_type.",
                retryable=True,
            )

    @staticmethod
    def _validate_json_or_fallback(content: str) -> str:
        """Validate that *content* is JSON, with thinking-block and markdown-fence fallback (LLM-06 / D-10).

        If the model returned valid JSON, return it as-is.
        If the model wrapped JSON in <think> tags, markdown code fences, or commentary,
        strip them and extract the inner JSON.

        Returns the repaired JSON string.
        """
        return _clean_and_repair_json(content)

    @staticmethod
    def _parse_model(content: str, model_class: type[BaseModel]) -> BaseModel | None:
        """Try to parse content into a Pydantic model. Returns None on failure.

        Logs the parse failure at WARNING with the truncated content head
        and the validation error so operators see what mismatched without
        bumping the logger to DEBUG. The full content is in the LLM cost
        record's response_preview column for replay.
        """
        parsed, _, _ = AilaLLMClient._parse_model_verbose(content, model_class)
        return parsed

    @staticmethod
    def _parse_model_verbose(
        content: str,
        model_class: type[BaseModel],
    ) -> tuple[BaseModel | None, str | None, str | None]:
        """Parse ``content`` into ``model_class`` and return diagnostics on failure.

        Returns a triple ``(parsed, error_text, partial_json)``:

        * On success -- ``(model_instance, None, None)``.
        * On JSON decode failure -- ``(None, str(exc), None)``. The model
          did not even produce parseable JSON, so there is no partial to
          feed back.
        * On schema validation failure -- ``(None, str(validation_exc),
          pretty_partial_json)``. The verbatim ``ValidationError`` string
          is preserved (pydantic's own message names each failing field
          and its reason) and the extracted JSON is round-tripped through
          ``json.dumps`` so the correction prompt shows exactly what the
          model produced.

        Called by ``chat_structured``'s bounded correction loop; the
        simpler ``_parse_model`` stays for call sites that only care
        whether the response parsed.
        """
        cleaned = _clean_and_repair_json(content)
        data = None
        decode_err: Exception | None = None
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            decode_err = exc
            # Fallback: extract the first top-level JSON object or array using raw_decode
            start_obj = cleaned.find("{")
            start_arr = cleaned.find("[")
            starts = [s for s in (start_obj, start_arr) if s >= 0]
            if starts:
                start = min(starts)
                try:
                    data, _ = json.JSONDecoder().raw_decode(cleaned[start:])
                    decode_err = None
                except json.JSONDecodeError as raw_exc:
                    decode_err = raw_exc

        if data is None or decode_err is not None:
            logger.warning(
                "_parse_model_verbose: JSON decode failed for %s -- %s. head=%r",
                model_class.__name__, decode_err, content[:200],
            )
            return None, str(decode_err), None
        try:
            return model_class.model_validate(data), None, None
        except ValidationError as exc:
            logger.warning(
                "_parse_model_verbose: schema validation failed for %s -- %s",
                model_class.__name__,
                str(exc).replace("\n", " | ")[:600],
            )
            try:
                partial = json.dumps(data, indent=2, default=str)[:4000]
            except (TypeError, ValueError):
                partial = None
            return None, str(exc), partial


def _make_strict_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Recursively make a JSON schema compatible with OpenAI strict mode.

    Strict mode requires additionalProperties: false on every object and
    all properties listed in required.  Pydantic does not add these by
    default.  This function adds them non-destructively (copies dicts).
    """
    schema = dict(schema)
    if schema.get("type") == "object":
        props = schema.get("properties", {})
        schema["properties"] = {k: _make_strict_schema(v) for k, v in props.items()}
        schema["additionalProperties"] = False
        # Ensure every property is required (strict mode mandates it)
        if props:
            existing = set(schema.get("required", []))
            schema["required"] = sorted(existing | set(props.keys()))
    for key in ("items", "prefixItems"):
        if key in schema:
            schema[key] = _make_strict_schema(schema[key])
    if "anyOf" in schema:
        schema["anyOf"] = [_make_strict_schema(s) for s in schema["anyOf"]]
    if "$defs" in schema:
        schema["$defs"] = {k: _make_strict_schema(v) for k, v in schema["$defs"].items()}
    return schema


def _schema_has_open_object(schema: dict[str, Any]) -> bool:
    """True when the schema contains an open-ended object (a free-form dict).

    Pydantic renders a ``dict[str, Any]`` field (observables, payload,
    edit_patches) as ``{type: object, additionalProperties: true}`` with no
    declared properties. OpenAI strict structured-output mode cannot express
    that: strict mode forces ``additionalProperties: false`` and lists every
    property in ``required``, which a free-form dict has none of. Strict
    OpenAI-compatible providers reject the resulting json_schema outright with
    "object type must have at least one required field", zeroing every turn on
    those providers. A schema carrying one must drop to json_object mode.
    """
    if not isinstance(schema, dict):
        return False
    if schema.get("type") == "object" and not schema.get("properties"):
        return True
    for node in (schema.get("properties") or {}).values():
        if _schema_has_open_object(node):
            return True
    for defn in (schema.get("$defs") or {}).values():
        if _schema_has_open_object(defn):
            return True
    for variant in schema.get("anyOf", []):
        if _schema_has_open_object(variant):
            return True
    for key in ("items", "prefixItems"):
        node = schema.get(key)
        if isinstance(node, dict) and _schema_has_open_object(node):
            return True
        if isinstance(node, list) and any(_schema_has_open_object(n) for n in node):
            return True
    return False


def _is_strict_schema_rejection(exc: Exception) -> bool:
    """True when a provider error is a rejection of the strict json_schema shape.

    Strict OpenAI-compatible providers reject a schema carrying a free-form
    dict (observables / payload) with a 400 that names the response_format or
    json_schema and the required-field / additionalProperties constraint. Such
    a call must retry in json_object mode rather than fail the turn. Transient
    and unrelated errors (token caps, inactive accounts, rate limits) do not
    match and propagate normally.
    """
    msg = str(exc).lower()
    if "json_schema" in msg or "response_format" in msg:
        return True
    return (
        "must have at least one required" in msg
        or "additionalproperties" in msg
    )


def _emit_cache_metrics(model_id: str, usage: dict[str, int]) -> None:
    """Emit the #155 Prometheus cache surfacing for one call.

    Reads the provider-normalised cache tokens via
    :func:`aila.platform.llm.prompt_layout.extract_cache_usage` and
    increments ``LLM_CACHE_TOKENS_TOTAL{model,kind}`` (cache_read /
    cache_write) plus sets ``LLM_CACHE_HIT_RATIO{model}`` to the
    per-call ratio. Errors are swallowed at DEBUG; the LLM hot path
    must not crash on a telemetry defect.
    """
    try:
        from aila.api.metrics import (
            LLM_CACHE_HIT_RATIO,
            LLM_CACHE_TOKENS_TOTAL,
        )
        from aila.platform.llm.prompt_layout import (
            compute_cache_hit_rate,
            extract_cache_usage,
        )
    except ImportError as exc:  # pragma: no cover - metrics package is required
        logger.debug("_emit_cache_metrics: import failed: %s", exc)
        return
    try:
        cache_usage = extract_cache_usage(usage)
        cache_read = int(cache_usage.get("cache_read", 0))
        cache_write = int(cache_usage.get("cache_write", 0))
        if cache_read:
            LLM_CACHE_TOKENS_TOTAL.labels(model=model_id, kind="read").inc(cache_read)
        if cache_write:
            LLM_CACHE_TOKENS_TOTAL.labels(model=model_id, kind="write").inc(cache_write)
        LLM_CACHE_HIT_RATIO.labels(model=model_id).set(
            compute_cache_hit_rate(usage, cache_usage),
        )
    except (RuntimeError, ValueError, TypeError, AttributeError) as exc:
        logger.debug("_emit_cache_metrics: skipped for %s: %s", model_id, exc)


_CACHE_USAGE_KEYS: tuple[str, ...] = (
    # Anthropic-style flat fields on the usage object.
    "cache_read_input_tokens",
    "cache_creation_input_tokens",
    "cache_read_tokens",
    "cache_write_input_tokens",
    # OpenAI-style: usually nested under prompt_tokens_details, but some
    # gateways flatten it. Read as a top-level fallback too.
    "cached_tokens",
)


def _extract_usage(completion: Any) -> dict[str, int]:
    """Extract token usage from a completion response.

    #155: pulls provider-specific cache-token fields into the returned
    dict when the upstream response carries them. Anthropic surfaces
    ``cache_read_input_tokens`` and ``cache_creation_input_tokens`` on
    the usage object; OpenAI nests ``cached_tokens`` under
    ``prompt_tokens_details``. Both surfaces sometimes leak through an
    OpenAI-compatible gateway (OpenRouter, LiteLLM) using the original
    provider names -- best-effort read with ``getattr`` so a missing
    field never crashes the hot path. The nested OpenAI value is
    flattened onto the top-level ``cached_tokens`` key so the returned
    dict keeps its ``dict[str, int]`` shape.

    :func:`aila.platform.llm.prompt_layout.extract_cache_usage` is the
    single reader that normalises these values into the uniform
    ``{cache_read, cache_write, cached}`` shape and drives the
    cache-hit-rate gauge on the cost surface.
    """
    if completion.usage is None:
        return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    usage = completion.usage
    result: dict[str, int] = {
        "prompt_tokens": int(usage.prompt_tokens or 0),
        "completion_tokens": int(usage.completion_tokens or 0),
        "total_tokens": int(usage.total_tokens or 0),
    }
    for attr in _CACHE_USAGE_KEYS:
        value = getattr(usage, attr, 0) or 0
        if value:
            result[attr] = int(value)
    details = getattr(usage, "prompt_tokens_details", None)
    if details is not None:
        cached = getattr(details, "cached_tokens", 0) or 0
        if cached:
            # Merge with any flat top-level value the loop above found.
            result["cached_tokens"] = max(
                int(cached), int(result.get("cached_tokens", 0)),
            )
    return result


def _merge_usage(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    """Merge two usage dicts by summing values.

    #155: preserves cache-token fields across a tool-loop step merge
    so the accumulated usage on the returned :class:`LLMResponse`
    still carries the cache signal from every step (the tool-loop
    caller sees the cumulative gauge, not just the final step).
    """
    merged: dict[str, int] = {
        "prompt_tokens": int(a.get("prompt_tokens", 0)) + int(b.get("prompt_tokens", 0)),
        "completion_tokens": int(a.get("completion_tokens", 0)) + int(b.get("completion_tokens", 0)),
        "total_tokens": int(a.get("total_tokens", 0)) + int(b.get("total_tokens", 0)),
    }
    for attr in _CACHE_USAGE_KEYS:
        value = int(a.get(attr, 0) or 0) + int(b.get(attr, 0) or 0)
        if value:
            merged[attr] = value
    return merged


def _require_choice(completion: Any, model_id: str) -> Any:
    """Return the first completion choice, or raise a clear retryable error.

    Multi-model gateways occasionally return a completion with an empty
    ``choices`` list (an upstream model dropped the turn). Indexing
    ``choices[0]`` blind turns that into an opaque ``IndexError``; this
    names the real condition and the model so the retry loop and logs are
    actionable.
    """
    if not completion.choices:
        raise LLMError(
            f"LLM provider returned no choices (model={model_id})",
            retryable=True,
        )
    return completion.choices[0]


def _enrich_response(response: LLMResponse, ctx: dict[str, Any]) -> LLMResponse:
    """Enrich an LLMResponse with pipeline metadata from the context dict.

    If no pipeline metadata is present in ctx, returns the original response
    unchanged (no copy overhead).

    Output sanitization (Phase 121): sanitize_output strips XSS patterns and
    control characters from the response content BEFORE enrichment.  The seal
    covers the raw output (seal step runs before _enrich_response) while
    callers and DB get sanitized content.

    Evidence validation results from ctx["evidence_validation"] are merged
    into pipeline_metadata["evidence_validation"] (Phase 118).
    """
    # Output sanitization (Phase 121, D-09/D-10)
    from .sanitize import sanitize_output

    cleaned_content, sanitized_count = sanitize_output(response.content)
    if sanitized_count > 0:
        ctx["output_sanitized"] = True
        ctx["output_sanitized_count"] = sanitized_count
        response = LLMResponse(
            content=cleaned_content,
            model=response.model,
            usage=response.usage,
            disabled=response.disabled,
            finish_reason=response.finish_reason,
        )

    classification = ctx.get("classification")
    confidence = ctx.get("confidence")
    seal_id = ctx.get("seal_id")
    metadata = ctx.get("pipeline_metadata")

    # Merge evidence_validation into pipeline_metadata (Phase 118)
    evidence_validation = ctx.get("evidence_validation")
    if evidence_validation is not None:
        if metadata is None:
            metadata = {}
        else:
            metadata = dict(metadata)  # copy to avoid mutation
        metadata["evidence_validation"] = evidence_validation

    if classification is None and confidence is None and seal_id is None and metadata is None:
        return response
    return LLMResponse(
        content=response.content,
        model=response.model,
        usage=response.usage,
        disabled=response.disabled,
        finish_reason=response.finish_reason,
        classification=classification,
        confidence=confidence,
        seal_id=seal_id,
        pipeline_metadata=metadata,
    )
