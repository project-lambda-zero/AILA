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
import json
import logging
import os
import time as _time_mod
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import sqlalchemy.exc
from openai import APIConnectionError, APITimeoutError, AsyncOpenAI, RateLimitError
from pydantic import BaseModel, ValidationError

from ..exceptions import AILAError
from .config import LLMConfigProvider
from .errors import LLMError
from .pipeline import PipelineRunner

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry
    from ...storage.secrets import SecretStore

logger = logging.getLogger(__name__)

# ── LLM endpoint health tracking ─────────────────────────────────────
#
# Per-process globals updated on every LLM call. Consumed by the masvs
# parent_reconciler to gate stale-branch abandonment: when the LLM
# endpoint has been unhealthy in the recent past, branches sitting
# idle on retry-loops are NOT "stalled" by their own fault — they're
# waiting on the LLM. Abandoning them in that window destroys real
# progress and is operator-prohibited.
#
# We update _LAST_LLM_ERROR_AT on every retryable exception even when
# a later retry succeeds — the failure window is still real, the
# branch did spend wall-clock time waiting, and any concurrent
# branches may have hit the same outage.
_LAST_LLM_OK_AT: float = 0.0
_LAST_LLM_ERROR_AT: float = 0.0
_LLM_HEALTH_LOCK = asyncio.Lock()


def _record_llm_ok() -> None:
    """Update the last-OK timestamp. Called inside the retry success path."""
    global _LAST_LLM_OK_AT
    _LAST_LLM_OK_AT = _time_mod.monotonic()


def _record_llm_error() -> None:
    """Update the last-error timestamp. Called inside every retry catch."""
    global _LAST_LLM_ERROR_AT
    _LAST_LLM_ERROR_AT = _time_mod.monotonic()


def is_llm_recently_unhealthy(window_s: float = 600.0) -> bool:
    """Return True iff the LLM had any error in the trailing window AND
    has not had a more recent success.

    Used by reconciler step 5 to gate stale-branch abandonment. A
    branch that has been idle through an LLM outage is waiting for
    work, not stalled — abandoning it would destroy real progress.

    Args:
        window_s: How far back to look for the last error. Default 10
            minutes — matches the worker's typical retry-window times
            (5-10 retries with exponential backoff cap at 60s each).
    """
    if _LAST_LLM_ERROR_AT == 0.0:
        return False
    now = _time_mod.monotonic()
    if (now - _LAST_LLM_ERROR_AT) > window_s:
        return False
    # Error within window — only "healthy" if a success has happened
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
    """Return False when the routed model is known to reject ``temperature``."""
    mid = (model_id or "").lower()
    return not any(marker in mid for marker in _get_rejection_markers())


def _strip_json_fences(content: str) -> str:
    """Remove Markdown code fences from an LLM JSON response.

    OmniRoute routed to Anthropic Claude returns ```json\\n{...}\\n``` even
    when response_format=json_schema is requested. This strips the fence so
    json.loads() works downstream. Safe for clean JSON (no-op).
    """
    if not content:
        return content
    text = content.strip()
    if text.startswith("```"):
        # Drop opening fence (possibly "```json" or "```")
        first_nl = text.find("\n")
        if first_nl == -1:
            return text
        text = text[first_nl + 1:]
        # Drop trailing fence
        if text.rstrip().endswith("```"):
            text = text.rstrip()
            text = text[: -3].rstrip()
    return text


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
    # Pipeline metadata (Phase 116) -- default None, transparent to existing callers
# Retry budget — TIGHT BY DESIGN.
#
# Background (the change shipped on 2026-06-13 after operator
# diagnosed the maddie / bc194403 stall on inv 86307908 et al):
#
# The old budget was _MAX_RETRIES=100 × up-to-30s backoff = ~48 min
# of in-task retry burn. That meant a single worker process would
# pin itself on ONE task's retry loop for nearly an hour during any
# sustained provider degradation (NVIDIA NIM 40 RPM throttling,
# OpenRouter 503, OmniRoute restart). All other queued tasks
# starved behind that worker, which was the operator-observed
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
# With _MAX_RETRIES=3 and capped 30s backoff:
#   attempts 1-3: 1s, 2s, 4s
# Total in-task budget ≈ 7 seconds. Anything longer is the queue
# layer's job, not the in-call retry loop.
#
# For ``RateLimitError`` specifically: when the provider sends a
# ``Retry-After`` header, honour it (capped at _RETRY_MAX_DELAY).
# That lets us delay-and-retry within the existing 3-attempt
# budget instead of failing immediately on a known-recoverable
# 429 with a "try again in N seconds" signal.
#
# Env knobs (defaults landed for the new fast-fail behavior):
#   AILA_LLM_MAX_RETRIES        — in-call attempts cap (default 3)
#   AILA_LLM_RETRY_BASE_DELAY_S — first-attempt backoff (default 1.0s)
#   AILA_LLM_RETRY_MAX_DELAY_S  — per-attempt backoff cap (default 30.0s)
_MAX_RETRIES = max(1, int(os.environ.get("AILA_LLM_MAX_RETRIES", "3")))
_RETRY_BASE_DELAY = max(0.1, float(os.environ.get("AILA_LLM_RETRY_BASE_DELAY_S", "1.0")))
_RETRY_MAX_DELAY = max(_RETRY_BASE_DELAY, float(os.environ.get("AILA_LLM_RETRY_MAX_DELAY_S", "30.0")))


class AilaLLMClient:
    """Async-first LLM client with config-based routing and operational controls.

    Not a singleton -- instantiate with registry and secret_store references.
    The client creates a fresh AsyncOpenAI per call to pick up runtime config
    changes (base_url, api_key can change via ConfigRegistry/SecretStore).
    """

    def __init__(
        self,
        registry: ConfigRegistry,
        secret_store: SecretStore,
    ) -> None:
        self._config = LLMConfigProvider(registry=registry, secret_store=secret_store)
        self._pipeline = PipelineRunner(config_provider=self._config)
        self.cost_tracker: Any = None  # Set by builder.py to CostTracker instance
        self.bus: Any = None  # Optional EventBus; set by builder.py for domain events

    @property
    def pipeline(self) -> PipelineRunner:
        """Access pipeline for step registration at platform startup."""
        return self._pipeline

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

        return await self._call_with_retry(
            routing=routing,
            messages=messages,
            response_format=None,
            tools=tools,
            tool_executor=tool_executor,
            run_id=run_id,
            team_id=team_id,
        )

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
                that overrides ``routing.max_tokens``. fix §309 — callers
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
        # fix §309 — apply per-call ceiling by cloning the frozen
        # LLMRouting dataclass with the smaller max_tokens. Never raise
        # above the routing-resolved cap (operator's configured ceiling
        # is authoritative); only narrow it.
        if max_output_tokens is not None and max_output_tokens > 0:
            from dataclasses import replace as _dc_replace
            effective_max = min(int(max_output_tokens), int(routing.max_tokens))
            if effective_max != routing.max_tokens:
                routing = _dc_replace(routing, max_tokens=effective_max)

        strict_schema = _make_strict_schema(schema)
        response_format = {
            "type": "json_schema",
            "json_schema": {
                "name": schema.get("title", "response"),
                "strict": True,
                "schema": strict_schema,
            },
        }

        resp = await self._call_with_retry(
            routing=routing,
            messages=messages,
            response_format=response_format,
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
        4. Returns LLMResponse with the validated model as .parsed and JSON as .content

        On parse failure, retries once with an explicit "fix your JSON" prompt
        (per LLM-10).

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
                routing-resolved cap). fix §309.

        Returns:
            LLMResponse where content is valid JSON and .parsed is the model instance.

        Raises:
            LLMError: On permanent errors or validation failure after retry.
            BudgetExceededError: If budget ceiling exceeded for the run.
        """
        schema = model_class.model_json_schema()
        response = await self.chat_json(
            task_type,
            messages,
            schema,
            tools=tools,
            tool_executor=tool_executor,
            run_id=run_id,
            team_id=team_id,
            max_output_tokens=max_output_tokens,
        )

        if response.disabled:
            return response

        # Try to parse into model
        parsed = self._parse_model(response.content, model_class)
        if parsed is not None:
            return LLMResponse(
                content=response.content,
                model=response.model,
                usage=response.usage,
                disabled=False,
                finish_reason=response.finish_reason,
            )

        # Retry with correction prompt
        logger.warning(
            "chat_structured: initial parse failed for %s, retrying with correction",
            model_class.__name__,
        )
        retry_messages = list(messages) + [
            {"role": "assistant", "content": response.content},
            {
                "role": "user",
                "content": (
                    f"Your previous response was not valid JSON matching the schema. "
                    f"Please respond with ONLY valid JSON matching this schema:\n"
                    f"{json.dumps(schema, indent=2)}"
                ),
            },
        ]
        retry_response = await self.chat_json(
            task_type,
            retry_messages,
            schema,
            tools=tools,
            tool_executor=tool_executor,
            run_id=run_id,
            team_id=team_id,
            max_output_tokens=max_output_tokens,
        )

        if retry_response.disabled:
            return retry_response

        parsed = self._parse_model(retry_response.content, model_class)
        if parsed is None:
            raise LLMError(
                f"Failed to parse LLM response into {model_class.__name__} after retry",
                retryable=False,
            )

        return LLMResponse(
            content=retry_response.content,
            model=retry_response.model,
            usage=_merge_usage(response.usage, retry_response.usage),
            disabled=False,
            finish_reason=retry_response.finish_reason,
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
        # out on cc/claude-sonnet-4-6). Default raised to 180s and overridable
        # via env (AILA_LLM_TIMEOUT_SECONDS) or ConfigRegistry for ops.
        import os as _os
        try:
            _timeout_s = float(_os.environ.get("AILA_LLM_TIMEOUT_SECONDS", "180"))
        except ValueError:
            _timeout_s = 180.0
        client = AsyncOpenAI(
            api_key=routing.api_key,
            base_url=routing.base_url,
            max_retries=0,  # we handle retries ourselves for logging
            timeout=_timeout_s,
        )

        last_error: Exception | None = None

        for attempt in range(_MAX_RETRIES):
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
                    },
                    run_id=run_id or "",
                )
                # Cost recording AFTER successful call (Phase 122)
                if self.cost_tracker is not None:
                    self.cost_tracker.record(run_id, response.usage)

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
                except (ValueError, sqlalchemy.exc.SQLAlchemyError):
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
                except sqlalchemy.exc.SQLAlchemyError:
                    import structlog
                    structlog.get_logger(__name__).warning(
                        "cost_persistence_failed", run_id=run_id, model=routing.model_id,
                    )

                # Step 3: Missing pricing warning (separate try/except)
                if not _pricing_configured:
                    try:
                        from aila.platform.llm.cost import emit_missing_pricing_notification
                        await emit_missing_pricing_notification(routing.model_id)
                    except sqlalchemy.exc.SQLAlchemyError:
                        pass  # emit_missing_pricing_notification already swallows; belt-and-suspenders

                # Step 4: Prometheus counter (separate try/except)
                try:
                    from aila.api.metrics import LLM_COST_TOTAL
                    LLM_COST_TOTAL.labels(model=routing.model_id).inc(_cost_usd)
                except (ImportError, ValueError, AttributeError) as exc:
                    # Prometheus counter is best-effort telemetry; never fail the LLM call
                    # because metrics emission failed. Specific types cover missing import,
                    # invalid label values, and unexpected counter shape.
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
                except (AILAError, AttributeError):
                    pass

                _record_llm_ok()
                return _enrich_response(response, ctx)
            except RateLimitError as exc:
                # Honour Retry-After when the provider tells us how
                # long to wait. NVIDIA NIM, OpenRouter, OpenAI all send
                # this header on 429s — it's the most accurate delay we
                # can pick. Fallback to exponential backoff (capped at
                # _RETRY_MAX_DELAY) when the header is missing.
                _record_llm_error()
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
                    delay = min(max(retry_after_s, 0.1), _RETRY_MAX_DELAY)
                else:
                    delay = min(_RETRY_BASE_DELAY * (2 ** attempt), _RETRY_MAX_DELAY)
                logger.warning(
                    "LLM rate-limit (attempt %d/%d): %s -- retrying in %.1fs "
                    "(retry_after_hdr=%s)",
                    attempt + 1,
                    _MAX_RETRIES,
                    type(exc).__name__,
                    delay,
                    retry_after_s,
                )
                await asyncio.sleep(delay)
            except (APIConnectionError, APITimeoutError) as exc:
                _record_llm_error()
                last_error = exc
                delay = min(_RETRY_BASE_DELAY * (2 ** attempt), _RETRY_MAX_DELAY)
                logger.warning(
                    "LLM transient error (attempt %d/%d): %s -- retrying in %.1fs",
                    attempt + 1,
                    _MAX_RETRIES,
                    type(exc).__name__,
                    delay,
                )
                await asyncio.sleep(delay)
            except LLMError as exc:
                if exc.retryable:
                    _record_llm_error()
                    last_error = exc
                    delay = min(_RETRY_BASE_DELAY * (2 ** attempt), _RETRY_MAX_DELAY)
                    logger.warning(
                        "LLM retryable error (attempt %d/%d): %s -- retrying in %.1fs",
                        attempt + 1,
                        _MAX_RETRIES,
                        exc.message,
                        delay,
                    )
                    await asyncio.sleep(delay)
                else:
                    # Non-retryable LLM errors (ClassificationBlockedError, etc.)
                    raise
            except Exception as exc:
                # ALL provider errors are transient — 500, 502, 503,
                # connection reset, timeout, DNS failure, etc. The only
                # non-retryable errors are LLMError(retryable=False)
                # which are caught above (classification blocks, schema
                # violations). Everything else gets retried.
                _record_llm_error()
                last_error = exc
                delay = min(_RETRY_BASE_DELAY * (2 ** attempt), _RETRY_MAX_DELAY)
                logger.warning(
                    "LLM provider error (attempt %d/%d): %s: %s -- retrying in %.1fs",
                    attempt + 1,
                    _MAX_RETRIES,
                    type(exc).__name__,
                    str(exc)[:200],
                    delay,
                )
                await asyncio.sleep(delay)

        raise LLMError(
            f"LLM API failed after {_MAX_RETRIES} retries: {last_error}",
            retryable=True,
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
        calls (§100) — both must bypass the pipeline (would recurse into
        themselves) but still accumulate cost against the operator's
        run budget. Previously each step constructed its own
        ``AsyncOpenAI`` directly and the tokens were invisible to the
        cost tracker / persist_cost_record / Prometheus pipeline. Now
        the platform builds the inner client the same way
        :meth:`_call_with_retry` does and records the same cost ledger.

        Pipeline recursion is avoided structurally — we call
        :meth:`_single_call` directly instead of routing through
        :class:`PipelineRunner`.
        """
        try:
            _timeout_s = float(os.environ.get("AILA_LLM_TIMEOUT_SECONDS", "180"))
        except ValueError:
            _timeout_s = 180.0
        client = AsyncOpenAI(
            api_key=routing.api_key,
            base_url=routing.base_url,
            max_retries=0,
            timeout=_timeout_s,
        )
        _call_start = _time_mod.perf_counter()
        try:
            response = await self._single_call(
                client=client,
                routing=routing,
                messages=messages,
                response_format=response_format,
                tools=tools,
                tool_executor=tool_executor,
            )

            # Cost recording — same shape as :meth:`_call_with_retry` so
            # consensus / verify tokens land in the same per-run budget
            # and the operator's spend reports tell the truth (fix §100).
            try:
                if self.cost_tracker is not None:
                    self.cost_tracker.record(run_id, response.usage)
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
        finally:
            try:
                await client.close()
            except Exception as exc:
                logger.debug("inner_call client.close() failed: %s", exc)

    async def _single_call(
        self,
        *,
        client: AsyncOpenAI,
        routing: Any,
        messages: list[dict[str, Any]],
        response_format: dict[str, Any] | None,
        tools: list[dict[str, Any]] | None,
        tool_executor: Callable[[str, dict[str, Any]], Awaitable[str]] | None,
    ) -> LLMResponse:
        """Execute a single API call, with optional tool loop.

        When tools are provided and the model responds with tool_calls,
        executes the tool loop up to routing.max_tool_steps iterations.
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

        choice = completion.choices[0]

        # Tool calling loop (per D-05-new)
        if tools and tool_executor and choice.finish_reason == "tool_calls":
            return await self._tool_loop(
                client=client,
                routing=routing,
                messages=list(messages),
                response_format=response_format,
                tools=tools,
                tool_executor=tool_executor,
                initial_choice=choice,
                initial_usage=_extract_usage(completion),
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
    ) -> LLMResponse:
        """Run the tool-calling loop until the model stops calling tools.

        Max iterations = routing.max_tool_steps.  If max_tool_steps is 0 or
        not set, tool calling is disabled -- returns whatever the model said.
        """
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
                result = await tool_executor(tc.function.name, args)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": str(result),
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

            choice = completion.choices[0]
            step_usage = _extract_usage(completion)
            accumulated_usage = _merge_usage(accumulated_usage, step_usage)

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
        """Validate that *content* is JSON, with a markdown-fence fallback (LLM-06 / D-10).

        If the model returned valid JSON, return it as-is.
        If the model wrapped JSON in a ```json ... ``` fence, strip the fence
        and return the inner JSON when it parses.

        Returns the validated JSON string.
        Raises LLMError if validation fails completely.
        """
        try:
            json.loads(content)
            return content
        except json.JSONDecodeError:
            # Try to extract JSON from markdown code blocks
            stripped = content.strip()
            if stripped.startswith("```"):
                lines = stripped.split("\n")
                # Remove first and last lines (``` markers)
                inner = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
                try:
                    json.loads(inner)
                    return inner
                except json.JSONDecodeError:
                    pass

            raise LLMError(
                "LLM response is not valid JSON and could not be recovered",
                retryable=True,
            )

    @staticmethod
    def _parse_model(content: str, model_class: type[BaseModel]) -> BaseModel | None:
        """Try to parse content into a Pydantic model. Returns None on failure.

        Logs the parse failure at WARNING with the truncated content head
        and the validation error so operators see what mismatched without
        bumping the logger to DEBUG. The full content is in the LLM cost
        record's response_preview column for replay.
        """
        try:
            data = json.loads(content)
            return model_class.model_validate(data)
        except json.JSONDecodeError as exc:
            logger.warning(
                "_parse_model: JSON decode failed for %s -- %s. head=%r",
                model_class.__name__, exc, content[:200],
            )
            return None
        except ValidationError as exc:
            logger.warning(
                "_parse_model: schema validation failed for %s -- %s",
                model_class.__name__,
                str(exc).replace("\n", " | ")[:600],
            )
            return None


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


def _extract_usage(completion: Any) -> dict[str, int]:
    """Extract token usage from a completion response."""
    if completion.usage is None:
        return {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    return {
        "prompt_tokens": completion.usage.prompt_tokens or 0,
        "completion_tokens": completion.usage.completion_tokens or 0,
        "total_tokens": completion.usage.total_tokens or 0,
    }


def _merge_usage(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    """Merge two usage dicts by summing values."""
    return {
        "prompt_tokens": a.get("prompt_tokens", 0) + b.get("prompt_tokens", 0),
        "completion_tokens": a.get("completion_tokens", 0) + b.get("completion_tokens", 0),
        "total_tokens": a.get("total_tokens", 0) + b.get("total_tokens", 0),
    }


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
