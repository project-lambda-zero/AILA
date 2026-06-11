"""LLM configuration provider -- routing, key resolution, kill switch.

Reads all configuration from ConfigRegistry (namespace "platform") and
SecretStore.  Zero caching -- every call reads current state so runtime
changes via PUT /config take effect immediately.

API key resolution order (per D-05):
  1. SecretStore("provider", "openai_api_key")
  2. OPENAI_API_KEY environment variable
  3. None (caller must handle missing key)

Model routing (per D-06):
  ConfigRegistry key "llm_model_{task_type}" maps task_type to model_id.
  Unknown task_types fall back to "llm_default_model".

Kill switch (per D-08):
  ConfigRegistry key "llm_kill_switch" -- when True, client returns
  error response without raising.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry
    from ...storage.secrets import SecretStore


class DataDirection(StrEnum):
    """Data flow constraint per task type."""

    INBOUND = "inbound"
    LOCAL_ONLY = "local_only"
    BIDIRECTIONAL = "bidirectional"


@dataclass(frozen=True, slots=True)
class LLMRouting:
    """Resolved routing for a single LLM call.

    Attributes:
        model_id: OpenRouter model identifier (e.g. "anthropic/claude-haiku-4-5-20251001").
        base_url: API base URL (e.g. "https://openrouter.ai/api/v1").
        api_key: Decrypted API key string.
        max_tokens: Maximum completion tokens for this task_type.
        temperature: Sampling temperature for this task_type.
        max_tool_steps: Maximum tool-calling loop iterations (per D-20).
    """

    model_id: str
    base_url: str
    api_key: str
    max_tokens: int
    temperature: float
    max_tool_steps: int
    task_type: str = ""


class LLMConfigProvider:
    """Resolves LLM configuration from ConfigRegistry + SecretStore.

    Not a singleton -- instantiated by the client, which passes its own
    registry and secret_store references.
    """

    def __init__(
        self,
        registry: ConfigRegistry,
        secret_store: SecretStore,
    ) -> None:
        self._registry = registry
        self._secret_store = secret_store

    async def resolve_api_key(self) -> str | None:
        """Resolve API key: SecretStore first, then OPENAI_API_KEY env var.

        Returns:
            The API key string, or None if neither source has a value.
        """
        key = await self._secret_store.resolve_provider_secret("openai_api_key")
        if key is not None:
            return key
        return os.environ.get("OPENAI_API_KEY")

    async def resolve_model(self, task_type: str) -> str:
        """Resolve model_id for a task_type.

        Lookup: llm_model_{task_type} in ConfigRegistry.
        Fallback: llm_default_model in ConfigRegistry.
        Final fallback: "openai/gpt-4o-mini" (safe default).

        Args:
            task_type: The task type string (e.g. "scoring", "synthesis").

        Returns:
            OpenRouter model identifier string.
        """
        specific = await self._registry.get("platform", f"llm_model_{task_type}")
        if specific is not None and str(specific).strip():
            return str(specific)
        default = await self._registry.get("platform", "llm_default_model")
        if default is not None and str(default).strip():
            return str(default)
        return "antigravity/claude-opus-4-6-thinking"

    async def resolve_base_url(self) -> str:
        """Resolve API base URL from ConfigRegistry.

        Returns:
            Base URL string. Defaults to OpenRouter endpoint.
        """
        url = await self._registry.get("platform", "llm_base_url")
        if url is not None and str(url).strip():
            return str(url)
        return "https://openrouter.ai/api/v1"

    async def resolve_max_tokens(self, task_type: str) -> int:
        """Resolve max_tokens for a task_type.

        Lookup: llm_max_tokens_{task_type} in ConfigRegistry.
        Fallback: llm_default_max_tokens.
        Final fallback: 4096.
        """
        specific = await self._registry.get("platform", f"llm_max_tokens_{task_type}")
        if specific is not None:
            try:
                return int(specific)
            except (ValueError, TypeError):
                pass
        default = await self._registry.get("platform", "llm_default_max_tokens")
        if default is not None:
            try:
                return int(default)
            except (ValueError, TypeError):
                pass
        return 4096

    async def resolve_temperature(self, task_type: str) -> float:
        """Resolve temperature for a task_type.

        Lookup: llm_temperature_{task_type} in ConfigRegistry.
        Fallback: llm_default_temperature.
        Final fallback: 0.0 (deterministic).
        """
        specific = await self._registry.get("platform", f"llm_temperature_{task_type}")
        if specific is not None:
            try:
                return float(specific)
            except (ValueError, TypeError):
                pass
        default = await self._registry.get("platform", "llm_default_temperature")
        if default is not None:
            try:
                return float(default)
            except (ValueError, TypeError):
                pass
        return 0.0

    async def resolve_max_tool_steps(self, task_type: str) -> int:
        """Resolve max tool-calling loop steps for a task_type (per D-20).

        No hardcoded default -- must be explicitly set.  Returns 0 if not
        configured, which means tool calling is disabled for that task_type.
        """
        specific = await self._registry.get("platform", f"llm_max_tool_steps_{task_type}")
        if specific is not None:
            try:
                return int(specific)
            except (ValueError, TypeError):
                pass
        return 0

    async def is_disabled(self) -> bool:
        """Check kill switch state.

        Returns:
            True if LLM calls are disabled by operator.
        """
        val = await self._registry.get("platform", "llm_kill_switch")
        if val is None:
            return False
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ("true", "1", "yes")

    async def resolve_routing(self, task_type: str) -> LLMRouting:
        """Resolve complete routing for a task_type.

        Combines all resolution methods into a single frozen dataclass.

        Args:
            task_type: The task type string.

        Returns:
            LLMRouting with all fields resolved.

        Raises:
            LLMError: If API key cannot be resolved.
        """
        from .errors import LLMError

        api_key = await self.resolve_api_key()
        if api_key is None:
            raise LLMError(
                "No API key configured. Set via SecretStore (provider/openai_api_key) "
                "or OPENAI_API_KEY environment variable.",
                retryable=False,
            )
        return LLMRouting(
            model_id=await self.resolve_model(task_type),
            base_url=await self.resolve_base_url(),
            api_key=api_key,
            max_tokens=await self.resolve_max_tokens(task_type),
            temperature=await self.resolve_temperature(task_type),
            max_tool_steps=await self.resolve_max_tool_steps(task_type),
            task_type=task_type,
        )

    async def is_step_enabled(self, step: str, task_type: str) -> bool:
        """Check if a pipeline step is enabled for a task_type.

        Reads key ``llm_pipeline_{step}_{task_type}`` from ConfigRegistry.
        Missing key (None) means enabled (True).

        Args:
            step: Pipeline step name (e.g. "classify").
            task_type: The task type string (e.g. "scoring").

        Returns:
            True if the step should run, False if disabled.
        """
        val = await self._registry.get("platform", f"llm_pipeline_{step}_{task_type}")
        if val is None:
            return True
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() not in ("false", "0", "no")

    # fix §156 — pipeline steps default to fail-closed so a regex compile
    # error or transient validator hiccup never silently bypasses sanitize
    # / validate / gate / verify on a hot path. Operators that want fail-
    # open MUST opt in explicitly per task_type.
    _SECURITY_CRITICAL_STEPS: frozenset[str] = frozenset(
        {"sanitize", "validate", "gate", "verify", "classify", "seal"},
    )

    async def resolve_fail_mode(self, step: str, task_type: str) -> str:
        """Resolve fail mode for a pipeline step and task_type.

        Reads key ``llm_pipeline_{step}_fail_mode_{task_type}`` from
        ConfigRegistry. Missing key defaults to ``"closed"`` for security-
        critical steps (sanitize/validate/gate/verify/classify/seal — §156)
        and ``"open"`` for everything else.

        Args:
            step: Pipeline step name (e.g. "classify").
            task_type: The task type string (e.g. "scoring").

        Returns:
            "open" or "closed".
        """
        val = await self._registry.get("platform", f"llm_pipeline_{step}_fail_mode_{task_type}")
        if val is None:
            return "closed" if step in self._SECURITY_CRITICAL_STEPS else "open"
        normalized = str(val).strip().lower()
        if normalized in ("closed", "close", "strict"):
            return "closed"
        return "open"

    async def resolve_data_direction(self, task_type: str) -> DataDirection:
        """Resolve data direction constraint for a task type.

        Lookup: llm_data_direction_{task_type} in ConfigRegistry.
        Fallback: data_direction_default in ConfigRegistry.
        Final fallback: DataDirection.BIDIRECTIONAL.

        Args:
            task_type: The task type string (e.g. "scoring").

        Returns:
            DataDirection enum value.
        """
        val = await self._registry.get("platform", f"llm_data_direction_{task_type}")
        if val and str(val) in (d.value for d in DataDirection):
            return DataDirection(str(val))
        default = await self._registry.get("platform", "data_direction_default")
        if default and str(default) in (d.value for d in DataDirection):
            return DataDirection(str(default))
        return DataDirection.BIDIRECTIONAL

    async def resolve_posture(self) -> str:
        """Resolve the active data posture mode.

        Reads key ``data_posture_mode`` from ConfigRegistry.
        Missing or invalid values default to "standard".

        Returns:
            One of "transparent", "standard", or "paranoid".
        """
        val = await self._registry.get("platform", "data_posture_mode")
        if val in ("transparent", "standard", "paranoid"):
            return str(val)
        return "standard"

    async def resolve_verify_threshold(self, task_type: str) -> float:
        """Resolve verification confidence threshold for a task_type.

        Verification is triggered when confidence_score < threshold.

        Lookup: llm_pipeline_verify_threshold_{task_type} in ConfigRegistry.
        Fallback: llm_pipeline_verify_threshold_default.
        Final fallback: 0.7.

        Args:
            task_type: The task type string (e.g. "scoring").

        Returns:
            Float threshold (0.0 - 1.0).
        """
        val = await self._registry.get(
            "platform", f"llm_pipeline_verify_threshold_{task_type}"
        )
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass
        default = await self._registry.get(
            "platform", "llm_pipeline_verify_threshold_default"
        )
        if default is not None:
            try:
                return float(default)
            except (TypeError, ValueError):
                pass
        return 0.7

    async def resolve_verify_model(self, task_type: str) -> str:
        """Resolve the second model for blind verification.

        Lookup: llm_pipeline_verify_model_{task_type} in ConfigRegistry.
        Fallback: llm_pipeline_verify_model_default.
        Final fallback: empty string (verification skipped if no model).

        Args:
            task_type: The task type string (e.g. "scoring").

        Returns:
            Model identifier string, or empty string if not configured.
        """
        val = await self._registry.get(
            "platform", f"llm_pipeline_verify_model_{task_type}"
        )
        if val:
            return str(val)
        default = await self._registry.get(
            "platform", "llm_pipeline_verify_model_default"
        )
        return str(default) if default else ""
