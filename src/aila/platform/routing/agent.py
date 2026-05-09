from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

if TYPE_CHECKING:
    from ..llm import AilaLLMClient

LOGGER = logging.getLogger(__name__)

_AGENT_SCHEMA_REGISTRY: dict[str, list[dict]] = {}
_AGENT_STATS: dict[str, dict] = {}


def _register_agent_schema(agent_name: str, model_cls: type[BaseModel]) -> None:
    """Register a Pydantic model schema in the global schema registry."""
    schema_json = json.dumps(model_cls.model_json_schema(), sort_keys=True, separators=(",", ":"))
    schema_hash = hashlib.sha256(schema_json.encode("utf-8")).hexdigest()[:16]
    entry = {
        "schema_name": model_cls.__name__,
        "schema_hash": schema_hash,
        "registered_at": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    _AGENT_SCHEMA_REGISTRY.setdefault(agent_name, [])
    existing_hashes = {e["schema_hash"] for e in _AGENT_SCHEMA_REGISTRY[agent_name]}
    if schema_hash not in existing_hashes:
        _AGENT_SCHEMA_REGISTRY[agent_name].append(entry)


def get_registered_schemas() -> list[dict]:
    """Return all registered agent schemas as a flat list."""
    result = []
    for agent_name, entries in _AGENT_SCHEMA_REGISTRY.items():
        for entry in entries:
            result.append({"agent_name": agent_name, **entry})
    return result


def get_agent_stats() -> dict:
    """Return cumulative per-agent call statistics."""
    return dict(_AGENT_STATS)


class StructuredAgent:
    """Prompt-building agent that delegates LLM calls to AilaLLMClient.

    Keeps prompt assembly (system instructions + task + additional_args),
    schema registry, and per-agent call stats. All LLM interaction --
    structured output, retry, JSON validation -- is handled by
    AilaLLMClient.chat_structured().

    Each subclass declares a task_type (e.g. "scoring", "synthesis",
    "routing") that the platform uses to route to the correct model.
    """

    task_type: str = "default"

    def __init__(
        self,
        *,
        model: AilaLLMClient | None = None,
        name: str = "",
        description: str = "",
        instructions: str = "",
        response_model: type[BaseModel] | None = None,
    ) -> None:
        self.model = model
        self.name = name or self.__class__.__name__
        self.description = description
        self._instructions = instructions
        self.response_model = response_model
        if self.response_model is not None:
            _register_agent_schema(self.__class__.__name__, self.response_model)

    async def run_structured(
        self,
        task: str,
        response_model: type[BaseModel] | None = None,
        additional_args: dict[str, Any] | None = None,
    ) -> BaseModel:
        """Run the agent and return a validated Pydantic model instance.

        Builds the message list from instructions + task + additional_args,
        then delegates to AilaLLMClient.chat_structured() which handles
        structured output, retry on parse failure, and Pydantic validation.

        Args:
            task: Natural-language task description.
            response_model: Pydantic model class. Defaults to self.response_model.
            additional_args: Optional extra key/value pairs appended to the prompt.

        Returns:
            A validated instance of response_model.

        Raises:
            ValueError: If response_model is None.
            RuntimeError: If no model is configured.
            LLMError: If the LLM call fails after retries.
        """
        t0 = time.monotonic()
        model_cls = response_model or self.response_model
        if model_cls is None:
            raise ValueError("A response model is required for structured agent runs.")
        if self.model is None:
            raise RuntimeError("Agent requires a configured model.")

        agent_name = self.name or self.__class__.__name__

        # Build prompt
        prompt = task
        if additional_args:
            prompt += "\nAdditional args:\n" + json.dumps(additional_args, separators=(",", ":"))

        # Build messages
        messages: list[dict[str, Any]] = []
        if self._instructions:
            messages.append({"role": "system", "content": self._instructions})
        messages.append({"role": "user", "content": prompt})

        # Delegate to AilaLLMClient -- handles retry, JSON parse, Pydantic validation
        response = await self.model.chat_structured(
            self.task_type,
            messages,
            model_cls,
        )

        # Parse the validated response
        parsed = model_cls.model_validate(json.loads(response.content))

        latency_ms = int((time.monotonic() - t0) * 1000)
        LOGGER.debug(
            "agent_run",
            extra={
                "agent_name": agent_name,
                "latency_ms": latency_ms,
                "model": response.model,
            },
        )

        stats = _AGENT_STATS.setdefault(agent_name, {"total_calls": 0})
        stats["total_calls"] += 1

        return parsed
