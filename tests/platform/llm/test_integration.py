"""Integration tests for aila.platform.llm -- real OpenRouter API.

These tests require:
  - OPENAI_API_KEY env var set to a valid OpenRouter API key
  - Network access to https://openrouter.ai

Run: pytest tests/platform/llm/test_integration.py -x -v -m integration

All tests use openai/gpt-4o-mini (cheapest, fastest) to minimize cost.
Expected cost per full test run: < $0.01.
"""

from __future__ import annotations

import json
import os

import pytest
from pydantic import BaseModel

from aila.platform.llm.client import AilaLLMClient, LLMResponse
from aila.platform.llm.errors import LLMError
from aila.platform.llm.run_memory import RunMemory

# Skip entire module if no API key
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not os.environ.get("OPENAI_API_KEY"),
        reason="OPENAI_API_KEY not set -- skipping integration tests",
    ),
]


# ---------------------------------------------------------------------------
# Test Pydantic models
# ---------------------------------------------------------------------------

class VulnScore(BaseModel):
    score: float
    severity: str
    reasoning: str


class SimpleAnswer(BaseModel):
    answer: str


# ---------------------------------------------------------------------------
# Fakes (lightweight -- no DB needed for integration tests)
# ---------------------------------------------------------------------------

class FakeRegistry:
    """In-memory registry with OpenRouter defaults."""

    def __init__(self, overrides: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = {
            "platform.llm_base_url": "https://openrouter.ai/api/v1",
            "platform.llm_default_model": "openai/gpt-4o-mini",
            "platform.llm_default_max_tokens": 256,
            "platform.llm_default_temperature": 0.0,
        }
        if overrides:
            self._data.update(overrides)

    async def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")


class FakeSecretStore:
    """Uses OPENAI_API_KEY from environment."""

    async def resolve_provider_secret(self, secret_key: str) -> str | None:
        if secret_key == "openai_api_key":
            return os.environ.get("OPENAI_API_KEY")
        return None


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client() -> AilaLLMClient:
    return AilaLLMClient(
        registry=FakeRegistry(),  # type: ignore[arg-type]
        secret_store=FakeSecretStore(),  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# chat() -- LLM-01 integration
# ---------------------------------------------------------------------------

class TestChatIntegration:
    """Real chat() calls via OpenRouter."""

    @pytest.mark.asyncio
    async def test_basic_chat(self, client: AilaLLMClient) -> None:
        """Send a simple prompt and get a text response."""
        response = await client.chat(
            "general",
            [{"role": "user", "content": "What is 2 + 2? Reply with just the number."}],
        )
        assert isinstance(response, LLMResponse)
        assert response.disabled is False
        assert response.content.strip() != ""
        assert "4" in response.content
        assert response.model == "openai/gpt-4o-mini"
        assert response.usage["prompt_tokens"] > 0
        assert response.usage["completion_tokens"] > 0
        print(f"\n  chat response: {response.content.strip()!r}")
        print(f"  usage: {response.usage}")

    @pytest.mark.asyncio
    async def test_model_routing(self) -> None:
        """Task-specific model routing via config (LLM-04)."""
        reg = FakeRegistry({
            "platform.llm_model_scoring": "openai/gpt-4o-mini",
        })
        c = AilaLLMClient(
            registry=reg,  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        response = await c.chat(
            "scoring",
            [{"role": "user", "content": "Say hello."}],
        )
        assert response.model == "openai/gpt-4o-mini"
        assert response.content.strip() != ""


# ---------------------------------------------------------------------------
# chat_json() -- LLM-02 integration
# ---------------------------------------------------------------------------

class TestChatJsonIntegration:
    """Real chat_json() calls with JSON schema enforcement."""

    @pytest.mark.asyncio
    async def test_json_response(self, client: AilaLLMClient) -> None:
        """Get a structured JSON response."""
        schema = SimpleAnswer.model_json_schema()
        response = await client.chat_json(
            "general",
            [
                {
                    "role": "system",
                    "content": "You are a helpful assistant. Always respond in the requested JSON format.",
                },
                {
                    "role": "user",
                    "content": "What is the capital of France? Respond with JSON.",
                },
            ],
            schema,
        )
        assert response.disabled is False
        data = json.loads(response.content)
        assert "answer" in data
        assert "paris" in data["answer"].lower()
        print(f"\n  chat_json response: {data}")


# ---------------------------------------------------------------------------
# chat_structured() -- LLM-10 integration
# ---------------------------------------------------------------------------

class TestChatStructuredIntegration:
    """Real chat_structured() calls with Pydantic validation."""

    @pytest.mark.asyncio
    async def test_structured_response(self, client: AilaLLMClient) -> None:
        """Get a validated Pydantic model response."""
        response = await client.chat_structured(
            "scoring",
            [
                {
                    "role": "system",
                    "content": (
                        "You are a vulnerability scoring assistant. "
                        "Score the vulnerability from 0.0 to 10.0."
                    ),
                },
                {
                    "role": "user",
                    "content": (
                        "Score CVE-2024-3094 (xz-utils backdoor). "
                        "Respond with score, severity (CRITICAL/HIGH/MEDIUM/LOW), and reasoning."
                    ),
                },
            ],
            VulnScore,
        )
        assert response.disabled is False
        parsed = VulnScore.model_validate_json(response.content)
        assert 0.0 <= parsed.score <= 10.0
        assert parsed.severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert len(parsed.reasoning) > 10
        print(f"\n  structured response: score={parsed.score}, severity={parsed.severity}")
        print(f"  reasoning: {parsed.reasoning[:100]}...")


# ---------------------------------------------------------------------------
# Sync wrappers -- LLM-03 integration
# ---------------------------------------------------------------------------

class TestSyncIntegration:
    """Sync wrappers work with real API."""

    def test_chat_sync(self, client: AilaLLMClient) -> None:
        response = client.chat_sync(
            "general",
            [{"role": "user", "content": "Say hello in one word."}],
        )
        assert response.content.strip() != ""
        print(f"\n  chat_sync: {response.content.strip()!r}")


# ---------------------------------------------------------------------------
# Kill switch -- LLM-08 integration
# ---------------------------------------------------------------------------

class TestKillSwitchIntegration:
    """Kill switch prevents real API calls."""

    @pytest.mark.asyncio
    async def test_kill_switch_blocks(self) -> None:
        reg = FakeRegistry({"platform.llm_kill_switch": True})
        c = AilaLLMClient(
            registry=reg,  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        response = await c.chat(
            "scoring",
            [{"role": "user", "content": "This should not reach the API"}],
        )
        assert response.disabled is True
        assert response.content == "LLM disabled by operator"


# ---------------------------------------------------------------------------
# RunMemory -- LLM-09 integration
# ---------------------------------------------------------------------------

class TestRunMemoryIntegration:
    """RunMemory in a simulated scan flow."""

    def test_scan_flow(self) -> None:
        mem = RunMemory()
        run_id = "scan-2024-0001"

        # Stage 1: store host context
        mem.put(run_id, "target_host", "10.0.0.5")
        mem.put(run_id, "os", "Ubuntu 22.04")

        # Stage 2: accumulate findings
        mem.append(run_id, "findings", "CVE-2024-0001")
        mem.append(run_id, "findings", "CVE-2024-0002")

        # Stage 3: store scoring summary
        mem.put(run_id, "risk_score", 8.5)

        # Verify all data accessible
        assert mem.get(run_id, "target_host") == "10.0.0.5"
        assert mem.get(run_id, "findings") == ["CVE-2024-0001", "CVE-2024-0002"]
        assert mem.get(run_id, "risk_score") == 8.5
        assert sorted(mem.keys(run_id)) == ["findings", "os", "risk_score", "target_host"]

        # Cleanup
        mem.clear(run_id)
        assert mem.active_runs() == []


# ---------------------------------------------------------------------------
# Error handling -- LLM-05 edge case
# ---------------------------------------------------------------------------

class TestErrorHandlingIntegration:
    """Error scenarios with real API."""

    @pytest.mark.asyncio
    async def test_invalid_model_raises(self) -> None:
        """Requesting a non-existent model should raise LLMError."""
        reg = FakeRegistry({
            "platform.llm_model_broken": "nonexistent/fake-model-xyz",
        })
        c = AilaLLMClient(
            registry=reg,  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        with pytest.raises(LLMError):
            await c.chat(
                "broken",
                [{"role": "user", "content": "This should fail"}],
            )
