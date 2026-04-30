"""Unit tests for aila.platform.llm.client.

Uses mock AsyncOpenAI to test client behavior without real API calls.
Integration tests with real OpenRouter are in test_integration.py (Plan 03).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import BaseModel

from aila.platform.llm.client import AilaLLMClient, LLMResponse, _extract_usage, _merge_usage
from aila.platform.llm.errors import LLMDisabledError, LLMError


# ---------------------------------------------------------------------------
# Test models
# ---------------------------------------------------------------------------

class ScoringOutput(BaseModel):
    score: float
    reasoning: str


# ---------------------------------------------------------------------------
# Fakes (same as test_config.py)
# ---------------------------------------------------------------------------

class FakeRegistry:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}

    def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")


class FakeSecretStore:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = secrets or {}

    def resolve_provider_secret(self, secret_key: str) -> str | None:
        return self._secrets.get(secret_key)


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _make_completion(
    content: str = "Hello",
    finish_reason: str = "stop",
    tool_calls: list[Any] | None = None,
    prompt_tokens: int = 10,
    completion_tokens: int = 5,
) -> MagicMock:
    """Build a mock ChatCompletion response."""
    usage = MagicMock()
    usage.prompt_tokens = prompt_tokens
    usage.completion_tokens = completion_tokens
    usage.total_tokens = prompt_tokens + completion_tokens

    message = MagicMock()
    message.content = content
    message.tool_calls = tool_calls or []

    choice = MagicMock()
    choice.message = message
    choice.finish_reason = finish_reason

    completion = MagicMock()
    completion.choices = [choice]
    completion.usage = usage
    return completion


def _make_tool_call(tc_id: str, name: str, arguments: dict[str, Any]) -> MagicMock:
    """Build a mock tool call object."""
    tc = MagicMock()
    tc.id = tc_id
    tc.function = MagicMock()
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments)
    return tc


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def client() -> AilaLLMClient:
    """Client with API key configured, kill switch off."""
    store = FakeSecretStore({"openai_api_key": "sk-test-key"})
    return AilaLLMClient(
        registry=FakeRegistry(),  # type: ignore[arg-type]
        secret_store=store,  # type: ignore[arg-type]
    )


@pytest.fixture()
def disabled_client() -> AilaLLMClient:
    """Client with kill switch enabled."""
    reg = FakeRegistry({"platform.llm_kill_switch": True})
    store = FakeSecretStore({"openai_api_key": "sk-test-key"})
    return AilaLLMClient(
        registry=reg,  # type: ignore[arg-type]
        secret_store=store,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# chat() tests (LLM-01)
# ---------------------------------------------------------------------------

class TestChat:
    """Basic chat() method."""

    @pytest.mark.asyncio
    async def test_returns_text(self, client: AilaLLMClient) -> None:
        mock_completion = _make_completion(content="The answer is 42")
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            response = await client.chat("scoring", [{"role": "user", "content": "test"}])

        assert isinstance(response, LLMResponse)
        assert response.content == "The answer is 42"
        assert response.disabled is False
        assert response.usage["prompt_tokens"] == 10
        assert response.usage["completion_tokens"] == 5

    @pytest.mark.asyncio
    async def test_kill_switch_returns_disabled(self, disabled_client: AilaLLMClient) -> None:
        response = await disabled_client.chat("scoring", [{"role": "user", "content": "test"}])
        assert response.disabled is True
        assert response.content == "LLM disabled by operator"

    @pytest.mark.asyncio
    async def test_missing_api_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        c = AilaLLMClient(
            registry=FakeRegistry(),  # type: ignore[arg-type]
            secret_store=FakeSecretStore(),  # type: ignore[arg-type]
        )
        with pytest.raises(LLMError, match="No API key configured"):
            await c.chat("scoring", [{"role": "user", "content": "test"}])


# ---------------------------------------------------------------------------
# chat_json() tests (LLM-02)
# ---------------------------------------------------------------------------

class TestChatJson:
    """chat_json() with structured output."""

    @pytest.mark.asyncio
    async def test_returns_json(self, client: AilaLLMClient) -> None:
        json_content = json.dumps({"score": 8.5, "reasoning": "critical vuln"})
        mock_completion = _make_completion(content=json_content)
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            response = await client.chat_json("scoring", [{"role": "user", "content": "score this"}], schema)

        assert response.content == json_content
        parsed = json.loads(response.content)
        assert parsed["score"] == 8.5

    @pytest.mark.asyncio
    async def test_kill_switch(self, disabled_client: AilaLLMClient) -> None:
        schema = ScoringOutput.model_json_schema()
        response = await disabled_client.chat_json("scoring", [{"role": "user", "content": "test"}], schema)
        assert response.disabled is True


# ---------------------------------------------------------------------------
# chat_structured() tests (LLM-10)
# ---------------------------------------------------------------------------

class TestChatStructured:
    """chat_structured() with Pydantic model validation."""

    @pytest.mark.asyncio
    async def test_returns_validated_model(self, client: AilaLLMClient) -> None:
        json_content = json.dumps({"score": 9.0, "reasoning": "exploitable"})
        mock_completion = _make_completion(content=json_content)
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            response = await client.chat_structured(
                "scoring",
                [{"role": "user", "content": "score"}],
                ScoringOutput,
            )

        assert response.disabled is False
        parsed = ScoringOutput.model_validate_json(response.content)
        assert parsed.score == 9.0
        assert parsed.reasoning == "exploitable"

    @pytest.mark.asyncio
    async def test_retry_on_parse_failure(self, client: AilaLLMClient) -> None:
        """First response is invalid, retry returns valid JSON."""
        bad_json = '{"score": "not_a_number", "reasoning": 123}'
        good_json = json.dumps({"score": 7.0, "reasoning": "medium risk"})
        mock_bad = _make_completion(content=bad_json)
        mock_good = _make_completion(content=good_json)
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[mock_bad, mock_good]
            )
            MockOAI.return_value = mock_instance

            response = await client.chat_structured(
                "scoring",
                [{"role": "user", "content": "score"}],
                ScoringOutput,
            )

        parsed = ScoringOutput.model_validate_json(response.content)
        assert parsed.score == 7.0


# ---------------------------------------------------------------------------
# Sync wrappers (LLM-03)
# ---------------------------------------------------------------------------

class TestSyncWrappers:
    """Sync wrappers use asyncio.run()."""

    def test_chat_sync(self, client: AilaLLMClient) -> None:
        mock_completion = _make_completion(content="sync result")
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            response = client.chat_sync("scoring", [{"role": "user", "content": "test"}])

        assert response.content == "sync result"

    def test_chat_json_sync(self, client: AilaLLMClient) -> None:
        json_content = json.dumps({"score": 5.0, "reasoning": "low"})
        mock_completion = _make_completion(content=json_content)
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            response = client.chat_json_sync("scoring", [{"role": "user", "content": "test"}], schema)

        assert json.loads(response.content)["score"] == 5.0

    def test_chat_structured_sync(self, client: AilaLLMClient) -> None:
        json_content = json.dumps({"score": 6.0, "reasoning": "medium"})
        mock_completion = _make_completion(content=json_content)
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            response = client.chat_structured_sync(
                "scoring",
                [{"role": "user", "content": "test"}],
                ScoringOutput,
            )

        parsed = ScoringOutput.model_validate_json(response.content)
        assert parsed.score == 6.0

    @pytest.mark.asyncio
    async def test_chat_json_sync_raises_in_async_context(self, client: AilaLLMClient) -> None:
        """Sync wrappers must raise RuntimeError when called from a running event loop."""
        with pytest.raises(RuntimeError, match="CLI-only sync wrapper"):
            client.chat_json_sync("test", [], {})


# ---------------------------------------------------------------------------
# Retry logic (LLM-05)
# ---------------------------------------------------------------------------

class TestRetry:
    """Retry with backoff on transient errors."""

    @pytest.mark.asyncio
    async def test_retries_on_connection_error(self, client: AilaLLMClient) -> None:
        from openai import APIConnectionError
        mock_completion = _make_completion(content="recovered")
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[
                    APIConnectionError(request=MagicMock()),
                    mock_completion,
                ]
            )
            MockOAI.return_value = mock_instance
            with patch("aila.platform.llm.client.asyncio.sleep", new_callable=AsyncMock):
                response = await client.chat("scoring", [{"role": "user", "content": "test"}])

        assert response.content == "recovered"

    @pytest.mark.asyncio
    async def test_permanent_error_no_retry(self, client: AilaLLMClient) -> None:
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=ValueError("bad request")
            )
            MockOAI.return_value = mock_instance

            with pytest.raises(LLMError, match="bad request"):
                await client.chat("scoring", [{"role": "user", "content": "test"}])

    @pytest.mark.asyncio
    async def test_exhausted_retries(self, client: AilaLLMClient) -> None:
        from openai import APITimeoutError
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=APITimeoutError(request=MagicMock())
            )
            MockOAI.return_value = mock_instance
            with patch("aila.platform.llm.client.asyncio.sleep", new_callable=AsyncMock):
                with pytest.raises(LLMError, match="failed after 3 retries"):
                    await client.chat("scoring", [{"role": "user", "content": "test"}])


# ---------------------------------------------------------------------------
# Truncation detection (LLM-07)
# ---------------------------------------------------------------------------

class TestTruncation:
    """Detect incomplete JSON from max_tokens hit."""

    @pytest.mark.asyncio
    async def test_truncated_json_raises(self, client: AilaLLMClient) -> None:
        truncated = '{"score": 8.5, "reason'  # incomplete
        mock_completion = _make_completion(content=truncated, finish_reason="length")
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            with pytest.raises(LLMError, match="truncated"):
                await client.chat_json("scoring", [{"role": "user", "content": "test"}], schema)

    @pytest.mark.asyncio
    async def test_complete_json_with_length_ok(self, client: AilaLLMClient) -> None:
        """If finish_reason=length but JSON is valid, no error."""
        complete = json.dumps({"score": 8.5, "reasoning": "critical"})
        mock_completion = _make_completion(content=complete, finish_reason="length")
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            response = await client.chat_json("scoring", [{"role": "user", "content": "test"}], schema)

        assert json.loads(response.content)["score"] == 8.5


# ---------------------------------------------------------------------------
# Pydantic fallback (LLM-06)
# ---------------------------------------------------------------------------

class TestPydanticFallback:
    """Client-side parse when model wraps JSON in markdown."""

    @pytest.mark.asyncio
    async def test_extracts_from_code_block(self, client: AilaLLMClient) -> None:
        wrapped = '```json\n{"score": 7.0, "reasoning": "test"}\n```'
        mock_completion = _make_completion(content=wrapped)
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            response = await client.chat_json("scoring", [{"role": "user", "content": "test"}], schema)

        parsed = json.loads(response.content)
        assert parsed["score"] == 7.0

    @pytest.mark.asyncio
    async def test_invalid_json_raises(self, client: AilaLLMClient) -> None:
        garbage = "this is not json at all"
        mock_completion = _make_completion(content=garbage)
        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            with pytest.raises(LLMError, match="not valid JSON"):
                await client.chat_json("scoring", [{"role": "user", "content": "test"}], schema)


# ---------------------------------------------------------------------------
# Tool calling (D-05-new, D-20)
# ---------------------------------------------------------------------------

class TestToolCalling:
    """Tool-calling loop."""

    @pytest.mark.asyncio
    async def test_tool_loop_single_round(self) -> None:
        """Model calls a tool, gets result, then returns final answer."""
        store = FakeSecretStore({"openai_api_key": "sk-test"})
        reg = FakeRegistry({"platform.llm_max_tool_steps_scoring": 5})
        c = AilaLLMClient(registry=reg, secret_store=store)  # type: ignore[arg-type]

        tool_call = _make_tool_call("tc-1", "get_cve", {"cve_id": "CVE-2024-0001"})
        tool_response = _make_completion(
            content="",
            finish_reason="tool_calls",
            tool_calls=[tool_call],
        )
        final_response = _make_completion(content="CVE-2024-0001 is critical")

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[tool_response, final_response]
            )
            MockOAI.return_value = mock_instance

            async def executor(name: str, args: dict[str, Any]) -> str:
                return '{"severity": "CRITICAL"}'

            tools = [{"type": "function", "function": {"name": "get_cve", "parameters": {}}}]
            response = await c.chat(
                "scoring",
                [{"role": "user", "content": "analyze CVE"}],
                tools=tools,
                tool_executor=executor,
            )

        assert response.content == "CVE-2024-0001 is critical"
        assert response.usage["total_tokens"] == 30  # 15 + 15 merged

    @pytest.mark.asyncio
    async def test_tool_calling_disabled_when_max_steps_zero(self) -> None:
        """If max_tool_steps is 0, tool_calls finish_reason is treated as final."""
        store = FakeSecretStore({"openai_api_key": "sk-test"})
        reg = FakeRegistry()  # no llm_max_tool_steps configured = 0
        c = AilaLLMClient(registry=reg, secret_store=store)  # type: ignore[arg-type]

        tool_call = _make_tool_call("tc-1", "get_cve", {"cve_id": "CVE-2024-0001"})
        mock_completion = _make_completion(
            content="I wanted to call a tool but cannot",
            finish_reason="tool_calls",
            tool_calls=[tool_call],
        )

        with patch("aila.platform.llm.client.AsyncOpenAI") as MockOAI:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            MockOAI.return_value = mock_instance

            async def executor(name: str, args: dict[str, Any]) -> str:
                raise AssertionError("Should not be called")

            tools = [{"type": "function", "function": {"name": "get_cve", "parameters": {}}}]
            response = await c.chat(
                "scoring",
                [{"role": "user", "content": "test"}],
                tools=tools,
                tool_executor=executor,
            )

        assert response.content == "I wanted to call a tool but cannot"


# ---------------------------------------------------------------------------
# Usage utilities
# ---------------------------------------------------------------------------

class TestUsageUtils:
    """_extract_usage and _merge_usage."""

    def test_extract_usage_normal(self) -> None:
        comp = _make_completion(prompt_tokens=100, completion_tokens=50)
        usage = _extract_usage(comp)
        assert usage == {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150}

    def test_extract_usage_none(self) -> None:
        comp = MagicMock()
        comp.usage = None
        usage = _extract_usage(comp)
        assert usage == {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}

    def test_merge_usage(self) -> None:
        a = {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
        b = {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}
        merged = _merge_usage(a, b)
        assert merged == {"prompt_tokens": 30, "completion_tokens": 15, "total_tokens": 45}


# ---------------------------------------------------------------------------
# LLMResponse dataclass
# ---------------------------------------------------------------------------

class TestLLMResponse:
    """LLMResponse frozen dataclass."""

    def test_defaults(self) -> None:
        r = LLMResponse(content="hello")
        assert r.content == "hello"
        assert r.model == ""
        assert r.usage == {}
        assert r.disabled is False
        assert r.finish_reason == ""

    def test_frozen(self) -> None:
        r = LLMResponse(content="hello")
        with pytest.raises(AttributeError):
            r.content = "world"  # type: ignore[misc]
