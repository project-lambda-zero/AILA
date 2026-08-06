"""Unit tests for aila.platform.llm.client.

Uses mock AsyncOpenAI to test client behavior without real API calls.
Integration tests with real OpenRouter are in test_integration.py (Plan 03).
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import time
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from openai import APIConnectionError, APITimeoutError
from pydantic import BaseModel

import aila.platform.llm.client as client_mod
from aila.platform.llm.cancellation import (
    LLMCancelledError,
    cancel_for_investigation,
    clear_for_investigation,
    get_cancellation_token,
)
from aila.platform.llm.client import (
    AilaLLMClient,
    LLMResponse,
    _AsyncOpenAIPool,
    _extract_usage,
    _merge_usage,
    _model_supports_temperature,
    _require_choice,
)
from aila.platform.llm.config import LLMConfigProvider, LLMRouting
from aila.platform.llm.errors import LLMError

# ---------------------------------------------------------------------------
# Test models
# ---------------------------------------------------------------------------

class ScoringOutput(BaseModel):
    score: float
    reasoning: str


class TestRequireChoice:
    """_require_choice guards empty provider responses (no opaque IndexError)."""

    def test_empty_choices_raises_retryable(self) -> None:
        completion = MagicMock()
        completion.choices = []
        with pytest.raises(LLMError) as exc_info:
            _require_choice(completion, "hadi")
        assert exc_info.value.retryable is True
        assert "no choices" in str(exc_info.value).lower()

    def test_non_empty_returns_first_choice(self) -> None:
        sentinel = object()
        completion = MagicMock()
        completion.choices = [sentinel, object()]
        assert _require_choice(completion, "hadi") is sentinel


# ---------------------------------------------------------------------------
# Fakes (same as test_config.py)
# ---------------------------------------------------------------------------

class FakeRegistry:
    def __init__(self, data: dict[str, object] | None = None) -> None:
        self._data: dict[str, object] = data or {}

    async def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")


class FakeSecretStore:
    def __init__(self, secrets: dict[str, str] | None = None) -> None:
        self._secrets: dict[str, str] = secrets or {}

    async def resolve_provider_secret(self, secret_key: str) -> str | None:
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
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

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
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

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
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

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
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[mock_bad, mock_good]
            )
            mock_oai.return_value = mock_instance

            response = await client.chat_structured(
                "scoring",
                [{"role": "user", "content": "score"}],
                ScoringOutput,
            )

        parsed = ScoringOutput.model_validate_json(response.content)
        assert parsed.score == 7.0

    @pytest.mark.asyncio
    async def test_recovers_on_final_attempt_within_cap(
        self,
        client: AilaLLMClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """With cap=3, first two attempts malformed, third valid -> recover.

        Verifies the bounded correction loop actually runs to the Nth
        attempt (not just the historical single-retry).
        """
        cap = 3
        monkeypatch.setattr(client_mod, "_STRUCTURED_JSON_MAX_ATTEMPTS", cap)

        bad_1 = '{"score": "nope", "reasoning": 1}'
        bad_2 = '{"score": null, "reasoning": null}'
        good = json.dumps({"score": 4.5, "reasoning": "eventual truth"})
        completions = [
            _make_completion(content=bad_1),
            _make_completion(content=bad_2),
            _make_completion(content=good),
        ]

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(side_effect=completions)
            mock_oai.return_value = mock_instance

            response = await client.chat_structured(
                "scoring",
                [{"role": "user", "content": "score"}],
                ScoringOutput,
            )

            assert mock_instance.chat.completions.create.await_count == cap

        parsed = ScoringOutput.model_validate_json(response.content)
        assert parsed.score == 4.5
        # Accumulated usage across all attempts (each stub returns 10+5=15).
        assert response.usage["total_tokens"] == cap * 15

    @pytest.mark.asyncio
    async def test_raises_after_exactly_cap_on_all_malformed(
        self,
        client: AilaLLMClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """All N attempts malformed -> raise LLMError(retryable=False) after N."""
        cap = 3
        monkeypatch.setattr(client_mod, "_STRUCTURED_JSON_MAX_ATTEMPTS", cap)

        bad = '{"score": "not_a_number", "reasoning": 123}'
        completions = [_make_completion(content=bad) for _ in range(cap)]

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(side_effect=completions)
            mock_oai.return_value = mock_instance

            with pytest.raises(LLMError) as exc_info:
                await client.chat_structured(
                    "scoring",
                    [{"role": "user", "content": "score"}],
                    ScoringOutput,
                )

            # Exactly N calls -- no more, no less.
            assert mock_instance.chat.completions.create.await_count == cap

        assert exc_info.value.retryable is False
        assert "ScoringOutput" in str(exc_info.value)
        assert str(cap) in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_correction_prompt_embeds_verbatim_error_and_partial(
        self,
        client: AilaLLMClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Correction turn injects the pydantic ValidationError text verbatim
        and the extracted partial JSON, so the model can fix the specific
        field rather than reguess the whole schema.
        """
        monkeypatch.setattr(client_mod, "_STRUCTURED_JSON_MAX_ATTEMPTS", 2)

        # Parseable JSON, wrong shape -- ValidationError with a partial payload.
        bad = json.dumps({"score": "not_a_number", "reasoning": 123})
        good = json.dumps({"score": 8.0, "reasoning": "corrected"})

        captured_messages: list[list[dict[str, Any]]] = []

        async def _fake_create(**kwargs: Any) -> MagicMock:
            captured_messages.append(list(kwargs["messages"]))
            if len(captured_messages) == 1:
                return _make_completion(content=bad)
            return _make_completion(content=good)

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(side_effect=_fake_create)
            mock_oai.return_value = mock_instance

            await client.chat_structured(
                "scoring",
                [{"role": "user", "content": "score"}],
                ScoringOutput,
            )

        assert len(captured_messages) == 2
        # The correction turn appends the assistant's bad reply + a user
        # correction. Find the user correction message.
        second_turn = captured_messages[1]
        correction_user = next(
            m for m in second_turn if m["role"] == "user" and "Validation error" in m["content"]
        )
        # Verbatim pydantic error text carries the field name + failure reason.
        assert "score" in correction_user["content"]
        # The prompt exposes the extracted partial JSON so the model sees
        # exactly what it produced.
        assert "not_a_number" in correction_user["content"]
        # And it names the model class explicitly.
        assert "ScoringOutput" in correction_user["content"]

    def test_env_override_controls_attempt_cap(self) -> None:
        """AILA_LLM_STRUCTURED_JSON_MAX_ATTEMPTS controls the cap at import.

        The constant is read at module import time (same pattern as
        _MAX_RETRIES). This test spawns a fresh interpreter under a
        patched env so the read is exercised end-to-end without
        corrupting the parent process's already-imported client module
        (reloading the module would rebind LLMResponse and break every
        subsequent isinstance() check in this test file).
        """
        env = {**os.environ, "AILA_LLM_STRUCTURED_JSON_MAX_ATTEMPTS": "7"}
        result = subprocess.run(
            [
                sys.executable, "-c",
                "import aila.platform.llm.client as m; "
                "print(m._STRUCTURED_JSON_MAX_ATTEMPTS)",
            ],
            check=True, capture_output=True, text=True, env=env,
        )
        assert result.stdout.strip() == "7"


# ---------------------------------------------------------------------------
# Sync wrappers (LLM-03)
# ---------------------------------------------------------------------------

class TestSyncWrappers:
    """Sync wrappers use asyncio.run()."""

    def test_chat_sync(self, client: AilaLLMClient) -> None:
        mock_completion = _make_completion(content="sync result")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

            response = client.chat_sync("scoring", [{"role": "user", "content": "test"}])

        assert response.content == "sync result"

    def test_chat_json_sync(self, client: AilaLLMClient) -> None:
        json_content = json.dumps({"score": 5.0, "reasoning": "low"})
        mock_completion = _make_completion(content=json_content)
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            response = client.chat_json_sync("scoring", [{"role": "user", "content": "test"}], schema)

        assert json.loads(response.content)["score"] == 5.0

    def test_chat_structured_sync(self, client: AilaLLMClient) -> None:
        json_content = json.dumps({"score": 6.0, "reasoning": "medium"})
        mock_completion = _make_completion(content=json_content)
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

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
    """Retry with backoff on transient errors.

    The retry loop calls ``asyncio.sleep(delay)`` between attempts where
    ``delay = min(_RETRY_BASE_DELAY * (2 ** attempt), _RETRY_MAX_DELAY)``
    (see ``aila.platform.llm.client``). With the shipped defaults
    ``_RETRY_BASE_DELAY=1.0`` / ``_RETRY_MAX_DELAY=30.0`` /
    ``_MAX_RETRIES=3`` this yields the backoff schedule 1s, 2s, 4s across
    attempts 0, 1, 2. Assert the schedule directly so the exponential
    curve cannot silently regress to constant or linear backoff without
    failing the suite (#62).
    """

    @pytest.mark.asyncio
    async def test_retries_on_connection_error(self, client: AilaLLMClient) -> None:
        mock_completion = _make_completion(content="recovered")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[
                    APIConnectionError(request=MagicMock()),
                    mock_completion,
                ]
            )
            mock_oai.return_value = mock_instance
            with patch(
                "aila.platform.llm.client.asyncio.sleep", new_callable=AsyncMock,
            ) as mock_sleep:
                response = await client.chat(
                    "scoring", [{"role": "user", "content": "test"}],
                )

        assert response.content == "recovered"
        # One transient failure then success: the retry loop should have
        # awaited sleep exactly once (attempt 0 -> 1.0s backoff) and the
        # provider was called twice (initial + one retry).
        assert mock_sleep.await_count == 1
        assert mock_sleep.await_args_list[0].args == (1.0,)
        assert mock_instance.chat.completions.create.await_count == 2

    @pytest.mark.asyncio
    async def test_permanent_error_no_retry(self, client: AilaLLMClient) -> None:
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            # A 4xx status is classified non-retryable by _is_retryable;
            # a bare unknown exception defaults to retryable by design, so
            # the permanent case must carry a 4xx status_code.
            _perm_err = ValueError("bad request")
            _perm_err.status_code = 400
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=_perm_err
            )
            mock_oai.return_value = mock_instance
            with patch(
                "aila.platform.llm.client.asyncio.sleep", new_callable=AsyncMock,
            ) as mock_sleep:
                with pytest.raises(LLMError, match="bad request"):
                    await client.chat(
                        "scoring", [{"role": "user", "content": "test"}],
                    )

        # Non-retryable error must fail fast: no backoff sleep, single provider call.
        assert mock_sleep.await_count == 0
        assert mock_instance.chat.completions.create.await_count == 1

    @pytest.mark.asyncio
    async def test_exhausted_retries(self, client: AilaLLMClient) -> None:
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=APITimeoutError(request=MagicMock())
            )
            mock_oai.return_value = mock_instance
            with patch(
                "aila.platform.llm.client.asyncio.sleep", new_callable=AsyncMock,
            ) as mock_sleep:
                with pytest.raises(LLMError, match="failed after 3 retries"):
                    await client.chat(
                        "scoring", [{"role": "user", "content": "test"}],
                    )

        # Three attempts total (1 initial + 2 retry sleeps + a final raise
        # after the third failed attempt): the exponential backoff formula
        # min(1.0 * 2**attempt, 30.0) yields 1.0s, 2.0s, 4.0s across
        # attempts 0..2. The loop sleeps BEFORE each attempt after the
        # first, so with _MAX_RETRIES=3 the client awaits sleep 3 times
        # in the sequence [1.0, 2.0, 4.0].
        assert mock_instance.chat.completions.create.await_count == 3
        assert mock_sleep.await_count == 3
        delays = [call.args[0] for call in mock_sleep.await_args_list]
        assert delays == [1.0, 2.0, 4.0], (
            f"exponential backoff schedule regressed: expected [1.0, 2.0, 4.0], "
            f"got {delays}"
        )

    @pytest.mark.asyncio
    async def test_retry_after_header_overrides_backoff(
        self, client: AilaLLMClient,
    ) -> None:
        """429 with a ``Retry-After`` header uses the header value (capped at
        ``_RETRY_MAX_DELAY``) instead of the exponential fallback.

        This is the second backoff path the retry loop supports; assert the
        override so a regression cannot silently swap the header value for
        the exponential curve on rate-limit responses.
        """
        from openai import RateLimitError

        rate_limit_response = MagicMock()
        rate_limit_response.status_code = 429
        rate_limit_response.headers = {"retry-after": "7"}
        rate_limit_exc = RateLimitError(
            message="rate limited",
            response=rate_limit_response,
            body={"error": {"message": "rate limited"}},
        )
        mock_completion = _make_completion(content="recovered")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[rate_limit_exc, mock_completion],
            )
            mock_oai.return_value = mock_instance
            with patch(
                "aila.platform.llm.client.asyncio.sleep", new_callable=AsyncMock,
            ) as mock_sleep:
                response = await client.chat(
                    "scoring", [{"role": "user", "content": "test"}],
                )

        assert response.content == "recovered"
        assert mock_sleep.await_count == 1
        # Header value wins over exponential fallback (7.0s, not 1.0s).
        assert mock_sleep.await_args_list[0].args == (7.0,)


# ---------------------------------------------------------------------------
# Truncation detection (LLM-07)
# ---------------------------------------------------------------------------

class TestTruncation:
    """Detect incomplete JSON from max_tokens hit."""

    @pytest.mark.asyncio
    async def test_truncated_json_raises(self, client: AilaLLMClient) -> None:
        truncated = '{"score": 8.5, "reason'  # incomplete
        mock_completion = _make_completion(content=truncated, finish_reason="length")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            with pytest.raises(LLMError, match="truncated"):
                await client.chat_json("scoring", [{"role": "user", "content": "test"}], schema)

    @pytest.mark.asyncio
    async def test_complete_json_with_length_ok(self, client: AilaLLMClient) -> None:
        """If finish_reason=length but JSON is valid, no error."""
        complete = json.dumps({"score": 8.5, "reasoning": "critical"})
        mock_completion = _make_completion(content=complete, finish_reason="length")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

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
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

            schema = ScoringOutput.model_json_schema()
            response = await client.chat_json("scoring", [{"role": "user", "content": "test"}], schema)

        parsed = json.loads(response.content)
        assert parsed["score"] == 7.0

    @pytest.mark.asyncio
    async def test_invalid_json_raises(self, client: AilaLLMClient) -> None:
        garbage = "this is not json at all"
        mock_completion = _make_completion(content=garbage)
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

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

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[tool_response, final_response]
            )
            mock_oai.return_value = mock_instance

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

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(return_value=mock_completion)
            mock_oai.return_value = mock_instance

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

    @pytest.mark.asyncio
    async def test_tool_executor_timeout_synthesises_result_and_continues(
        self, client: AilaLLMClient
    ) -> None:
        """A tool exceeding routing.tool_timeout_s is surfaced to the model as a
        tool_timeout result and the loop continues; the turn is not blocked and
        the LLM call is not retried from scratch (#44)."""
        routing = LLMRouting(
            model_id="test-model",
            base_url="http://test",
            api_key="sk-test",
            max_tokens=256,
            temperature=0.0,
            max_tool_steps=5,
            task_type="scoring",
            tool_timeout_s=0.1,
        )
        tc = _make_tool_call("tc-1", "slow_tool", {})
        initial_choice = _make_completion(
            content="", finish_reason="tool_calls", tool_calls=[tc]
        ).choices[0]
        final_response = _make_completion(content="done despite timeout")

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(return_value=final_response)

        async def slow_executor(name: str, args: dict[str, Any]) -> str:
            await asyncio.sleep(60)
            return "never returned"

        start = time.perf_counter()
        response = await client._tool_loop(
            client=mock_client,
            routing=routing,
            messages=[{"role": "user", "content": "go"}],
            response_format=None,
            tools=[
                {
                    "type": "function",
                    "function": {"name": "slow_tool", "parameters": {}},
                }
            ],
            tool_executor=slow_executor,
            initial_choice=initial_choice,
            initial_usage={},
        )
        elapsed = time.perf_counter() - start

        assert response.content == "done despite timeout"
        # wait_for cancelled the 60s sleep at the 0.1s bound.
        assert elapsed < 5.0
        # The synthesized timeout result was fed back to the model.
        sent_messages = mock_client.chat.completions.create.call_args.kwargs[
            "messages"
        ]
        tool_msgs = [m for m in sent_messages if m.get("role") == "tool"]
        assert tool_msgs
        assert "tool_timeout" in tool_msgs[-1]["content"]
        assert "slow_tool" in tool_msgs[-1]["content"]


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


# ---------------------------------------------------------------------------
# Tool-timeout config resolution (#44)
# ---------------------------------------------------------------------------

class TestToolTimeoutConfig:
    """resolve_tool_timeout_s precedence: task-specific > global > 300s default."""

    @pytest.mark.asyncio
    async def test_default_is_300(self) -> None:
        p = LLMConfigProvider(FakeRegistry(), FakeSecretStore())  # type: ignore[arg-type]
        assert await p.resolve_tool_timeout_s("scoring") == 300.0

    @pytest.mark.asyncio
    async def test_specific_wins_over_global(self) -> None:
        p = LLMConfigProvider(  # type: ignore[arg-type]
            FakeRegistry(
                {
                    "platform.llm_tool_timeout_s": 120.0,
                    "platform.llm_tool_timeout_s_scoring": 15.0,
                }
            ),
            FakeSecretStore(),
        )
        assert await p.resolve_tool_timeout_s("scoring") == 15.0
        assert await p.resolve_tool_timeout_s("other") == 120.0

    @pytest.mark.asyncio
    async def test_non_numeric_falls_back(self) -> None:
        p = LLMConfigProvider(  # type: ignore[arg-type]
            FakeRegistry({"platform.llm_tool_timeout_s": "not-a-number"}),
            FakeSecretStore(),
        )
        assert await p.resolve_tool_timeout_s("scoring") == 300.0


# ---------------------------------------------------------------------------
# AsyncOpenAI client pool (#44)
# ---------------------------------------------------------------------------

class TestAsyncOpenAIPool:
    """The pool reuses one client per (api_key, base_url, timeout) so the LLM
    call path stops creating (and leaking) a fresh AsyncOpenAI per request."""

    def test_reuses_client_for_same_key(self) -> None:
        pool = _AsyncOpenAIPool()
        c1 = pool.get(api_key="sk-a", base_url="http://x", timeout_s=180.0)
        c2 = pool.get(api_key="sk-a", base_url="http://x", timeout_s=180.0)
        assert c1 is c2

    def test_distinct_client_per_key(self) -> None:
        pool = _AsyncOpenAIPool()
        base = pool.get(api_key="sk-a", base_url="http://x", timeout_s=180.0)
        rotated_key = pool.get(api_key="sk-b", base_url="http://x", timeout_s=180.0)
        other_url = pool.get(api_key="sk-a", base_url="http://y", timeout_s=180.0)
        other_timeout = pool.get(api_key="sk-a", base_url="http://x", timeout_s=60.0)
        assert base is not rotated_key
        assert base is not other_url
        assert base is not other_timeout

    @pytest.mark.asyncio
    async def test_aclose_closes_all_and_empties_pool(self) -> None:
        """aclose awaits every pooled client's close() and drops the entries so
        the underlying httpx.AsyncClient releases connections on shutdown
        instead of leaking to GC."""
        pool = _AsyncOpenAIPool()
        c1 = pool.get(api_key="sk-a", base_url="http://x", timeout_s=180.0)
        c2 = pool.get(api_key="sk-b", base_url="http://x", timeout_s=180.0)
        c1.close = AsyncMock()
        c2.close = AsyncMock()
        await pool.aclose()
        assert c1.close.await_count == 1
        assert c2.close.await_count == 1
        # Post-close: a fresh get() rebuilds -- pool is not permanently poisoned.
        assert pool.get(api_key="sk-a", base_url="http://x", timeout_s=180.0) is not c1

    @pytest.mark.asyncio
    async def test_aclose_swallows_per_client_failure(self) -> None:
        """A single pooled client raising on close() must not block the others."""
        pool = _AsyncOpenAIPool()
        c_bad = pool.get(api_key="sk-a", base_url="http://x", timeout_s=180.0)
        c_ok = pool.get(api_key="sk-b", base_url="http://x", timeout_s=180.0)
        c_bad.close = AsyncMock(side_effect=RuntimeError("already closed"))
        c_ok.close = AsyncMock()
        await pool.aclose()
        assert c_ok.close.await_count == 1  # not blocked by c_bad


# ---------------------------------------------------------------------------
# AilaLLMClient.aclose delegates to the pool (#44)
# ---------------------------------------------------------------------------

class TestClientAclose:
    """The client exposes ``aclose`` so worker/API shutdown hooks release
    the pooled ``AsyncOpenAI`` connections instead of leaking on GC."""

    @pytest.mark.asyncio
    async def test_aclose_delegates_to_pool(self, client: AilaLLMClient) -> None:
        client._client_pool.aclose = AsyncMock()  # type: ignore[method-assign]
        await client.aclose()
        assert client._client_pool.aclose.await_count == 1  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Temperature-rejection markers matched on boundaries, not substrings (#44)
# ---------------------------------------------------------------------------

class TestTemperatureMarkerBoundaries:
    """The old ``marker in model_id`` test stripped temperature from any id that
    happened to contain ``o1`` / ``o3`` / ``o4`` (``proto1``, ``audio1``,
    ``proto3``). Match on alphanumeric boundaries so a substring collision no
    longer silently drops the model's temperature."""

    def test_real_o3_stripped(self) -> None:
        assert _model_supports_temperature("o3") is False
        assert _model_supports_temperature("o3-mini") is False
        assert _model_supports_temperature("openai/o3-mini") is False

    def test_substring_collision_not_stripped(self) -> None:
        # These are non-o-series models that happen to contain the marker
        # substring; the old ``in`` check falsely stripped temperature.
        assert _model_supports_temperature("proto3") is True
        assert _model_supports_temperature("audio1") is True
        assert _model_supports_temperature("proto1-instruct") is True
        assert _model_supports_temperature("o4mini") is True  # concatenated -- not the o4 family marker


# ---------------------------------------------------------------------------
# LLMResponse declares pipeline metadata fields (#44)
# ---------------------------------------------------------------------------

class TestLLMResponsePipelineFields:
    """The dataclass is frozen + slots. Constructing with the pipeline metadata
    kwargs (``classification`` / ``confidence`` / ``seal_id`` /
    ``pipeline_metadata``) must not raise -- the moment a pipeline step wrote a
    non-None value into the ctx and _enrich_response tried to construct with
    those kwargs, the missing declaration used to TypeError in prod."""

    def test_construct_with_all_pipeline_fields(self) -> None:
        r = LLMResponse(
            content="hello",
            classification="safe",
            confidence=0.87,
            seal_id="seal-xyz",
            pipeline_metadata={"evidence_validation": {"ok": True}},
        )
        assert r.classification == "safe"
        assert r.confidence == 0.87
        assert r.seal_id == "seal-xyz"
        assert r.pipeline_metadata == {"evidence_validation": {"ok": True}}


# ---------------------------------------------------------------------------
# Cancellation checks around the retry / tool loop (#44)
# ---------------------------------------------------------------------------

class TestCancellationChecks:
    """Retry-loop, pre-tool-loop, and per-tool-step cancellation guards so a
    paused/cancelled investigation stops burning credits instead of waiting
    out the retry schedule or the next tool call."""

    @pytest.mark.asyncio
    async def test_retry_loop_aborts_when_cancelled(
        self, client: AilaLLMClient
    ) -> None:
        run_id = "inv-retry-cancel"
        get_cancellation_token(run_id)
        cancel_for_investigation(run_id)
        try:
            with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
                mock_instance = AsyncMock()
                mock_instance.chat.completions.create = AsyncMock(
                    return_value=_make_completion(content="never returned"),
                )
                mock_oai.return_value = mock_instance
                with pytest.raises(LLMCancelledError):
                    await client.chat(
                        "scoring",
                        [{"role": "user", "content": "go"}],
                        run_id=run_id,
                    )
        finally:
            clear_for_investigation(run_id)

    @pytest.mark.asyncio
    async def test_tool_loop_step_check_aborts_between_tools(
        self, client: AilaLLMClient
    ) -> None:
        """A cancellation flipped after the first LLM turn (which produced
        tool_calls) is caught at the top of the tool loop's next step so no
        tools fire against the cancelled investigation."""
        run_id = "inv-tool-loop-cancel"
        get_cancellation_token(run_id)
        # Flip the token BEFORE the tool loop is invoked so its top-of-step
        # peek fires first, before any executor runs.
        cancel_for_investigation(run_id)

        routing = LLMRouting(
            model_id="test-model",
            base_url="http://test",
            api_key="sk-test",
            max_tokens=256,
            temperature=0.0,
            max_tool_steps=5,
            task_type="scoring",
            tool_timeout_s=30.0,
        )
        tc = _make_tool_call("tc-cancel", "noop_tool", {})
        initial_choice = _make_completion(
            content="", finish_reason="tool_calls", tool_calls=[tc]
        ).choices[0]

        executor_calls: list[str] = []

        async def executor(name: str, args: dict[str, Any]) -> str:
            executor_calls.append(name)
            return "{}"

        mock_client = AsyncMock()
        mock_client.chat.completions.create = AsyncMock(
            return_value=_make_completion(content="never returned"),
        )

        try:
            with pytest.raises(LLMCancelledError):
                await client._tool_loop(
                    client=mock_client,
                    routing=routing,
                    messages=[{"role": "user", "content": "go"}],
                    response_format=None,
                    tools=[
                        {
                            "type": "function",
                            "function": {"name": "noop_tool", "parameters": {}},
                        }
                    ],
                    tool_executor=executor,
                    initial_choice=initial_choice,
                    initial_usage={},
                    run_id=run_id,
                )
            # No tool ran because the cancel check fired at step 1's top.
            assert executor_calls == []
        finally:
            clear_for_investigation(run_id)


# ---------------------------------------------------------------------------
# Retry idempotency -- side-effectful tools not replayed (#44)
# ---------------------------------------------------------------------------

class TestRetryIdempotency:
    """Once a tool_executor call has committed in an attempt, any subsequent
    transient failure must NOT retry the outer call -- doing so would re-issue
    the same tool (or a new tool from a fresh model turn) and duplicate the
    side effects."""

    @pytest.mark.asyncio
    async def test_post_tool_failure_does_not_replay_tools(self) -> None:
        """First model turn issues tool_calls; the executor runs; the follow-up
        model call raises APIConnectionError. The outer retry loop must give
        up (retry disabled by the commit-gate) and surface a non-retryable
        LLMError instead of replaying the whole attempt (which would fire the
        executor a second time)."""
        # max_tool_steps>0 required or the tool loop never runs.
        store = FakeSecretStore({"openai_api_key": "sk-test"})
        reg = FakeRegistry({"platform.llm_max_tool_steps_scoring": 5})
        client = AilaLLMClient(registry=reg, secret_store=store)  # type: ignore[arg-type]
        # tc-1 is what the model asks for; the executor records every call.
        tc = _make_tool_call("tc-1", "side_effectful", {"cve": "CVE-1"})
        first_response = _make_completion(
            content="", finish_reason="tool_calls", tool_calls=[tc]
        )
        # After the tool runs, the next model round-trip fails transiently.
        # A naive retry would restart the pipeline, replay _pipeline.run, and
        # execute the same tool again.
        executor_calls: list[dict[str, Any]] = []

        async def executor(name: str, args: dict[str, Any]) -> str:
            executor_calls.append({"name": name, "args": args})
            return '{"severity": "CRITICAL"}'

        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            # Turn 1 (initial) -> tool_calls; Turn 2 (post-tool) -> raise.
            # Any further turn would indicate an unwanted retry.
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[
                    first_response,
                    APIConnectionError(request=MagicMock()),
                    # Guard: if the retry gate fails and a replay happens, the
                    # third call would land here. We assert it never does.
                    _make_completion(content="unexpected replay success"),
                ]
            )
            mock_oai.return_value = mock_instance

            tools = [
                {
                    "type": "function",
                    "function": {
                        "name": "side_effectful",
                        "parameters": {},
                    },
                }
            ]
            with patch(
                "aila.platform.llm.client.asyncio.sleep", new_callable=AsyncMock
            ):
                with pytest.raises(LLMError) as exc_info:
                    await client.chat(
                        "scoring",
                        [{"role": "user", "content": "test"}],
                        tools=tools,
                        tool_executor=executor,
                    )

        # The commit-gate marks the wrapped error non-retryable so the ARQ
        # layer sees a terminal failure and cursor SSOT decides recovery.
        assert exc_info.value.retryable is False
        assert "already committed" in str(exc_info.value)
        # Executor fired exactly once; the retry did NOT replay the tool.
        assert len(executor_calls) == 1

    @pytest.mark.asyncio
    async def test_pre_tool_failure_still_retries(
        self, client: AilaLLMClient
    ) -> None:
        """A failure BEFORE any tool has run must remain retryable -- this is
        the normal transient-error recovery path and is not gated."""
        good = _make_completion(content="recovered")
        with patch("aila.platform.llm.client.AsyncOpenAI") as mock_oai:
            mock_instance = AsyncMock()
            mock_instance.chat.completions.create = AsyncMock(
                side_effect=[APIConnectionError(request=MagicMock()), good]
            )
            mock_oai.return_value = mock_instance
            with patch(
                "aila.platform.llm.client.asyncio.sleep", new_callable=AsyncMock
            ):
                response = await client.chat(
                    "scoring",
                    [{"role": "user", "content": "test"}],
                )
        assert response.content == "recovered"
