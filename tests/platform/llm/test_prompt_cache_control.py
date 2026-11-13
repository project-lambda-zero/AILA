"""Prompt-cache TTL reaches outgoing Claude-family requests as cache_control.

Each test captures the payload handed to the OpenAI-compatible transport, so
the assertions observe what a provider receives. Helpers are local: this module
does not import from other test modules.
"""

from __future__ import annotations

import copy
import json
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aila.platform.llm.client import AilaLLMClient

CLAUDE_MODEL = "anthropic/claude-sonnet-4.5"
OPENAI_MODEL = "openai/gpt-4o"
GOOGLE_MODEL = "google/gemini-2.5-pro"

SYSTEM_TEXT = "You are a security analyst. Reply with JSON only."
USER_TEXT = "Score this finding."

FIVE_MINUTE = {"type": "ephemeral", "ttl": "5m"}
ONE_HOUR = {"type": "ephemeral", "ttl": "1h"}
BARE = {"type": "ephemeral"}


class _Registry:
    """Config reads keyed ``namespace.key``, matching FakeRegistry in test_client.py."""

    def __init__(self, data: dict[str, object]) -> None:
        self._data = data

    async def get(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")

    def get_sync(self, namespace: str, key: str) -> object:
        return self._data.get(f"{namespace}.{key}")


class _SecretStore:
    async def resolve_provider_secret(self, secret_key: str) -> str | None:
        return {"openai_api_key": "sk-test-key"}.get(secret_key)


def _client(model: str, ttl: int, *, max_tool_steps: int = 0) -> AilaLLMClient:
    data: dict[str, object] = {
        "platform.llm_model_scoring": model,
        "platform.llm_max_tool_steps_scoring": max_tool_steps,
        "platform.prompt_cache_ttl_seconds": ttl,
    }
    return AilaLLMClient(
        registry=_Registry(data),  # type: ignore[arg-type]
        secret_store=_SecretStore(),  # type: ignore[arg-type]
    )


def _completion(
    content: str = "ok",
    finish_reason: str = "stop",
    tool_calls: list[Any] | None = None,
) -> MagicMock:
    usage = MagicMock()
    usage.prompt_tokens = 10
    usage.completion_tokens = 5
    usage.total_tokens = 15

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


def _tool_call(tc_id: str, name: str, arguments: dict[str, Any]) -> MagicMock:
    tc = MagicMock()
    tc.id = tc_id
    tc.function = MagicMock()
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments)
    return tc


@contextmanager
def _transport(responses: list[MagicMock]) -> Generator[AsyncMock, None, None]:
    """Patch the OpenAI transport and cost persistence; yield the create mock."""
    create = AsyncMock(side_effect=responses)
    instance = AsyncMock()
    instance.chat.completions.create = create
    with (
        patch("aila.platform.llm.client.AsyncOpenAI", return_value=instance),
        patch("aila.platform.llm.cost.calculate_cost_usd", AsyncMock(return_value=(0.0, True))),
        patch("aila.platform.llm.cost.persist_cost_record", AsyncMock()),
    ):
        yield create


def _messages() -> list[dict[str, Any]]:
    return [
        {"role": "system", "content": SYSTEM_TEXT},
        {"role": "user", "content": USER_TEXT},
    ]


def _annotated(marker: dict[str, str]) -> list[dict[str, Any]]:
    """Expected provider payload: the stable system prefix carries the breakpoint."""
    return [
        {
            "role": "system",
            "content": [{"type": "text", "text": SYSTEM_TEXT, "cache_control": marker}],
        },
        {"role": "user", "content": USER_TEXT},
    ]


def _sent(create: AsyncMock, index: int = 0) -> list[dict[str, Any]]:
    return create.call_args_list[index].kwargs["messages"]


@pytest.mark.asyncio
async def test_claude_five_minute_ttl_marks_stable_system_prefix() -> None:
    client = _client(CLAUDE_MODEL, ttl=300)
    with _transport([_completion()]) as create:
        await client.chat("scoring", _messages())
    assert _sent(create) == _annotated(FIVE_MINUTE)


@pytest.mark.asyncio
async def test_two_positive_ttls_select_their_own_lifetime_without_touching_stable_text() -> None:
    short = _client(CLAUDE_MODEL, ttl=300)
    long = _client(CLAUDE_MODEL, ttl=3600)
    with _transport([_completion()]) as create_short:
        await short.chat("scoring", _messages())
    with _transport([_completion()]) as create_long:
        await long.chat("scoring", _messages())
    assert _sent(create_short) == _annotated(FIVE_MINUTE)
    assert _sent(create_long) == _annotated(ONE_HOUR)


@pytest.mark.asyncio
async def test_repeated_requests_with_same_ttl_send_identical_stable_prefix() -> None:
    client = _client(CLAUDE_MODEL, ttl=3600)
    with _transport([_completion(), _completion()]) as create:
        await client.chat("scoring", _messages())
        await client.chat("scoring", _messages())
    assert _sent(create, 0) == _sent(create, 1) == _annotated(ONE_HOUR)


@pytest.mark.asyncio
async def test_zero_ttl_sends_bare_marker_for_provider_default_lifetime() -> None:
    client = _client(CLAUDE_MODEL, ttl=0)
    with _transport([_completion()]) as create:
        await client.chat("scoring", _messages())
    assert _sent(create) == _annotated(BARE)


@pytest.mark.asyncio
@pytest.mark.parametrize("model", [OPENAI_MODEL, GOOGLE_MODEL])
async def test_automatic_cache_providers_receive_messages_unchanged(model: str) -> None:
    client = _client(model, ttl=3600)
    with _transport([_completion()]) as create:
        await client.chat("scoring", _messages())
    assert _sent(create) == _messages()


@pytest.mark.asyncio
async def test_caller_message_list_is_not_modified() -> None:
    client = _client(CLAUDE_MODEL, ttl=3600)
    messages = _messages()
    snapshot = copy.deepcopy(messages)
    with _transport([_completion()]) as create:
        await client.chat("scoring", messages)
    assert messages == snapshot
    assert _sent(create) == _annotated(ONE_HOUR)


@pytest.mark.asyncio
async def test_tool_loop_annotates_each_step_and_keeps_caller_list() -> None:
    client = _client(CLAUDE_MODEL, ttl=300, max_tool_steps=5)
    tools = [
        {
            "type": "function",
            "function": {"name": "get_cve", "parameters": {"type": "object", "properties": {}}},
        }
    ]
    executed: list[tuple[str, dict[str, Any]]] = []

    async def executor(name: str, args: dict[str, Any]) -> str:
        executed.append((name, args))
        return '{"cvss": 9.8}'

    responses = [
        _completion(
            finish_reason="tool_calls",
            tool_calls=[_tool_call("tc-1", "get_cve", {"cve_id": "CVE-2024-0001"})],
        ),
        _completion(content="done"),
    ]
    messages = _messages()
    snapshot = copy.deepcopy(messages)
    with _transport(responses) as create:
        result = await client.chat("scoring", messages, tools=tools, tool_executor=executor)

    assert result.content == "done"
    assert executed == [("get_cve", {"cve_id": "CVE-2024-0001"})]
    assert messages == snapshot
    assert _sent(create, 0) == _annotated(FIVE_MINUTE)
    second = _sent(create, 1)
    assert second[0] == _annotated(FIVE_MINUTE)[0]
    assert second[1] == {"role": "user", "content": USER_TEXT}
    assert [m["role"] for m in second[2:]] == ["assistant", "tool"]
