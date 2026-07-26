"""Strict json_schema -> json_object fallback for open-dict schemas.

Guards the wiring fix that lets reasoning turns run on strict
OpenAI-compatible providers: a schema carrying a free-form dict
(observables / payload) is rejected by strict providers, so chat_json must
retry the same call in json_object mode with the schema appended to the
prompt, instead of failing the whole turn.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock

import pytest

from aila.platform.llm.client import (
    AilaLLMClient,
    LLMResponse,
    _is_strict_schema_rejection,
    _schema_has_open_object,
)
from aila.platform.llm.errors import LLMError


class _FakeRegistry:
    async def get(self, namespace: str, key: str) -> object:
        del namespace, key
        return None


class _FakeSecretStore:
    async def resolve_provider_secret(self, secret_key: str) -> str | None:
        del secret_key
        return "sk-test-key"


def _client() -> AilaLLMClient:
    return AilaLLMClient(
        registry=_FakeRegistry(),  # type: ignore[arg-type]
        secret_store=_FakeSecretStore(),  # type: ignore[arg-type]
    )


_OPEN = {
    "type": "object",
    "title": "T",
    "properties": {
        "reasoning": {"type": "string"},
        "observables": {"type": "object", "additionalProperties": True},
    },
    "required": ["reasoning"],
}
_CLOSED = {
    "type": "object",
    "title": "T",
    "properties": {"score": {"type": "number"}, "reasoning": {"type": "string"}},
    "required": ["score", "reasoning"],
    "additionalProperties": False,
}


def test_open_object_detected() -> None:
    assert _schema_has_open_object(_OPEN) is True


def test_closed_schema_not_flagged() -> None:
    assert _schema_has_open_object(_CLOSED) is False


def test_open_object_detected_in_defs() -> None:
    schema = {
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/Inner"}},
        "$defs": {"Inner": {"type": "object", "additionalProperties": True}},
    }
    assert _schema_has_open_object(schema) is True


def test_schema_rejection_matches_provider_400() -> None:
    exc = LLMError(
        "LLM non-retryable provider error: BadRequestError: Error code: 400 - "
        "{'error': {'message': \"[400]: invalid request: response_format "
        "validation: invalid 'json_schema' provided: error at "
        "'properties.observables': object type must have at least one required field\"}}"
    )
    assert _is_strict_schema_rejection(exc) is True


@pytest.mark.parametrize(
    "message",
    [
        "LLM API failed after 3 retries: Error code: 503 - all upstream accounts are inactive",
        "too many tokens: max tokens must be less than or equal to 8192",
        "Model 'gpt-4.1-nano' is currently unavailable.",
    ],
)
def test_non_schema_errors_not_matched(message: str) -> None:
    assert _is_strict_schema_rejection(LLMError(message)) is False


@pytest.mark.asyncio
async def test_open_schema_falls_back_to_json_object(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    good = LLMResponse(
        content=json.dumps({"reasoning": "ok", "observables": {}}),
        model="test",
        usage={"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
        finish_reason="stop",
    )
    rejection = LLMError(
        "provider error: 400 response_format validation: invalid 'json_schema' "
        "provided: object type must have at least one required field"
    )
    mock = AsyncMock(side_effect=[rejection, good])
    monkeypatch.setattr(client, "_call_with_retry", mock)

    resp = await client.chat_json("scoring", [{"role": "user", "content": "x"}], _OPEN)

    assert resp.content == good.content
    assert mock.call_count == 2
    first_rf: dict[str, Any] = mock.call_args_list[0].kwargs["response_format"]
    second_rf: dict[str, Any] = mock.call_args_list[1].kwargs["response_format"]
    assert first_rf["type"] == "json_schema"
    assert second_rf == {"type": "json_object"}
    # The schema is appended to the prompt on the fallback so a weak model
    # still has the exact field spec.
    second_msgs = mock.call_args_list[1].kwargs["messages"]
    assert any("observables" in m["content"] for m in second_msgs)


@pytest.mark.asyncio
async def test_non_schema_error_propagates(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    inactive = LLMError("Error code: 503 - all upstream accounts are inactive")
    mock = AsyncMock(side_effect=[inactive])
    monkeypatch.setattr(client, "_call_with_retry", mock)

    with pytest.raises(LLMError) as excinfo:
        await client.chat_json("scoring", [{"role": "user", "content": "x"}], _OPEN)
    assert "inactive" in str(excinfo.value)
    assert mock.call_count == 1
