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
from pydantic import BaseModel, ConfigDict

from aila.modules.malware.contracts.playbook import MalwarePlaybookStep
from aila.modules.vr.contracts.pattern import VRPatternCreate
from aila.platform.agents.claim_verifier import _ExtractorProbeSpec
from aila.platform.contracts.reasoning import LedgerWrite, ReasoningTurnDecision
from aila.platform.llm.client import (
    AilaLLMClient,
    LLMResponse,
    _is_strict_schema_rejection,
    _make_strict_schema,
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


_OPEN_OBJECT = {"additionalProperties": True, "title": "Payload", "type": "object"}


def test_free_form_payload_stays_open() -> None:
    schema = _make_strict_schema(LedgerWrite.model_json_schema())
    assert schema["properties"]["payload"] == _OPEN_OBJECT


def test_reasoning_decision_free_form_fields_stay_open() -> None:
    props = _make_strict_schema(ReasoningTurnDecision.model_json_schema())["properties"]
    for field in ("observables", "edit_patches", "payload"):
        assert props[field]["additionalProperties"] is True, field
        assert "properties" not in props[field], field


def test_probe_args_stay_open() -> None:
    props = _make_strict_schema(_ExtractorProbeSpec.model_json_schema())["properties"]
    assert props["args"]["additionalProperties"] is True
    assert "properties" not in props["args"]


def test_pattern_applicability_and_provenance_stay_open() -> None:
    props = _make_strict_schema(VRPatternCreate.model_json_schema())["properties"]
    for field in ("applicability", "provenance"):
        assert props[field]["additionalProperties"] is True, field
        assert "properties" not in props[field], field


def test_playbook_step_free_form_fields_stay_open() -> None:
    props = _make_strict_schema(MalwarePlaybookStep.model_json_schema())["properties"]
    for field in ("args", "expects"):
        assert props[field]["additionalProperties"] is True, field
        assert "properties" not in props[field], field


class _Child(BaseModel):
    x: int


class _Parent(BaseModel):
    child: _Child
    note: str = "n"


def test_declared_child_model_is_closed_and_fully_required() -> None:
    schema = _make_strict_schema(_Parent.model_json_schema())
    child = schema["$defs"]["_Child"]
    assert child["additionalProperties"] is False
    assert child["required"] == ["x"]


def test_explicitly_closed_property_less_object_stays_closed() -> None:
    closed = {"type": "object", "additionalProperties": False}
    result = _make_strict_schema(closed)
    assert result["additionalProperties"] is False
    assert result["properties"] == {}
    assert "required" not in result


def test_empty_closed_model_emits_empty_properties_and_closed() -> None:
    class _Empty(BaseModel):
        model_config = ConfigDict(extra="forbid")

    result = _make_strict_schema(_Empty.model_json_schema())
    assert result["properties"] == {}
    assert result["additionalProperties"] is False


def test_open_mapping_with_empty_properties_stays_open_without_required() -> None:
    schema = {"type": "object", "properties": {}, "additionalProperties": True}
    assert _make_strict_schema(schema) == {
        "type": "object",
        "properties": {},
        "additionalProperties": True,
    }


def test_closed_mapping_with_empty_properties_stays_closed() -> None:
    result = _make_strict_schema(
        {"type": "object", "properties": {}, "additionalProperties": False},
    )
    assert result["properties"] == {}
    assert result["additionalProperties"] is False
    assert "required" not in result


def test_open_mapping_normalizes_dict_valued_additional_properties() -> None:
    schema = {
        "type": "object",
        "additionalProperties": {"$ref": "#/$defs/Child"},
        "$defs": {"Child": {"type": "object", "properties": {"x": {"type": "integer"}}}},
    }
    result = _make_strict_schema(schema)
    assert result["additionalProperties"] == {"$ref": "#/$defs/Child"}
    assert "required" not in result
    child = result["$defs"]["Child"]
    assert child["additionalProperties"] is False
    assert child["required"] == ["x"]


def test_open_mapping_recurses_into_value_items_and_anyof() -> None:
    schema = {
        "type": "object",
        "additionalProperties": {
            "type": "array",
            "items": {"type": "object", "properties": {"y": {"type": "string"}}},
        },
        "anyOf": [{"type": "object", "properties": {"z": {"type": "integer"}}}],
    }
    result = _make_strict_schema(schema)
    assert "required" not in result
    items = result["additionalProperties"]["items"]
    assert items["additionalProperties"] is False
    assert items["required"] == ["y"]
    branch = result["anyOf"][0]
    assert branch["additionalProperties"] is False
    assert branch["required"] == ["z"]
