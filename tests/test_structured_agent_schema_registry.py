"""Tests for StructuredAgent schema registry and CLI ops commands.

AGENT-09: StructuredAgent registers its response_model schema at construction
in _AGENT_SCHEMA_REGISTRY. get_registered_schemas() and get_agent_stats() expose
the data. aila ops list-schemas and aila ops agent-stats surface it via CLI.
"""
from __future__ import annotations

import json
from unittest.mock import MagicMock

from pydantic import BaseModel

from aila.platform.routing.agent import (
    _AGENT_SCHEMA_REGISTRY,
    StructuredAgent,
    _register_agent_schema,
    get_agent_stats,
    get_registered_schemas,
)


class _ModelA(BaseModel):
    value: str


class _ModelB(BaseModel):
    score: int


class _ModelAExtended(BaseModel):
    value: str
    extra: int


def _make_mock_model() -> MagicMock:
    """Return a MagicMock that satisfies the LLMClient protocol."""
    model = MagicMock()
    model.model_id = "test-model"
    return model


# ---------------------------------------------------------------------------
# Test 1: Constructing a StructuredAgent registers schema in the registry
# ---------------------------------------------------------------------------


def test_construction_registers_schema_entry():
    """Constructing a StructuredAgent registers an entry in _AGENT_SCHEMA_REGISTRY."""
    _AGENT_SCHEMA_REGISTRY.clear()

    StructuredAgent(
        model=_make_mock_model(),
        name="test_agent",
        response_model=_ModelA,
    )

    assert "StructuredAgent" in _AGENT_SCHEMA_REGISTRY
    entries = _AGENT_SCHEMA_REGISTRY["StructuredAgent"]
    assert len(entries) == 1
    assert entries[0]["schema_name"] == "_ModelA"
    assert "schema_hash" in entries[0]
    assert "registered_at" in entries[0]


# ---------------------------------------------------------------------------
# Test 2: Two different agent subclasses register two separate entries
# ---------------------------------------------------------------------------


def test_two_agent_classes_register_separate_entries():
    _AGENT_SCHEMA_REGISTRY.clear()

    class _AgentOne(StructuredAgent):
        pass

    class _AgentTwo(StructuredAgent):
        pass

    _register_agent_schema(agent_name="_AgentOne", model_cls=_ModelA)
    _register_agent_schema(agent_name="_AgentTwo", model_cls=_ModelB)

    assert "_AgentOne" in _AGENT_SCHEMA_REGISTRY
    assert "_AgentTwo" in _AGENT_SCHEMA_REGISTRY
    assert _AGENT_SCHEMA_REGISTRY["_AgentOne"][0]["schema_name"] == "_ModelA"
    assert _AGENT_SCHEMA_REGISTRY["_AgentTwo"][0]["schema_name"] == "_ModelB"


# ---------------------------------------------------------------------------
# Test 3: schema_hash changes when the Pydantic model's JSON schema changes
# ---------------------------------------------------------------------------


def test_schema_hash_differs_for_different_models():
    _AGENT_SCHEMA_REGISTRY.clear()

    _register_agent_schema(agent_name="HashAgent", model_cls=_ModelA)
    _register_agent_schema(agent_name="HashAgent", model_cls=_ModelAExtended)

    entries = _AGENT_SCHEMA_REGISTRY["HashAgent"]
    # Both should be registered because they have different hashes
    assert len(entries) == 2
    hashes = {e["schema_hash"] for e in entries}
    assert len(hashes) == 2, "Different schemas should produce different hashes"


# ---------------------------------------------------------------------------
# Test 4: get_registered_schemas() returns flat list with agent_name key
# ---------------------------------------------------------------------------


def test_get_registered_schemas_returns_flat_list():
    _AGENT_SCHEMA_REGISTRY.clear()

    _register_agent_schema(agent_name="AgentAlpha", model_cls=_ModelA)
    _register_agent_schema(agent_name="AgentBeta", model_cls=_ModelB)

    schemas = get_registered_schemas()
    assert isinstance(schemas, list)
    assert len(schemas) == 2

    agent_names = {s["agent_name"] for s in schemas}
    assert "AgentAlpha" in agent_names
    assert "AgentBeta" in agent_names

    for entry in schemas:
        assert "agent_name" in entry
        assert "schema_name" in entry
        assert "schema_hash" in entry
        assert "registered_at" in entry


# ---------------------------------------------------------------------------
# Test 5: Constructing agent with response_model=None does not add registry entry
# ---------------------------------------------------------------------------


def test_no_registry_entry_for_none_response_model():
    _AGENT_SCHEMA_REGISTRY.clear()

    StructuredAgent(
        model=_make_mock_model(),
        name="no_model_agent",
    )

    # Should not have added any registry entry
    assert "StructuredAgent" not in _AGENT_SCHEMA_REGISTRY


# ---------------------------------------------------------------------------
# Test 6: schema_hash is deterministic (same model -> same hash)
# ---------------------------------------------------------------------------


def test_schema_hash_is_deterministic():
    _AGENT_SCHEMA_REGISTRY.clear()

    _register_agent_schema(agent_name="DetAgent", model_cls=_ModelA)
    hash1 = _AGENT_SCHEMA_REGISTRY["DetAgent"][0]["schema_hash"]

    _AGENT_SCHEMA_REGISTRY.clear()
    _register_agent_schema(agent_name="DetAgent", model_cls=_ModelA)
    hash2 = _AGENT_SCHEMA_REGISTRY["DetAgent"][0]["schema_hash"]

    assert hash1 == hash2, "Same Pydantic model should always produce the same schema_hash"


# ---------------------------------------------------------------------------
# Test 7: get_agent_stats() returns dict (may be empty)
# ---------------------------------------------------------------------------


def test_get_agent_stats_returns_dict():
    stats = get_agent_stats()
    assert isinstance(stats, dict)


# ---------------------------------------------------------------------------
# Test 8: aila ops list-schemas CLI command exits 0 and outputs valid JSON
# ---------------------------------------------------------------------------


def test_cli_list_schemas_outputs_valid_json():
    from typer.testing import CliRunner

    from aila.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["ops", "list-schemas"])
    assert result.exit_code == 0, f"Unexpected exit code: {result.exit_code}\n{result.output}"
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)


# ---------------------------------------------------------------------------
# Test 9: aila ops agent-stats CLI command exits 0 and outputs valid JSON
# ---------------------------------------------------------------------------


def test_cli_agent_stats_outputs_valid_json():
    from typer.testing import CliRunner

    from aila.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["ops", "agent-stats"])
    assert result.exit_code == 0, f"Unexpected exit code: {result.exit_code}\n{result.output}"
    parsed = json.loads(result.output)
    assert isinstance(parsed, dict)
