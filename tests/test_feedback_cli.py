"""Tests for aila feedback CLI sub-app (store and retrieve commands)."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from aila.cli import app

runner = CliRunner()


def _make_tool_registry(store_result=None, retrieve_result=None):
    """Build a mock ToolRegistry with store and retrieve tools wired."""
    store_tool = MagicMock()
    store_tool.forward.return_value = store_result or {"entry_id": "abc-123"}

    retrieve_tool = MagicMock()
    retrieve_tool.forward.return_value = retrieve_result or {
        "status": "retrieved",
        "count": 2,
        "results": [
            {"content": "first result text", "score": 0.9, "source": "platform"},
            {"content": "second result text", "score": 0.75, "source": "platform"},
        ],
    }

    tool_registry = MagicMock()
    tool_registry.require.side_effect = lambda key, cls: (
        store_tool if key == "knowledge.store" else retrieve_tool
    )
    return tool_registry, store_tool, retrieve_tool


# ---------------------------------------------------------------------------
# feedback store
# ---------------------------------------------------------------------------

class TestFeedbackStore:
    def test_store_echoes_entry_id(self):
        registry, store_tool, _ = _make_tool_registry()
        with patch("aila.cli._build_tool_registry", return_value=registry):
            result = runner.invoke(app, ["feedback", "store", "--content", "test entry"])
        assert result.exit_code == 0
        assert "Stored entry abc-123." in result.output

    def test_store_calls_forward_with_content(self):
        registry, store_tool, _ = _make_tool_registry()
        with patch("aila.cli._build_tool_registry", return_value=registry):
            runner.invoke(app, ["feedback", "store", "--content", "important note"])
        store_tool.forward.assert_called_once_with(content="important note", metadata=None)

    def test_store_with_tags_passes_metadata(self):
        registry, store_tool, _ = _make_tool_registry()
        with patch("aila.cli._build_tool_registry", return_value=registry):
            runner.invoke(app, ["feedback", "store", "--content", "tagged note", "--tags", "cve,patch"])
        store_tool.forward.assert_called_once_with(
            content="tagged note",
            metadata={"tags": ["cve", "patch"]},
        )

    def test_store_with_tags_strips_whitespace(self):
        registry, store_tool, _ = _make_tool_registry()
        with patch("aila.cli._build_tool_registry", return_value=registry):
            runner.invoke(app, ["feedback", "store", "--content", "x", "--tags", " cve , patch "])
        store_tool.forward.assert_called_once_with(
            content="x",
            metadata={"tags": ["cve", "patch"]},
        )

    def test_store_with_empty_tags_passes_no_metadata(self):
        registry, store_tool, _ = _make_tool_registry()
        with patch("aila.cli._build_tool_registry", return_value=registry):
            runner.invoke(app, ["feedback", "store", "--content", "no tags", "--tags", ""])
        store_tool.forward.assert_called_once_with(content="no tags", metadata=None)

    def test_store_exception_exits_1(self):
        registry = MagicMock()
        registry.require.side_effect = RuntimeError("tool not found")
        with patch("aila.cli._build_tool_registry", return_value=registry):
            result = runner.invoke(app, ["feedback", "store", "--content", "test"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# feedback retrieve
# ---------------------------------------------------------------------------

class TestFeedbackRetrieve:
    def test_retrieve_prints_formatted_results(self):
        registry, _, retrieve_tool = _make_tool_registry()
        with patch("aila.cli._build_tool_registry", return_value=registry):
            result = runner.invoke(app, ["feedback", "retrieve", "--query", "openssh cve"])
        assert result.exit_code == 0
        assert "[0.900] first result text" in result.output
        assert "[0.750] second result text" in result.output

    def test_retrieve_calls_forward_with_query_and_default_limit(self):
        registry, _, retrieve_tool = _make_tool_registry()
        with patch("aila.cli._build_tool_registry", return_value=registry):
            runner.invoke(app, ["feedback", "retrieve", "--query", "openssh cve"])
        retrieve_tool.forward.assert_called_once_with(query="openssh cve", limit=10)

    def test_retrieve_with_custom_limit(self):
        registry, _, retrieve_tool = _make_tool_registry()
        with patch("aila.cli._build_tool_registry", return_value=registry):
            runner.invoke(app, ["feedback", "retrieve", "--query", "test", "--limit", "25"])
        retrieve_tool.forward.assert_called_once_with(query="test", limit=25)

    def test_retrieve_no_results_prints_message(self):
        no_results = {"status": "retrieved", "count": 0, "results": []}
        registry, _, _ = _make_tool_registry(retrieve_result=no_results)
        with patch("aila.cli._build_tool_registry", return_value=registry):
            result = runner.invoke(app, ["feedback", "retrieve", "--query", "nothing here"])
        assert result.exit_code == 0
        assert "No results found." in result.output

    def test_retrieve_exception_exits_1(self):
        registry = MagicMock()
        registry.require.side_effect = RuntimeError("db unavailable")
        with patch("aila.cli._build_tool_registry", return_value=registry):
            result = runner.invoke(app, ["feedback", "retrieve", "--query", "test"])
        assert result.exit_code == 1
