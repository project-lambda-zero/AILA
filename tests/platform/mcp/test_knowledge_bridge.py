"""KnowledgeBridgeTool -- RFC-12 agentic retrieval bridge.

Guards the read-only + server-side-scope contract that keeps the agent's
knowledge surface safe: only ``retrieve`` is dispatchable (no write path),
and a retrieve with no server-injected ``_namespaces`` is refused rather
than run unscoped (cross-workspace). These paths short-circuit before any
KnowledgeService call, so they need no database.
"""
from __future__ import annotations

import asyncio

from aila.platform.agents.prompt_sections import render_available_tools_section
from aila.platform.mcp.bridges.knowledge import KnowledgeBridgeTool


def _run(coro):
    return asyncio.run(coro)


class TestKnowledgeBridgeReadOnly:
    def test_list_tool_specs_exposes_only_retrieve(self) -> None:
        specs = _run(KnowledgeBridgeTool().list_tool_specs())
        assert [s["name"] for s in specs] == ["retrieve"]

    def test_store_action_refused(self) -> None:
        result = _run(
            KnowledgeBridgeTool().forward(
                "store", query="x", _namespaces=["vr.audit_memo.workspace.w"],
            ),
        )
        assert result["status"] == "error"
        assert "retrieve" in result["error"]

    def test_arbitrary_mutating_action_refused(self) -> None:
        result = _run(KnowledgeBridgeTool().forward("delete", query="x"))
        assert result["status"] == "error"


class TestKnowledgeBridgeScopeRefusal:
    def test_missing_scope_refused(self) -> None:
        # No server-injected _namespaces -> refuse rather than run unscoped.
        result = _run(KnowledgeBridgeTool().forward("retrieve", query="q"))
        assert result["status"] == "error"
        assert "scope" in result["error"].lower()

    def test_empty_scope_refused(self) -> None:
        result = _run(
            KnowledgeBridgeTool().forward("retrieve", query="q", _namespaces=[]),
        )
        assert result["status"] == "error"

    def test_empty_query_refused(self) -> None:
        result = _run(
            KnowledgeBridgeTool().forward(
                "retrieve", query="   ", _namespaces=["vr.audit_memo.workspace.w"],
            ),
        )
        assert result["status"] == "error"
        assert "query" in result["error"].lower()


class TestKnowledgeBridgePromptSignature:
    def test_rendered_retrieve_signature_lists_its_arguments(self) -> None:
        specs = _run(KnowledgeBridgeTool().list_tool_specs())
        out = render_available_tools_section(
            "source_repo",
            {"knowledge": specs},
            applicable_servers={"knowledge"},
            applicable_servers_for_kind=lambda _kind: set(),
        )
        line = next(ln for ln in out.splitlines() if "`knowledge.retrieve(" in ln)
        assert "query: string [required]" in line
        assert "limit: integer = 8" in line
        assert "route: string" in line
