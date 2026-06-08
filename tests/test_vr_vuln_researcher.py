"""M3.R-2 — HonestVulnResearcher unit tests.

Pure-helper tests (no DB, no LLM). The full DB-round-trip test for
``run_turn`` requires fixtures that stand up the schema + insert a
target / investigation / branch, which is more work than warranted
here — that path will get its integration test once the workflow
state machine (M3.R-7) is wired.
"""
from __future__ import annotations

import json

import pytest

from aila.modules.vr.agents.vuln_researcher import (
    _applicable_servers_for_kind,
    _decision_to_message_payload,
    _decode_case_state,
    _encode_case_state,
    _fetch_tool_specs,
    _format_param,
    _load_prompt,
    _mcp_family_rule_for_kind,
    _outcome_payload,
    _render_available_tools_section,
    _render_operator_messages_section,
    _terminal_outcome_kind,
    _to_outcome_confidence,
)
from aila.modules.vr.contracts import OutcomeConfidence, OutcomeKind, PayloadKind
from aila.modules.vr.tools.android_mcp_bridge import AndroidMcpBridgeTool
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.contracts.reasoning import (
    EvidenceProvenance,
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    ReasoningTurnDecision,
    RejectedHypothesis,
)


class TestCaseStateEncoding:
    def test_round_trip(self) -> None:
        original = ReasoningCaseState(
            contract=ReasoningContract(answer_type="x", answer_format="json"),
            hypotheses=[Hypothesis(id="h1", claim="c", why_plausible="w", kill_criterion="k")],
            rejected=[RejectedHypothesis(id="h0", claim="old", reason="r")],
            observables={"k": "v"},
        )
        encoded = _encode_case_state(original)
        assert isinstance(encoded, str)
        restored = _decode_case_state(encoded)
        assert restored == original

    def test_empty_decode(self) -> None:
        assert _decode_case_state(None) == ReasoningCaseState()
        assert _decode_case_state("") == ReasoningCaseState()

    def test_invalid_json_decode_recovers(self) -> None:
        assert _decode_case_state("{not json") == ReasoningCaseState()

    def test_invalid_shape_recovers(self) -> None:
        assert _decode_case_state(json.dumps({"hypotheses": "not a list"})) == ReasoningCaseState()


class TestDecisionToMessagePayload:
    def test_tool_run(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="run decompile on the suspect",
            action="tool_run",
            expected_observation="pseudocode of the function",
            command="decompile",
            script_content="address_or_name=0x140012345",
        )
        kind, payload = _decision_to_message_payload(d)
        assert kind == PayloadKind.TOOL_CALL
        assert payload["command"] == "decompile"
        assert "address_or_name=0x140012345" in payload["script_content"]
        assert payload["reasoning"] == "run decompile on the suspect"

    def test_submit(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="audit complete",
            action="submit",
            expected_observation="final",
            answer="no bug found in region",
            confidence="strong",
            provenance=EvidenceProvenance(
                primary_artifact="step-3",
                corroboration=["step-5"],
                rejected_alternatives=[],
            ),
        )
        kind, payload = _decision_to_message_payload(d)
        assert kind == PayloadKind.OUTCOME_PENDING
        assert payload["answer"] == "no bug found in region"
        assert payload["confidence"] == "strong"

    def test_reasoning(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="thinking about JSPI",
            action="reasoning",
            expected_observation="hypothesis refined",
        )
        kind, payload = _decision_to_message_payload(d)
        assert kind == PayloadKind.TEXT
        assert payload["text"] == "thinking about JSPI"


class TestTerminalOutcomeKindRouting:
    def test_strong_confidence_becomes_direct_finding(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="strong", answer="found",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.DIRECT_FINDING

    def test_exact_confidence_becomes_direct_finding(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="exact", answer="found",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.DIRECT_FINDING

    def test_medium_becomes_assessment_report(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="medium", answer="maybe",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.ASSESSMENT_REPORT

    def test_caveated_becomes_assessment_report(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="caveated", answer="unclear",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.ASSESSMENT_REPORT

    def test_unknown_becomes_assessment_report(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r", action="submit", confidence="unknown", answer="dunno",
        )
        assert _terminal_outcome_kind(d) == OutcomeKind.ASSESSMENT_REPORT


class TestToOutcomeConfidence:
    @pytest.mark.parametrize(
        "value,expected",
        [
            ("exact", OutcomeConfidence.EXACT),
            ("strong", OutcomeConfidence.STRONG),
            ("medium", OutcomeConfidence.MEDIUM),
            ("caveated", OutcomeConfidence.CAVEATED),
            ("unknown", OutcomeConfidence.UNKNOWN),
        ],
    )
    def test_passthrough(self, value: str, expected: OutcomeConfidence) -> None:
        d = ReasoningTurnDecision(reasoning="", action="submit", confidence=value)
        assert _to_outcome_confidence(d) == expected

    def test_missing_confidence_defaults_unknown(self) -> None:
        d = ReasoningTurnDecision(reasoning="", action="submit")
        assert _to_outcome_confidence(d) == OutcomeConfidence.UNKNOWN


class TestOutcomePayload:
    def test_basic_shape(self) -> None:
        d = ReasoningTurnDecision(
            reasoning="r",
            action="submit",
            answer="ok",
            confidence="strong",
            contract=ReasoningContract(answer_type="audit"),
        )
        payload = _outcome_payload(d)
        assert payload["answer"] == "ok"
        assert payload["reasoning"] == "r"
        assert payload["contract"]["answer_type"] == "audit"

    def test_no_contract(self) -> None:
        d = ReasoningTurnDecision(reasoning="r", action="submit", answer="x")
        payload = _outcome_payload(d)
        assert payload["contract"] is None


class TestPromptLoading:
    def test_audit_prompt_loads(self) -> None:
        text = _load_prompt("vulnerability_research.audit")
        assert "audit-only investigation" in text
        assert "submit" in text

    def test_unknown_strategy_falls_back_to_audit(self) -> None:
        text = _load_prompt("vulnerability_research.discovery_research")
        # Falls back to audit prompt for v0.3 v1 (other strategies stub)
        assert "audit-only investigation" in text

    def test_completely_unknown_family_also_falls_back(self) -> None:
        text = _load_prompt("weird.unknown_family")
        assert "audit-only investigation" in text


class TestRenderOperatorMessagesSection:
    def test_empty_returns_empty_string(self) -> None:
        assert _render_operator_messages_section([]) == ""

    def test_single_message_includes_text_and_intent(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "check JSPI base", "intent": "steering"},
        ])
        assert "check JSPI base" in out
        assert "[intent: steering]" in out
        assert "Operator messages" in out

    def test_unclassified_intent_default(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "look at recv", "intent": ""},
        ])
        assert "[intent: unclassified]" in out

    def test_multiple_messages_preserve_order(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "first thought", "intent": "steering"},
            {"id": "m2", "text": "second thought", "intent": "correction"},
        ])
        assert out.index("first thought") < out.index("second thought")
        assert "[intent: steering]" in out
        assert "[intent: correction]" in out

    def test_missing_text_doesnt_crash(self) -> None:
        out = _render_operator_messages_section([{"id": "m1", "intent": "steering"}])
        assert "[intent: steering]" in out


class TestRenderAvailableToolsSection:
    def test_includes_both_servers(self) -> None:
        out = _render_available_tools_section()
        assert "## ida_headless" in out
        assert "## audit_mcp" in out
        assert "# Available tools" in out

    def test_marks_specialized_tools(self) -> None:
        out = _render_available_tools_section()
        # Specialized adapter: decompile
        assert "`ida_headless.decompile` [structured]" in out
        # Specialized adapter: taint_paths_to
        assert "`audit_mcp.taint_paths_to` [structured]" in out

    def test_lists_generic_tools_without_marker(self) -> None:
        out = _render_available_tools_section()
        # No specialized adapter: list_binaries (generic only)
        assert "`ida_headless.list_binaries`\n" in out
        # Not marked as [structured]
        line_with_list_binaries = next(
            line for line in out.splitlines()
            if "ida_headless.list_binaries" in line
        )
        assert "[structured]" not in line_with_list_binaries

    def test_includes_tool_count_per_server(self) -> None:
        out = _render_available_tools_section()
        # New header format carries a schema-availability suffix
        # (``— live schema`` or ``— schema unavailable``); the count
        # is the first thing after the open paren.
        assert "(81 tools — " in out or "(80 tools — " in out  # ida_headless
        assert "(54 tools — " in out or "(53 tools — " in out  # audit_mcp


class TestFormatParam:
    """Renders parameter signatures the agent must use verbatim."""

    def test_required_param(self) -> None:
        out = _format_param({"name": "index_id", "type": "string", "required": True})
        assert out == "index_id: string [required]"

    def test_optional_with_default(self) -> None:
        out = _format_param({
            "name": "limit",
            "type": "integer",
            "required": False,
            "default": 100,
        })
        assert out == "limit: integer = 100"

    def test_optional_string_default_is_quoted(self) -> None:
        out = _format_param({
            "name": "mode",
            "type": "string",
            "required": False,
            "default": "fast",
        })
        # json.dumps quotes strings — so the agent sees mode: string = "fast"
        assert out == 'mode: string = "fast"'

    def test_optional_no_default(self) -> None:
        out = _format_param({"name": "tag", "type": "string", "required": False})
        assert out == "tag: string"

    def test_truncates_huge_defaults(self) -> None:
        big = "x" * 200
        out = _format_param({
            "name": "p", "type": "string", "required": False, "default": big,
        })
        # Cap is 60 chars (then "..."); prevents one runaway default from
        # eating the whole prompt.
        assert "..." in out
        assert len(out) <= 80


class TestRenderAvailableToolsWithSchemas:
    """When tool_specs is provided, each tool renders with its full
    signature so the agent never has to guess parameter names — which
    is the bug that produced read_function(file_hint=...) etc.
    """

    def test_schema_renders_param_signatures(self) -> None:
        specs = {
            "audit_mcp": [
                {
                    "name": "read_function",
                    "description": "Read function source",
                    "params": [
                        {"name": "index_id", "type": "string", "required": True},
                        {"name": "file_path", "type": "string", "required": True},
                        {"name": "name", "type": "string", "required": True},
                    ],
                    "required": ["index_id", "file_path", "name"],
                },
                {
                    "name": "search_functions",
                    "description": "Pattern search",
                    "params": [
                        {"name": "index_id", "type": "string", "required": True},
                        {"name": "pattern", "type": "string", "required": True},
                        {"name": "limit", "type": "integer", "required": False, "default": 100},
                        {"name": "offset", "type": "integer", "required": False, "default": 0},
                    ],
                    "required": ["index_id", "pattern"],
                },
            ],
        }
        out = _render_available_tools_section(
            target_kind="source_repo",
            tool_specs=specs,
        )
        # Required params appear with [required]
        assert (
            "audit_mcp.read_function(index_id: string [required], "
            "file_path: string [required], name: string [required])" in out
        )
        # Optional params show defaults
        assert (
            "search_functions(index_id: string [required], "
            "pattern: string [required], limit: integer = 100, "
            "offset: integer = 0)" in out
        )
        # Header announces live schema
        assert "— live schema" in out

    def test_schema_fallback_when_specs_missing(self) -> None:
        """Empty specs => name-only listing with `schema unavailable` header."""
        out = _render_available_tools_section(
            target_kind="source_repo",
            tool_specs={"audit_mcp": []},
        )
        assert "— schema unavailable" in out
        # Still lists tools by name from KNOWN_TOOLS
        assert "`audit_mcp." in out

    def test_non_applicable_server_suppressed_even_with_specs(self) -> None:
        """source_repo kind hides ida_headless even when specs are present."""
        specs = {
            "ida_headless": [
                {"name": "decompile", "params": [], "required": []},
            ],
        }
        out = _render_available_tools_section(
            target_kind="source_repo",
            tool_specs=specs,
        )
        assert "NOT APPLICABLE for target kind `source_repo`" in out
        # Don't render the signature for a suppressed server
        assert "ida_headless.decompile(" not in out


class TestFetchToolSpecs:
    """_fetch_tool_specs is the bridge between bridges and the prompt
    builder. It must (a) filter by target kind, (b) call list_tool_specs
    on each applicable bridge.
    """

    @pytest.mark.asyncio
    async def test_source_repo_only_hits_audit_mcp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        audit_calls: list[str] = []
        ida_calls: list[str] = []

        async def fake_audit_specs(self: object) -> list[dict]:
            audit_calls.append("hit")
            return [{"name": "read_function", "params": [], "required": []}]

        async def fake_ida_specs(self: object) -> list[dict]:
            ida_calls.append("hit")
            return []

        from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
        from aila.modules.vr.tools.ida_bridge import IDABridgeTool
        monkeypatch.setattr(AuditMcpBridgeTool, "list_tool_specs", fake_audit_specs)
        monkeypatch.setattr(IDABridgeTool, "list_tool_specs", fake_ida_specs)

        out = await _fetch_tool_specs(target_kind="source_repo")
        assert "audit_mcp" in out
        assert "ida_headless" not in out
        assert audit_calls == ["hit"]
        assert ida_calls == []

    @pytest.mark.asyncio
    async def test_binary_only_hits_ida(self, monkeypatch: pytest.MonkeyPatch) -> None:
        audit_calls: list[str] = []
        ida_calls: list[str] = []

        async def fake_audit_specs(self: object) -> list[dict]:
            audit_calls.append("hit")
            return []

        async def fake_ida_specs(self: object) -> list[dict]:
            ida_calls.append("hit")
            return [{"name": "decompile", "params": [], "required": []}]

        from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
        from aila.modules.vr.tools.ida_bridge import IDABridgeTool
        monkeypatch.setattr(AuditMcpBridgeTool, "list_tool_specs", fake_audit_specs)
        monkeypatch.setattr(IDABridgeTool, "list_tool_specs", fake_ida_specs)

        out = await _fetch_tool_specs(target_kind="native_binary")
        assert "ida_headless" in out
        assert "audit_mcp" not in out
        assert ida_calls == ["hit"]
        assert audit_calls == []


    @pytest.mark.asyncio
    async def test_android_apk_hits_both_android_and_audit_mcp(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """F-2: android_apk targets need both android_mcp (APK facts:
        manifest, perms, signing, behaviour classification) AND
        audit_mcp (source-graph over the decompiled Java tree).
        ida_headless must NOT be polled for this kind.
        """
        audit_calls: list[str] = []
        ida_calls: list[str] = []
        android_calls: list[str] = []

        async def fake_audit_specs(self: object) -> list[dict]:
            audit_calls.append("hit")
            return [{"name": "semantic_search", "params": [], "required": []}]

        async def fake_ida_specs(self: object) -> list[dict]:
            ida_calls.append("hit")
            return [{"name": "decompile", "params": [], "required": []}]

        async def fake_android_specs(self: object) -> list[dict]:
            android_calls.append("hit")
            return [
                {"name": "apktool_decode", "params": [], "required": []},
                {"name": "androguard_summary", "params": [], "required": []},
                {"name": "verify_capabilities", "params": [], "required": []},
            ]

        monkeypatch.setattr(
            AuditMcpBridgeTool, "list_tool_specs", fake_audit_specs,
        )
        monkeypatch.setattr(
            IDABridgeTool, "list_tool_specs", fake_ida_specs,
        )
        monkeypatch.setattr(
            AndroidMcpBridgeTool, "list_tool_specs", fake_android_specs,
        )

        out = await _fetch_tool_specs(target_kind="android_apk")
        assert "android_mcp" in out
        assert "audit_mcp" in out
        assert "ida_headless" not in out
        assert android_calls == ["hit"]
        assert audit_calls == ["hit"]
        assert ida_calls == []
        # Both bridges contribute their full filtered catalog.
        android_names = {s["name"] for s in out["android_mcp"]}
        assert "apktool_decode" in android_names
        assert "androguard_summary" in android_names
        assert "verify_capabilities" in android_names
        audit_names = {s["name"] for s in out["audit_mcp"]}
        assert "semantic_search" in audit_names


class TestApplicableServersForKind:
    """F-2: target-kind -> applicable MCP server set mapping."""

    def test_source_repo_returns_audit_only(self) -> None:
        assert _applicable_servers_for_kind("source_repo") == {"audit_mcp"}

    def test_native_binary_returns_ida_only(self) -> None:
        assert _applicable_servers_for_kind("native_binary") == {"ida_headless"}

    def test_legacy_apk_still_routes_to_ida(self) -> None:
        # Pre-existing "apk" kind ingests through ida_headless via the
        # _ingest_binary path. F-2 must NOT widen this kind — only the
        # new "android_apk" gets the dual-bridge treatment.
        assert _applicable_servers_for_kind("apk") == {"ida_headless"}

    def test_android_apk_returns_both_android_and_audit(self) -> None:
        assert _applicable_servers_for_kind("android_apk") == {
            "android_mcp", "audit_mcp",
        }

    def test_unknown_kind_defaults_to_every_bridge(self) -> None:
        out = _applicable_servers_for_kind("totally_made_up")
        assert "android_mcp" in out
        assert "audit_mcp" in out
        assert "ida_headless" in out


class TestMcpFamilyRuleForKind:
    """F-2: the prompt-builder rule line that pins the agent to the
    right MCP family for the target kind.
    """

    def test_android_apk_with_both_handles_names_both_servers(self) -> None:
        rule = _mcp_family_rule_for_kind(
            "android_apk",
            {
                "audit_mcp_decompiled_index_id": "idx-abc123",
                "android_mcp_apk_path": "/tmp/yanimda.apk",
            },
        )
        assert "audit_mcp" in rule
        assert "android_mcp" in rule
        assert "idx-abc123" in rule
        assert "/tmp/yanimda.apk" in rule
        # The rule MUST NOT reach for ida_headless on this kind.
        assert "ida_headless" not in rule

    def test_android_apk_missing_handles_still_emits_rule(self) -> None:
        rule = _mcp_family_rule_for_kind("android_apk", {})
        assert "audit_mcp" in rule
        assert "android_mcp" in rule
        # When ingestion handles aren't ready yet, the rule should still
        # name both bridges so the agent doesn't drift to ida_headless.
        assert "ida_headless" not in rule

    def test_legacy_apk_kind_still_routes_to_ida(self) -> None:
        # The legacy "apk" kind (binary-style ingestion) stays on
        # ida_headless. Only "android_apk" gets the new dual-bridge
        # rule.
        rule = _mcp_family_rule_for_kind("apk", {"binary_id": "b_xyz"})
        assert "ida_headless" in rule
        assert "android_mcp" not in rule
