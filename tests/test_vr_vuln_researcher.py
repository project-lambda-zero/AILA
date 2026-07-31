"""M3.R-2 -- HonestVulnResearcher unit tests.

Pure-helper tests (no DB, no LLM). The full DB-round-trip test for
``run_turn`` requires fixtures that stand up the schema + insert a
target / investigation / branch, which is more work than warranted
here -- that path will get its integration test once the workflow
state machine (M3.R-7) is wired.
"""
from __future__ import annotations

import json
import re
from types import SimpleNamespace

import pytest

from aila.modules.vr.agents.vuln_researcher import (
    HonestVulnResearcher,
    _PROMPT_VERSION_STORE,
    _applicable_servers_for_kind,
    _decision_to_message_payload,
    _fetch_tool_specs,
    _format_param,
    _load_prompt,
    _mcp_family_rule_for_kind,
    _prompt_key,
    _outcome_payload,
    _render_available_tools_section,
    _render_operator_messages_section,
    _render_target_snapshot_section,
    _terminal_outcome_kind,
)
from aila.modules.vr.contracts import OutcomeConfidence, OutcomeKind, PayloadKind
from aila.platform.agents.turn_helpers import (
    decode_case_state,
    encode_case_state,
    to_outcome_confidence,
)
from aila.platform.contracts.reasoning import (
    EvidenceProvenance,
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    ReasoningTurnDecision,
    RejectedHypothesis,
)
from aila.platform.mcp.bridges.android_mcp import AndroidMcpBridgeTool
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool


class TestCaseStateEncoding:
    def test_round_trip(self) -> None:
        original = ReasoningCaseState(
            contract=ReasoningContract(answer_type="x", answer_format="json"),
            hypotheses=[Hypothesis(id="h1", claim="c", why_plausible="w", kill_criterion="k")],
            rejected=[RejectedHypothesis(id="h0", claim="old", reason="r")],
            observables={"k": "v"},
        )
        encoded = encode_case_state(original)
        assert isinstance(encoded, str)
        restored = decode_case_state(encoded)
        assert restored == original

    def test_empty_decode(self) -> None:
        assert decode_case_state(None) == ReasoningCaseState()
        assert decode_case_state("") == ReasoningCaseState()

    def test_invalid_json_decode_recovers(self) -> None:
        assert decode_case_state("{not json") == ReasoningCaseState()

    def test_invalid_shape_recovers(self) -> None:
        assert decode_case_state(json.dumps({"hypotheses": "not a list"})) == ReasoningCaseState()


class TestDecisionToMessagePayload:
    def test_tool_run(self) -> None:
        cmd = json.dumps({
            "tool": "ida_headless.decompile",
            "args": {"address_or_name": "0x140012345"},
        })
        d = ReasoningTurnDecision(
            reasoning="run decompile on the suspect",
            action="tool_run",
            expected_observation="pseudocode of the function",
            command=cmd,
            script_content="address_or_name=0x140012345",
        )
        kind, payload = _decision_to_message_payload(d)
        assert kind == PayloadKind.TOOL_CALL
        assert payload["command"] == cmd
        parsed = json.loads(payload["command"])
        assert parsed["tool"] == "ida_headless.decompile"
        assert parsed["args"]["address_or_name"] == "0x140012345"
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
        assert to_outcome_confidence(d) == expected

    def test_missing_confidence_defaults_unknown(self) -> None:
        d = ReasoningTurnDecision(reasoning="", action="submit")
        assert to_outcome_confidence(d) == OutcomeConfidence.UNKNOWN


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
    async def test_audit_prompt_loads(self, test_db) -> None:
        text = (await _load_prompt("vulnerability_research.audit")).body
        assert "audit-only investigation" in text
        assert "submit" in text

    async def test_unknown_strategy_falls_back_to_audit(self, test_db) -> None:
        text = (await _load_prompt("vulnerability_research.discovery_research")).body
        # Falls back to audit prompt for v0.3 v1 (other strategies stub)
        assert "audit-only investigation" in text

    async def test_completely_unknown_family_also_falls_back(self, test_db) -> None:
        text = (await _load_prompt("weird.unknown_family")).body
        assert "audit-only investigation" in text

    async def test_registered_production_version_overrides_file(self, test_db) -> None:
        """A version registered and aliased 'production' for the key is
        served instead of the file baseline (the RFC-09 deploy path)."""
        key = _prompt_key("vulnerability_research.audit")
        version = await _PROMPT_VERSION_STORE.register(key, "DEPLOYED PROMPT BODY")
        await _PROMPT_VERSION_STORE.set_alias(key, "production", version)
        text = (await _load_prompt("vulnerability_research.audit")).body
        assert text == "DEPLOYED PROMPT BODY"


class TestRenderOperatorMessagesSection:
    def test_empty_returns_empty_string(self) -> None:
        assert _render_operator_messages_section([]) == ""

    def test_single_message_includes_text_and_intent(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "check JSPI base", "intent": "steering"},
        ])
        assert "check JSPI base" in out
        assert "intent=steering]" in out
        assert "OPERATOR STEERING" in out

    def test_unclassified_intent_default(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "look at recv", "intent": ""},
        ])
        assert "intent=unclassified]" in out

    def test_multiple_messages_preserve_order(self) -> None:
        out = _render_operator_messages_section([
            {"id": "m1", "text": "first thought", "intent": "steering"},
            {"id": "m2", "text": "second thought", "intent": "correction"},
        ])
        assert out.index("first thought") < out.index("second thought")
        assert "intent=steering]" in out
        assert "intent=correction]" in out

    def test_missing_text_doesnt_crash(self) -> None:
        out = _render_operator_messages_section([{"id": "m1", "intent": "steering"}])
        assert "intent=steering]" in out


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
        # Headers carry the count and a schema-availability suffix
        # (``-- live schema`` or ``-- schema unavailable``). The exact
        # count is intentionally elastic -- bumping a tool catalog
        # shouldn't churn this test.
        assert re.search(r"## ida_headless \(\d+ tools -- ", out)
        assert re.search(r"## audit_mcp \(\d+ tools -- ", out)


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
        # json.dumps quotes strings -- so the agent sees mode: string = "fast"
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
    signature so the agent never has to guess parameter names -- which
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
        assert "-- live schema" in out

    def test_schema_fallback_when_specs_missing(self) -> None:
        """Empty specs => name-only listing with `schema unavailable` header."""
        out = _render_available_tools_section(
            target_kind="source_repo",
            tool_specs={"audit_mcp": []},
        )
        assert "-- schema unavailable" in out
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
        # Server section for a non-applicable kind is silently
        # suppressed entirely; an observed regression was that
        # surfacing "NOT APPLICABLE: ida_headless" still gave the agent
        # a hook to think about IDA tools on a source_repo target.
        # Contract is now total absence.
        assert "## ida_headless" not in out
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

        from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
        from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
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

        from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
        from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
        monkeypatch.setattr(AuditMcpBridgeTool, "list_tool_specs", fake_audit_specs)
        monkeypatch.setattr(IDABridgeTool, "list_tool_specs", fake_ida_specs)

        out = await _fetch_tool_specs(target_kind="native_binary")
        assert "ida_headless" in out
        assert "audit_mcp" not in out
        assert ida_calls == ["hit"]
        assert audit_calls == []


    @pytest.mark.asyncio
    async def test_android_apk_hits_all_three_bridges(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """android_apk targets now poll ALL three bridges: android_mcp
        (APK-level facets), audit_mcp (source-graph over the jadx-
        decompiled Java tree), AND ida_headless (native .so libraries
        under lib/<abi>/). See _applicable_servers_for_kind in
        src/aila/modules/vr/agents/vuln_researcher.py -- ida_headless
        was intentionally added because excluding it forced agents to
        hallucinate android_mcp calls for native analysis.
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
                {"name": "drozer_scan_apk", "params": [], "required": []},
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
        assert "ida_headless" in out
        assert android_calls == ["hit"]
        assert audit_calls == ["hit"]
        assert ida_calls == ["hit"]
        # Each bridge contributes its full filtered catalog.
        android_names = {s["name"] for s in out["android_mcp"]}
        assert "apktool_decode" in android_names
        assert "drozer_scan_apk" in android_names
        assert "verify_capabilities" in android_names
        audit_names = {s["name"] for s in out["audit_mcp"]}
        assert "semantic_search" in audit_names
        ida_names = {s["name"] for s in out["ida_headless"]}
        assert "decompile" in ida_names


class TestApplicableServersForKind:
    """F-2: target-kind -> applicable MCP server set mapping."""

    def test_source_repo_returns_audit_only(self) -> None:
        assert _applicable_servers_for_kind("source_repo") == {"audit_mcp"}

    def test_native_binary_returns_ida_only(self) -> None:
        assert _applicable_servers_for_kind("native_binary") == {"ida_headless"}

    def test_legacy_apk_falls_through_to_unknown(self) -> None:
        # "apk" is no longer a first-class kind (superseded by
        # "android_apk"). It is not registered in _SOURCE_REPO_KINDS,
        # _ANDROID_KINDS or _BINARY_KINDS, so the fallback branch
        # returns every known bridge -- same as any other unrecognised
        # kind. Live rows use "android_apk"; the legacy string is only
        # exercised by this drift test.
        out = _applicable_servers_for_kind("apk")
        assert "ida_headless" in out
        assert "audit_mcp" in out
        assert "android_mcp" in out

    def test_android_apk_returns_all_three_bridges(self) -> None:
        # android_apk needs android_mcp (APK-level facets), audit_mcp
        # (source-graph over jadx-decompiled Java) AND ida_headless
        # (native .so files under lib/<abi>/).
        assert _applicable_servers_for_kind("android_apk") == {
            "android_mcp", "audit_mcp", "ida_headless",
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

    def test_android_apk_with_both_handles_names_all_three_servers(self) -> None:
        rule = _mcp_family_rule_for_kind(
            "android_apk",
            {
                "audit_mcp_decompiled_index_id": "idx-abc123",
                "android_mcp_apk_path": "/tmp/sampleapp.apk",
            },
        )
        assert "audit_mcp" in rule
        assert "android_mcp" in rule
        assert "idx-abc123" in rule
        assert "/tmp/sampleapp.apk" in rule
        # ida_headless is now intentionally named for NATIVE LIBRARY
        # analysis on lib/<abi>/*.so. Excluding it caused agents to
        # skip native analysis entirely on APK targets.
        assert "ida_headless" in rule

    def test_android_apk_missing_handles_still_emits_rule(self) -> None:
        rule = _mcp_family_rule_for_kind("android_apk", {})
        assert "audit_mcp" in rule
        assert "android_mcp" in rule
        # ida_headless is named unconditionally for android_apk (see
        # the sibling test above); the RULE talks about NATIVE
        # LIBRARY analysis for every android_apk target.
        assert "ida_headless" in rule

    def test_legacy_apk_kind_has_no_rule(self) -> None:
        # The legacy "apk" string is not in _mcp_family_rule_for_kind's
        # dispatch table anymore; live rows all carry "android_apk".
        # The function returns "" for unrecognised kinds -- callers
        # concatenate unconditionally, so an empty rule is a no-op.
        rule = _mcp_family_rule_for_kind("apk", {"binary_id": "b_xyz"})
        assert rule == ""


class TestSnapshotTargetAndroidApk:
    """F-4: ``_snapshot_target`` must surface the APK path under the
    handle key the F-2 RULE line and the renderer both expect, even
    for rows ingested before the F-4 commit landed.
    """

    def _build_target(
        self,
        *,
        kind: str,
        descriptor: dict | None = None,
        handles: dict | None = None,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            id="t-1",
            kind=kind,
            display_name="SampleApp",
            primary_language="java",
            secondary_languages_json="[]",
            analysis_state="ready",
            analysis_state_message=None,
            descriptor_json=json.dumps(descriptor or {}),
            capability_profile_json="{}",
            mcp_handles_json=json.dumps(handles or {}),
        )

    def test_android_apk_synthesizes_apk_path_into_handles(self) -> None:
        target = self._build_target(
            kind="android_apk",
            descriptor={"apk_path": "/work/sampleapp.apk"},
            handles={"audit_mcp_decompiled_index_id": "idx-abc123"},
        )

        snap = HonestVulnResearcher._snapshot_target(target)  # noqa: SLF001

        # apk_path projected onto the F-2 handle key the RULE line reads.
        assert snap["mcp_handles"]["android_mcp_apk_path"] == "/work/sampleapp.apk"
        # F-3 handle flows through verbatim.
        assert snap["mcp_handles"]["audit_mcp_decompiled_index_id"] == "idx-abc123"

    def test_existing_apk_path_handle_is_not_overwritten(self) -> None:
        target = self._build_target(
            kind="android_apk",
            descriptor={"apk_path": "/from/descriptor.apk"},
            handles={"android_mcp_apk_path": "/already/in/handles.apk"},
        )

        snap = HonestVulnResearcher._snapshot_target(target)  # noqa: SLF001

        # Descriptor never clobbers an already-persisted handle value.
        assert snap["mcp_handles"]["android_mcp_apk_path"] == "/already/in/handles.apk"

    def test_non_android_kinds_get_no_synthesis(self) -> None:
        target = self._build_target(
            kind="source_repo",
            descriptor={"apk_path": "/should/not/leak.apk"},
            handles={"audit_mcp_index_id": "idx-zzz"},
        )

        snap = HonestVulnResearcher._snapshot_target(target)  # noqa: SLF001

        # apk_path from descriptor must NOT bleed into handles for
        # other kinds -- the synthesis is gated on kind == android_apk.
        assert "android_mcp_apk_path" not in snap["mcp_handles"]

    def test_android_apk_with_missing_descriptor_apk_path_is_noop(self) -> None:
        # If the descriptor invariant is broken (no apk_path), the
        # snapshot returns cleanly without inventing a handle.
        target = self._build_target(
            kind="android_apk",
            descriptor={},
            handles={"audit_mcp_decompiled_index_id": "idx-1"},
        )

        snap = HonestVulnResearcher._snapshot_target(target)  # noqa: SLF001

        assert "android_mcp_apk_path" not in snap["mcp_handles"]


class TestRenderTargetSnapshotSectionAndroidApk:
    """F-4: end-to-end smoke -- the rendered snapshot text for an
    android_apk target must surface both the apk_path and the
    decompiled audit-mcp index id so the agent prompt grounds on
    both bridges.
    """

    def test_renders_both_apk_path_and_decompiled_index_id(self) -> None:
        snapshot = {
            "id": "t-1",
            "kind": "android_apk",
            "display_name": "com.examplecorp.selfservis",
            "primary_language": "java",
            "secondary_languages": [],
            "analysis_state": "ready",
            "analysis_state_message": "",
            "descriptor": {"apk_path": "/work/sampleapp.apk"},
            "applicable_mcp_servers": ["audit_mcp", "android_mcp"],
            "applicable_fuzzing_engines": [],
            "applicable_strategies": [],
            "functions_of_interest": [],
            "attack_surface": [],
            "mitigations": {},
            "mcp_handles": {
                "android_mcp_apk_path": "/work/sampleapp.apk",
                "audit_mcp_decompiled_index_id": "idx-abc123",
                "audit_mcp_decompiled_indexed_at": "2026-06-08T10:00:00+00:00",
                "android_mcp_package_name": "com.examplecorp.selfservis",
            },
        }

        rendered = _render_target_snapshot_section(snapshot)

        # The acceptance test from IMPLEMENTATION_PLAN.md F-4.3:
        # both handle values must appear verbatim in the prompt.
        assert "android_mcp_apk_path=/work/sampleapp.apk" in rendered
        assert "audit_mcp_decompiled_index_id=idx-abc123" in rendered
        # The F-2 RULE line names both bridges with the concrete ids.
        assert "idx-abc123" in rendered
        assert "/work/sampleapp.apk" in rendered
        # The audit_mcp_-prefixed timestamp must not be filtered out.
        assert "audit_mcp_decompiled_indexed_at=" in rendered

    def test_audit_mcp_handles_are_never_filtered_by_kind(self) -> None:
        # Defensive guard: the renderer's mcp_handles loop is
        # unfiltered. If a future refactor swaps it for an allowlist,
        # this test catches the regression by holding the line that
        # `audit_mcp_*` keys must keep flowing through for
        # `android_apk` targets specifically.
        snapshot = {
            "id": "t-1",
            "kind": "android_apk",
            "display_name": "x",
            "primary_language": "java",
            "secondary_languages": [],
            "analysis_state": "ready",
            "analysis_state_message": "",
            "descriptor": {"apk_path": "/x.apk"},
            "applicable_mcp_servers": [],
            "applicable_fuzzing_engines": [],
            "applicable_strategies": [],
            "functions_of_interest": [],
            "attack_surface": [],
            "mitigations": {},
            "mcp_handles": {
                "audit_mcp_decompiled_index_id": "idx-zzz",
                "audit_mcp_decompiled_indexed_at": "2026-06-08T11:00:00+00:00",
            },
        }

        rendered = _render_target_snapshot_section(snapshot)

        assert "audit_mcp_decompiled_index_id=idx-zzz" in rendered
        assert "audit_mcp_decompiled_indexed_at=2026-06-08T11:00:00+00:00" in rendered


# ----------------------------------------------------------------------
# #4 convergence fix -- sibling-open-hypothesis gate. A terminal
# no_finding / inconclusive submit is blocked while any sibling still
# holds a live hypothesis id no branch has rejected. Passes on a
# finding-polarity submit, on "all sibling hyps rejected", and once the
# consecutive-rejection cap is exceeded (force-through stamps the
# advisory).
# ----------------------------------------------------------------------


def _no_finding_submit_decision() -> ReasoningTurnDecision:
    """Terminal audit_memo submit with verdict=no_finding -- derives
    to polarity='no_finding' via the outcome_polarity helper."""
    return ReasoningTurnDecision(
        reasoning="nothing found on my branch",
        action="submit",
        expected_observation="terminal",
        answer="branch is clear",
        confidence="medium",
        payload={"verdict": "no_finding"},
    )


def _finding_submit_decision() -> ReasoningTurnDecision:
    """Terminal submit with strong confidence -- derives to
    outcome_kind=direct_finding + polarity='finding'."""
    return ReasoningTurnDecision(
        reasoning="found the bug",
        action="submit",
        expected_observation="terminal",
        answer="heap OOB on strcpy at foo:42",
        confidence="strong",
    )


def _make_researcher_with_cap(cap: int) -> HonestVulnResearcher:
    """Build a researcher instance for direct gate-method invocation.

    The gate is pure over its arguments (no DB, no engine) so a
    bare-bones construction is enough; caps normally set by
    :meth:`_load_turn_config` are stamped manually here.
    """
    researcher = HonestVulnResearcher(
        reasoning_engine=SimpleNamespace(),  # type: ignore[arg-type]
        investigation_id="inv-gate",
        branch_id="b-under-test",
    )
    researcher._sibling_open_hyp_reject_cap = cap  # noqa: SLF001 -- test-only manual init
    return researcher


class TestSiblingOpenHypGate:
    def test_finding_polarity_bypasses_gate(self) -> None:
        """A finding-polarity submit is NEVER blocked by this gate --
        panel review handles sibling disagreement on a positive finding.
        Sibling still has a live unresolved hypothesis, but the submit
        is a finding, so the gate passes."""
        researcher = _make_researcher_with_cap(3)
        case_state = ReasoningCaseState()
        sibling_context = [{
            "branch_id": "b-sibling",
            "persona_voice": "maddie",
            "hypotheses": [{"id": "h_live", "claim": "still hunting"}],
            "rejected": [],
        }]

        result = researcher._maybe_reject_no_finding_while_sibling_open_hyp(
            decision=_finding_submit_decision(),
            case_state=case_state,
            sibling_context=sibling_context,
            turn_number=5,
        )

        assert result.action == "submit"
        assert "_directive.sibling_open_hyp_block" not in case_state.observables
        assert "_sibling_open_hyp_reject_count" not in case_state.observables

    def test_no_finding_with_sibling_open_hyp_blocks(self) -> None:
        """A no_finding submit while a sibling holds a live hypothesis
        no branch has rejected: gate swaps to non-terminal and stamps
        ``_directive.sibling_open_hyp_block`` naming the sibling +
        hypothesis, plus increments the reject counter."""
        researcher = _make_researcher_with_cap(3)
        case_state = ReasoningCaseState()
        sibling_context = [{
            "branch_id": "b-maddie",
            "persona_voice": "maddie",
            "hypotheses": [
                {"id": "h_race", "claim": "TOCTOU on rename"},
            ],
            "rejected": [],
        }]

        result = researcher._maybe_reject_no_finding_while_sibling_open_hyp(
            decision=_no_finding_submit_decision(),
            case_state=case_state,
            sibling_context=sibling_context,
            turn_number=3,
        )

        assert result.action == "tool_run"
        assert result.command == ""
        directive = case_state.observables.get("_directive.sibling_open_hyp_block")
        assert isinstance(directive, str)
        assert "h_race" in directive
        assert "TOCTOU on rename" in directive
        assert "maddie" in directive
        assert case_state.observables["_sibling_open_hyp_reject_count"] == 1
        # Original answer is preserved verbatim inside the rejected
        # command text so an audit can reconstruct the intent.
        assert "branch is clear" in (result.answer or "")

    def test_no_finding_when_all_sibling_hyps_rejected_passes(self) -> None:
        """Sibling's live hypothesis id appears in this branch's
        rejected[] (a cross-branch rejection is enough): gate passes
        the submit and clears any prior directive stamp."""
        researcher = _make_researcher_with_cap(3)
        case_state = ReasoningCaseState(
            rejected=[
                RejectedHypothesis(
                    id="h_race",
                    claim="TOCTOU on rename",
                    reason="path guarded by O_NOFOLLOW at foo:42",
                ),
            ],
            observables={
                # Simulate a prior gate rejection that should clear.
                "_directive.sibling_open_hyp_block": "prior banner",
                "_sibling_open_hyp_reject_count": 2,
            },
        )
        sibling_context = [{
            "branch_id": "b-maddie",
            "persona_voice": "maddie",
            "hypotheses": [
                {"id": "h_race", "claim": "TOCTOU on rename"},
            ],
            "rejected": [],
        }]

        result = researcher._maybe_reject_no_finding_while_sibling_open_hyp(
            decision=_no_finding_submit_decision(),
            case_state=case_state,
            sibling_context=sibling_context,
            turn_number=3,
        )

        assert result.action == "submit"
        assert "_directive.sibling_open_hyp_block" not in case_state.observables
        assert "_sibling_open_hyp_reject_count" not in case_state.observables

    def test_force_through_after_cap_stamps_advisory(self) -> None:
        """Above ``_sibling_open_hyp_reject_cap`` consecutive rejections,
        the submit is FORCED THROUGH with
        ``payload.sibling_open_hyp_advisory`` naming the open sibling
        ids so the operator can audit the closure gap."""
        cap = 3
        researcher = _make_researcher_with_cap(cap)
        # Prior rejects already at the cap -> next call goes over.
        case_state = ReasoningCaseState(
            observables={"_sibling_open_hyp_reject_count": cap},
        )
        sibling_context = [{
            "branch_id": "b-maddie",
            "persona_voice": "maddie",
            "hypotheses": [
                {"id": "h_race", "claim": "TOCTOU"},
            ],
            "rejected": [],
        }]

        result = researcher._maybe_reject_no_finding_while_sibling_open_hyp(
            decision=_no_finding_submit_decision(),
            case_state=case_state,
            sibling_context=sibling_context,
            turn_number=15,
        )

        assert result.action == "submit", (
            "force-through should keep the terminal submit intact"
        )
        advisory = result.payload.get("sibling_open_hyp_advisory")
        assert isinstance(advisory, dict)
        assert advisory["open_count"] == 1
        assert advisory["forced_through_after_rejects"] == cap
        assert advisory["open"][0]["sibling_branch_id"] == "b-maddie"
        assert advisory["open"][0]["hypothesis_id"] == "h_race"
        # Force-through path clears the counter + directive so the next
        # panel iteration starts fresh.
        assert "_sibling_open_hyp_reject_count" not in case_state.observables
        assert "_directive.sibling_open_hyp_block" not in case_state.observables

    def test_this_turn_rejected_id_closes_gate(self) -> None:
        """The current turn's ``decision.rejected[]`` counts as a
        rejection for the union -- a branch can close its OWN turn's
        leftover in the same turn it submits."""
        researcher = _make_researcher_with_cap(3)
        case_state = ReasoningCaseState()
        sibling_context = [{
            "branch_id": "b-maddie",
            "persona_voice": "maddie",
            "hypotheses": [{"id": "h_race", "claim": "TOCTOU"}],
            "rejected": [],
        }]
        decision = _no_finding_submit_decision().model_copy(update={
            "rejected": [
                RejectedHypothesis(
                    id="h_race", claim="TOCTOU",
                    reason="guard added at foo:42",
                ),
            ],
        })

        result = researcher._maybe_reject_no_finding_while_sibling_open_hyp(
            decision=decision,
            case_state=case_state,
            sibling_context=sibling_context,
            turn_number=4,
        )

        assert result.action == "submit"
        assert "_directive.sibling_open_hyp_block" not in case_state.observables


class TestReviewVoteAndCommentNotReady:
    """#6 convergence fix -- VR override of ``_review_vote_and_comment``
    recognises ``not_ready`` as a first-class vote and preserves the
    blocker verbatim as the review comment."""

    def _researcher(self) -> HonestVulnResearcher:
        return HonestVulnResearcher(
            reasoning_engine=SimpleNamespace(),  # type: ignore[arg-type]
            investigation_id="inv-vote",
            branch_id="b-vote",
        )

    def test_not_ready_preserves_blocker(self) -> None:
        decision = SimpleNamespace(
            review_vote="not_ready",
            review_comment="awaiting audit_mcp read_function for parse_uri",
            reasoning="see review_comment",
        )
        vote, comment = self._researcher()._review_vote_and_comment(decision)
        assert vote == "not_ready"
        assert comment == "awaiting audit_mcp read_function for parse_uri"

    def test_not_ready_falls_back_to_reasoning(self) -> None:
        """When ``review_comment`` is empty the reasoning body carries
        the blocker; the override still labels the vote not_ready."""
        decision = SimpleNamespace(
            review_vote="not_ready",
            review_comment="",
            reasoning="need MASVS-STORAGE-2 evidence before I can approve",
        )
        vote, comment = self._researcher()._review_vote_and_comment(decision)
        assert vote == "not_ready"
        assert comment == "need MASVS-STORAGE-2 evidence before I can approve"

    def test_approve_vote_still_uses_default_flow(self) -> None:
        """Regression guard: adding not_ready must not change the
        approve / reject / abstain paths."""
        decision = SimpleNamespace(
            review_vote="approve",
            review_comment="corroborated",
            reasoning="see the shared ledger note",
        )
        vote, comment = self._researcher()._review_vote_and_comment(decision)
        assert vote == "approve"
        assert comment == "corroborated"

    def test_empty_vote_defaults_to_abstain(self) -> None:
        decision = SimpleNamespace(
            review_vote=None, review_comment=None, reasoning="",
        )
        vote, comment = self._researcher()._review_vote_and_comment(decision)
        assert vote == "abstain"
        assert comment == ""
