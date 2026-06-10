from __future__ import annotations

import pytest

from aila.platform.contracts.reasoning import (
    EvidenceProvenance,
    Hypothesis,
    ReasoningCaseState,
    ReasoningContract,
    ReasoningOperatorSteering,
    ReasoningPromptContext,
    ReasoningTurnDecision,
    RejectedHypothesis,
 )
from aila.platform.exceptions import ValidationError
from aila.platform.services.reasoning import CyberReasoningEngine


class _FakeResponse:
    def __init__(self, content: str, disabled: bool = False) -> None:
        self.content = content
        self.disabled = disabled


class _FakeLLMClient:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response
        self.calls: list[dict[str, object]] = []

    async def chat(self, *, task_type: str, messages: list[dict[str, str]]) -> _FakeResponse:
        self.calls.append({"task_type": task_type, "messages": messages})
        return self._response


@pytest.mark.asyncio
async def test_decide_next_turn_parses_valid_json() -> None:
    client = _FakeLLMClient(
        _FakeResponse(
            '{"reasoning":"Inspect manifest first","action":"tool_run","command":"jadx -h",'
            '"hypotheses":[{"id":"H1","claim":"APK is packed"}],'
            '"observables":{"surface":"mobile"}}'
        )
    )
    engine = CyberReasoningEngine(client)  # type: ignore[arg-type]

    decision = await engine.decide_next_turn(
        task_type="mobile_research",
        system_prompt="system",
        user_prompt="user",
    )

    assert decision.action == "tool_run"
    assert decision.command == "jadx -h"
    assert decision.hypotheses[0].id == "H1"
    assert decision.observables["surface"] == "mobile"
    assert client.calls[0]["task_type"] == "mobile_research"


@pytest.mark.asyncio
async def test_decide_next_turn_raises_on_non_json() -> None:
    client = _FakeLLMClient(_FakeResponse("not json at all"))
    engine = CyberReasoningEngine(client)  # type: ignore[arg-type]

    with pytest.raises(ValidationError, match="JSON object"):
        await engine.decide_next_turn(
            task_type="forensics_freeflow",
            system_prompt="system",
            user_prompt="user",
        )


def test_absorb_preserves_locked_contract_and_dedupes_rejected() -> None:
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    initial = ReasoningCaseState(
        contract=ReasoningContract(
            answer_type="filename",
            answer_format="exact filename",
            evidence_domain="mobile",
        ),
        hypotheses=[Hypothesis(id="H1", claim="APK is trojanized")],
        rejected=[RejectedHypothesis(id="H0", claim="Benign app", reason="network indicators disagree")],
        observables={"package": "com.example.app"},
    )

    decision_contract = ReasoningContract(
        answer_type="hash",
        answer_format="sha256",
        evidence_domain="binary",
    )
    merged = engine.absorb(
        initial,
        ReasoningTurnDecision(
            reasoning="Need stronger proof",
            action="reasoning",
            contract=decision_contract,
            hypotheses=[Hypothesis(id="H2", claim="Dynamic loading present")],
            rejected=[
                RejectedHypothesis(id="H0", claim="Benign app", reason="duplicate"),
                RejectedHypothesis(id="H3", claim="No network", reason="manifest disproves it"),
            ],
            observables={"loader": "DexClassLoader"},
            provenance=EvidenceProvenance(),
        ),
    )

    assert merged.contract.answer_type == "filename"
    assert [h.id for h in merged.hypotheses] == ["H2"]
    assert len(merged.rejected) == 2
    assert merged.observables["package"] == "com.example.app"
    assert merged.observables["loader"] == "DexClassLoader"


def test_render_case_model_includes_contract_hypotheses_and_rejections() -> None:
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    case_state = ReasoningCaseState(
        contract=ReasoningContract(
            answer_type="path",
            answer_format="absolute path",
            evidence_domain="windows_disk",
            depends_on=["H2"],
        ),
        hypotheses=[Hypothesis(id="H1", claim="Persistence via Run key", kill_criterion="No autorun reference")],
        rejected=[RejectedHypothesis(id="H0", claim="Service persistence", reason="service list clean")],
        observables={"autorun": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"},
    )

    rendered = engine.render_case_model(case_state)

    assert "Contract:" in rendered
    assert "answer_type   = path" in rendered
    assert "Live hypotheses:" in rendered
    assert "Persistence via Run key" in rendered
    assert "Rejected (do not re-propose" in rendered


def test_render_case_model_partitions_tool_observables_across_three_mcp_servers() -> None:
    """G-8: tool keys from all three MCP servers (audit_mcp, ida_headless,
    android_mcp) must land in the uncapped "tool readings" bucket — not
    the 15-key agent scratchpad bucket. Without this, android_mcp tool
    observations (e.g. ``android_mcp.androguard_summary.apk_path=...``)
    get evicted alongside agent scratchpad keys and the agent re-issues
    APK static-summary calls it already paid for.
    """
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    case_state = ReasoningCaseState(
        observables={
            "audit_mcp.read_function.name=Foo": "fn body",
            "ida_headless.decompile.address=0x1234": "decompiled",
            "android_mcp.androguard_summary.apk_path=/tmp/x.apk": "perms+certs",
            "audit_mcp:legacy_colon_form": "still tool",
            "android_mcp:legacy_colon_form": "still tool",
            "_directive.pivot": "must not appear",
            "sibling_h7": "agent scratchpad",
            "mandatory_next": "agent scratchpad",
        },
    )

    rendered = engine.render_case_model(case_state)

    # All five tool-prefixed keys (3 dot + 2 colon) land under "tool readings".
    assert "Observables — tool readings" in rendered
    assert "audit_mcp.read_function.name=Foo = fn body" in rendered
    assert "ida_headless.decompile.address=0x1234 = decompiled" in rendered
    assert "android_mcp.androguard_summary.apk_path=/tmp/x.apk = perms+certs" in rendered
    assert "audit_mcp:legacy_colon_form = still tool" in rendered
    assert "android_mcp:legacy_colon_form = still tool" in rendered
    # Agent scratchpad keys land separately.
    assert "Observables — agent scratchpad (most recent 15):" in rendered
    assert "sibling_h7 = agent scratchpad" in rendered
    assert "mandatory_next = agent scratchpad" in rendered
    # _directive.* is lifted to its own section, not rendered here.
    assert "_directive.pivot" not in rendered


def test_select_strategy_family_routes_mobile_and_vuln_cases() -> None:
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    empty_state = ReasoningCaseState()

    mobile = engine.select_strategy_family(
        question="Does this APK use dynamic code loading?",
        case_state=empty_state,
        evidence_listing="sample.apk",
        project_kind="disk_evidence",
    )
    vuln = engine.select_strategy_family(
        question="Is CVE-2026-1234 exploitable in this package version?",
        case_state=empty_state,
        evidence_listing="inventory.txt",
        project_kind="disk_evidence",
    )

    assert mobile == "mobile_reverse"
    assert vuln == "vulnerability_research"


def test_build_user_prompt_embeds_strategy_and_context() -> None:
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    prompt = engine.build_user_prompt(
        ReasoningPromptContext(
            turn=2,
            max_turns=5,
            question="Which file launches the payload?",
            evidence_dir="/evidence",
            evidence_listing="archive.zip",
            project_kind="raw_directory",
            case_model="Observables: none",
            artifacts="(no artefacts collected yet)",
            previous="[turn 1] action=tool_run",
            operator_steering=ReasoningOperatorSteering(
                confirmed_facts=["Artifact 123 is known-good"],
                disproved_hypotheses=["Prior malware guess rejected"],
                guidance=["Prefer static parsing first."],
                pinned_strategy_family="filesystem_triage",
                required_artifacts=["artifact-123"],
            ),
            strategy_family="filesystem_triage",
        )
    )

    assert "Reasoning domain profile: generic" in prompt
    assert "Preferred strategy family: filesystem_triage" in prompt
    assert "OPERATOR STEERING:" in prompt
    assert "pinned_strategy_family = filesystem_triage" in prompt
    assert "required_artifact = artifact-123" in prompt
    assert "PROJECT KIND: raw_directory" in prompt
    assert "Return a single JSON object matching the response contract." in prompt


def test_validate_submission_accepts_prior_output_and_observables() -> None:
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    assert engine.validate_submission(
        answer="payload.dll",
        primary_artifact="payload.dll",
        previous_turns=[{"stdout": "found payload.dll in archive"}],
        observables={},
    ) is None
    assert engine.validate_submission(
        answer="HKCU\\Run",
        primary_artifact="HKCU\\Run",
        previous_turns=[],
        observables={"autorun": "HKCU\\Run => updater.exe"},
    ) is None
    assert engine.validate_submission(
        answer="payload.dll",
        primary_artifact="artifact-999",
        previous_turns=[],
        observables={},
        required_artifacts=["[P] artifact-123"],
        corroboration=["artifact-123"],
    ) is None
    assert engine.validate_submission(
        answer="",
        primary_artifact="artifact-1",
        previous_turns=[],
        observables={},
    ) == "answer is empty"


def test_resolve_domain_profile_returns_cross_domain_adapter() -> None:
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    profile = engine.resolve_domain_profile("mobile_reverse")

    assert profile.domain_id == "mobile_reverse"
    assert profile.task_type == "mobile_reverse"
    assert "mobile_reverse" in profile.allowed_strategies
    assert profile.default_strategy == "mobile_reverse"


def test_select_strategy_family_respects_operator_pin() -> None:
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    empty_state = ReasoningCaseState()
    steering = ReasoningOperatorSteering(pinned_strategy_family="network_forensics")

    selected = engine.select_strategy_family(
        question="Is this APK malicious?",
        case_state=empty_state,
        evidence_listing="sample.apk",
        project_kind="disk_evidence",
        steering=steering,
    )

    assert selected == "network_forensics"


def test_build_evidence_graph_links_contract_evidence_and_answer() -> None:
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    case_state = ReasoningCaseState(
        contract=ReasoningContract(
            answer_type="path",
            answer_format="absolute path",
            evidence_domain="windows_disk",
            depends_on=["H1"],
        ),
        hypotheses=[Hypothesis(id="H1", claim="Persistence via Run key")],
        observables={"autorun": "HKCU\\Run => updater.exe"},
    )
    decision = ReasoningTurnDecision(
        reasoning="The autorun key is the launch point.",
        action="submit",
        answer="C:/Users/Alice/AppData/Roaming/updater.exe",
        confidence="strong",
        provenance=EvidenceProvenance(
            primary_artifact="artifact-123",
            corroboration=["artifact-456"],
        ),
    )

    graph = engine.build_evidence_graph(case_state=case_state, decision=decision)

    node_ids = {node.id for node in graph.nodes}
    edge_kinds = {(edge.source, edge.target, edge.kind) for edge in graph.edges}

    assert "contract" in node_ids
    assert "hyp:H1" in node_ids
    assert "obs:autorun" in node_ids
    assert "evidence:artifact-123" in node_ids
    assert "answer" in node_ids
    assert ("hyp:H1", "contract", "depends_on") in edge_kinds
    assert ("evidence:artifact-123", "answer", "answered_by") in edge_kinds
