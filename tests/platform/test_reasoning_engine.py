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

    async def chat_structured(
        self,
        *,
        task_type: str,
        messages: list[dict[str, str]],
        model_class: object,
        run_id: str | None = None,
        team_id: str | None = None,
    ) -> _FakeResponse:
        self.calls.append({
            "task_type": task_type,
            "messages": messages,
            "run_id": run_id,
            "team_id": team_id,
        })
        return self._response


@pytest.mark.asyncio
async def test_decide_next_turn_parses_valid_json() -> None:
    client = _FakeLLMClient(
        _FakeResponse(
            '{"reasoning":"Inspect manifest first","action":"tool_run",'
            '"command":"{\\"tool\\": \\"jadx\\", \\"args\\": {}}",'
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
    # tool_run command is a JSON dispatch object ({tool, args}), validated by
    # ReasoningTurnDecision._validate_tool_run_command and kept as-is.
    assert decision.command == '{"tool": "jadx", "args": {}}'
    assert decision.hypotheses[0].id == "H1"
    assert decision.observables["surface"] == "mobile"
    assert client.calls[0]["task_type"] == "mobile_research"


@pytest.mark.asyncio
async def test_decide_next_turn_forwards_run_id() -> None:
    """run_id threads to chat_structured so per-run cost records, budget
    checks, and the forensics freeflow ceiling attribute this turn's spend
    to the caller's investigation (#59/#39). A None run_id stays None."""
    client = _FakeLLMClient(
        _FakeResponse(
            '{"reasoning":"r","action":"tool_run",'
            '"command":"{\\"tool\\": \\"x\\", \\"args\\": {}}",'
            '"hypotheses":[],"observables":{}}'
        )
    )
    engine = CyberReasoningEngine(client)  # type: ignore[arg-type]

    await engine.decide_next_turn(
        task_type="mobile_research",
        system_prompt="s",
        user_prompt="u",
        run_id="inv-abc123",
    )

    assert client.calls[0]["run_id"] == "inv-abc123"
    assert client.calls[0]["team_id"] is None


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
    # absorb merges live hypotheses across turns (nothing the agent proposed
    # vanishes unless explicitly rejected), so H1 survives alongside new H2.
    assert [h.id for h in merged.hypotheses] == ["H1", "H2"]
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
    # populated hypothesis header carries the live count
    assert "Live hypotheses (1):" in rendered
    assert "Persistence via Run key" in rendered
    assert "Rejected (do not re-propose" in rendered


def test_render_case_model_partitions_tool_observables_across_three_mcp_servers() -> None:
    """G-8: tool keys from all three MCP servers (audit_mcp, ida_headless,
    android_mcp) must land in the uncapped "tool readings" bucket -- not
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
    assert "Observables -- tool readings" in rendered
    # All five tool-prefixed keys (3 dot + 2 colon) render in the tool-readings
    # section; the current format puts the key and its body on separate lines.
    assert "audit_mcp.read_function.name=Foo" in rendered
    assert "ida_headless.decompile.address=0x1234" in rendered
    assert "android_mcp.androguard_summary.apk_path=/tmp/x.apk" in rendered
    assert "audit_mcp:legacy_colon_form" in rendered
    assert "android_mcp:legacy_colon_form" in rendered
    assert "fn body" in rendered
    assert "decompiled" in rendered
    assert "perms+certs" in rendered
    # Agent scratchpad keys land separately; the header reports the total count
    # (2), which also proves the five tool keys did NOT leak into this bucket.
    assert "Observables -- agent scratchpad (2 total):" in rendered
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


# ----------------------------------------------------------------------
# #61-2 -- observables must be JSON-serializable at construction time.
# A datetime/bytes slipping into observables used to pass Pydantic
# construction and only crash later at model_dump(mode='json') /
# task_queue.submit. The AfterValidator surfaces it at the source.
# ----------------------------------------------------------------------


def test_case_state_rejects_non_json_observable() -> None:
    from datetime import datetime

    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError, match="JSON-serializable"):
        ReasoningCaseState(observables={"ts": datetime(2026, 7, 20)})


def test_case_state_rejects_bytes_observable() -> None:
    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError, match="JSON-serializable"):
        ReasoningCaseState(observables={"blob": b"\x00\x01"})


def test_turn_decision_rejects_non_json_observable() -> None:
    from datetime import datetime

    from pydantic import ValidationError as PydanticValidationError

    with pytest.raises(PydanticValidationError, match="JSON-serializable"):
        ReasoningTurnDecision(
            reasoning="x",
            action="reasoning",
            observables={"ts": datetime(2026, 7, 20)},
        )


# ----------------------------------------------------------------------
# Recall durable-history backing (STEP 2). The absorb() recall branch
# accepts a module-supplied ``fetch_observable_body`` callable and uses
# it to rehydrate any pinned key that has already been evicted from the
# live observables. When no fetcher is wired (malware/forensics today),
# the branch injects a short not-available marker so the render layer
# still surfaces the recall attempt instead of dropping it silently.
# ----------------------------------------------------------------------


def _recall_decision(*keys: str) -> ReasoningTurnDecision:
    return ReasoningTurnDecision(
        reasoning="pull those bodies back",
        action="recall",
        recall_keys=list(keys),
        provenance=EvidenceProvenance(),
    )


def test_absorb_recall_present_key_no_rehydrate() -> None:
    """When the recalled key IS still in live observables, the fetcher
    is not consulted and the existing body stays put -- recall on a
    live key is a pure pin operation."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    calls: list[str] = []

    def _boom(key: str) -> str | None:
        calls.append(key)
        raise AssertionError(f"fetcher must not be consulted for live key {key!r}")

    initial = ReasoningCaseState(
        observables={"audit_mcp.read_function.source.foo": "int foo() { return 1; }"},
    )
    merged = engine.absorb(
        initial,
        _recall_decision("audit_mcp.read_function.source.foo"),
        fetch_observable_body=_boom,
    )

    assert merged.observables["audit_mcp.read_function.source.foo"] == "int foo() { return 1; }"
    assert merged.observables["_recall.pinned"] == ["audit_mcp.read_function.source.foo"]
    assert calls == []


def test_absorb_recall_evicted_key_rehydrates_from_fetcher() -> None:
    """When the recalled key is ABSENT from live observables, the
    fetcher rehydrates it and absorb re-injects the returned body under
    the same key so the render layer can render it full."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    history = {
        "audit_mcp.read_function.source.foo": "int foo(void) { return 42; }",
        "audit_mcp.read_function.source.bar": "void bar(int x) { }",
    }
    seen: list[str] = []

    def _fake_fetcher(key: str) -> str | None:
        seen.append(key)
        return history.get(key)

    initial = ReasoningCaseState()
    merged = engine.absorb(
        initial,
        _recall_decision(
            "audit_mcp.read_function.source.foo",
            "audit_mcp.read_function.source.bar",
        ),
        fetch_observable_body=_fake_fetcher,
    )

    assert merged.observables["audit_mcp.read_function.source.foo"] == "int foo(void) { return 42; }"
    assert merged.observables["audit_mcp.read_function.source.bar"] == "void bar(int x) { }"
    assert merged.observables["_recall.pinned"] == [
        "audit_mcp.read_function.source.foo",
        "audit_mcp.read_function.source.bar",
    ]
    assert seen == [
        "audit_mcp.read_function.source.foo",
        "audit_mcp.read_function.source.bar",
    ]


def test_absorb_recall_fetcher_none_result_injects_marker() -> None:
    """When the fetcher returns None for a key (durable history has no
    hit), absorb injects a short marker under the key so the render
    layer surfaces the recall attempt instead of silently dropping it."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]

    def _empty_fetcher(_key: str) -> str | None:
        return None

    merged = engine.absorb(
        ReasoningCaseState(),
        _recall_decision("audit_mcp.read_function.source.missing"),
        fetch_observable_body=_empty_fetcher,
    )

    marker = merged.observables["audit_mcp.read_function.source.missing"]
    assert "recall" in marker.lower()
    assert "not available" in marker.lower() or "not retrievable" in marker.lower()
    assert merged.observables["_recall.pinned"] == ["audit_mcp.read_function.source.missing"]


def test_absorb_recall_no_fetcher_wired_degrades_gracefully() -> None:
    """Malware/forensics-style engine construction (no fetcher wired):
    a recall of an absent key MUST NOT crash. Absorb injects the
    not-available marker under the pinned key."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]

    merged = engine.absorb(
        ReasoningCaseState(),
        _recall_decision("audit_mcp.read_function.source.orphan"),
        # No fetch_observable_body -- default None, current malware/forensics behavior.
    )

    marker = merged.observables["audit_mcp.read_function.source.orphan"]
    assert isinstance(marker, str)
    assert marker != ""
    assert "recall" in marker.lower()
    assert merged.observables["_recall.pinned"] == ["audit_mcp.read_function.source.orphan"]


def test_absorb_recall_fetcher_raises_falls_back_to_marker() -> None:
    """A misbehaving fetcher (raises an expected class) MUST NOT crash
    the turn -- absorb catches the error and injects the marker."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]

    def _raising(_key: str) -> str | None:
        raise RuntimeError("DB connection reset")

    merged = engine.absorb(
        ReasoningCaseState(),
        _recall_decision("audit_mcp.read_function.source.broken"),
        fetch_observable_body=_raising,
    )

    marker = merged.observables["audit_mcp.read_function.source.broken"]
    assert isinstance(marker, str) and marker
    assert "recall" in marker.lower()


# ----------------------------------------------------------------------
# STEP 3 -- storage caps resolve via ConfigRegistry under the platform
# namespace with the schema defaults preserved when no registry is
# wired.
# ----------------------------------------------------------------------


class _FakeConfigRegistry:
    """Minimal ConfigRegistry stub: dict-backed sync reads for tests."""

    def __init__(self, values: dict[tuple[str, str], object] | None = None) -> None:
        self._values = dict(values or {})

    def get_sync(self, namespace: str, key: str) -> object:
        return self._values.get((namespace, key))


def test_absorb_agent_key_cap_defaults_to_150() -> None:
    """No config registry wired -> the schema default (150) applies."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    seed = {f"scratch_{i}": i for i in range(200)}
    initial = ReasoningCaseState(observables=seed)
    merged = engine.absorb(
        initial,
        ReasoningTurnDecision(
            reasoning="noop",
            action="reasoning",
            provenance=EvidenceProvenance(),
        ),
    )
    agent_keys = [k for k in merged.observables if not k.startswith(("audit_mcp", "ida_headless", "_directive.", "_recall."))]
    assert len(agent_keys) == 150


def test_absorb_agent_key_cap_resolves_from_platform_registry() -> None:
    """Wire a ConfigRegistry that returns 25 -> absorb enforces 25."""
    registry = _FakeConfigRegistry(
        {("platform", "reasoning_max_agent_keys_total"): 25},
    )
    engine = CyberReasoningEngine(
        _FakeLLMClient(_FakeResponse("{}")),  # type: ignore[arg-type]
        config_registry=registry,
    )
    seed = {f"scratch_{i}": i for i in range(80)}
    initial = ReasoningCaseState(observables=seed)
    merged = engine.absorb(
        initial,
        ReasoningTurnDecision(
            reasoning="noop",
            action="reasoning",
            provenance=EvidenceProvenance(),
        ),
    )
    agent_keys = [k for k in merged.observables if not k.startswith(("audit_mcp", "ida_headless", "_directive.", "_recall."))]
    assert len(agent_keys) == 25


def test_absorb_recall_pinned_cap_defaults_to_8() -> None:
    """No config wired -> pinned working set caps at 8."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    # Prior state already has 5 pins.
    initial = ReasoningCaseState(
        observables={
            "_recall.pinned": [f"audit_mcp.old_pin.{i}" for i in range(5)],
        },
    )
    merged = engine.absorb(
        initial,
        _recall_decision(*(f"audit_mcp.new_pin.{i}" for i in range(6))),
    )
    assert len(merged.observables["_recall.pinned"]) == 8
    # Newest arrivals win.
    assert merged.observables["_recall.pinned"][-1] == "audit_mcp.new_pin.5"


def test_absorb_recall_pinned_cap_resolves_from_platform_registry() -> None:
    """Registry override 3 -> pinned working set trims to 3."""
    registry = _FakeConfigRegistry(
        {("platform", "reasoning_recall_pinned_max"): 3},
    )
    engine = CyberReasoningEngine(
        _FakeLLMClient(_FakeResponse("{}")),  # type: ignore[arg-type]
        config_registry=registry,
    )
    merged = engine.absorb(
        ReasoningCaseState(),
        _recall_decision(*(f"audit_mcp.k{i}" for i in range(10))),
    )
    assert len(merged.observables["_recall.pinned"]) == 3
    assert merged.observables["_recall.pinned"] == [
        "audit_mcp.k7", "audit_mcp.k8", "audit_mcp.k9",
    ]


def test_json_safe_observables_pass() -> None:
    # The shapes the reasoning loop actually stores: strings, ints,
    # nested json-dicts, and lists all round-trip cleanly.
    state = ReasoningCaseState(
        observables={
            "_directive.note": "steering text",
            "_reject_count": 3,
            "_pending": {"answer": "a", "blocked_at_turn": 2},
            "_recall.pinned": ["artifact-1", "artifact-2"],
        },
    )
    assert state.observables["_reject_count"] == 3
    assert state.observables["_pending"]["blocked_at_turn"] == 2


# ----------------------------------------------------------------------
# Acceptance (c): render_case_model no longer applies the 7 hardcoded
# display caps (hyp_ceiling=60 / scratchpad_ceiling=150 /
# scratchpad_preview=240 / index_ceiling=400 / recent_full_count=12 /
# recent_full_cap=4000 / index_firstline_cap=80). Every hypothesis,
# every tool reading, and every scratchpad entry now renders in full;
# the RFC-24 ContextAssembler sizes the LIVE section against a real
# token budget instead. Trimmed content stays recall-able through the
# durable message history (see absorb path).
# ----------------------------------------------------------------------


def test_render_case_model_renders_all_hypotheses_past_former_60_cap() -> None:
    """Former hyp_ceiling=60 truncated live hypothesis lists; renders now
    emit every hypothesis (RFC-24 budget layer decides fit)."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    case_state = ReasoningCaseState(
        hypotheses=[Hypothesis(id=f"H{i}", claim=f"claim {i}") for i in range(120)],
    )

    rendered = engine.render_case_model(case_state)

    for i in range(120):
        assert f"H{i}: claim {i}" in rendered, (
            f"hypothesis {i} missing -- former hyp_ceiling still capping"
        )
    # No overflow note.
    assert "rendering ceiling" not in rendered


def test_render_case_model_renders_all_scratchpad_full_body_past_former_150_240() -> None:
    """Former caps: scratchpad_ceiling=150 (drop past 150 keys) and
    scratchpad_preview=240 (per-value truncation). Neither applies now:
    every agent-set key renders with its full value."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    long_value = "X" * 500  # > former 240 preview
    observables: dict[str, object] = {
        f"scratch_key_{i}": long_value for i in range(160)  # > former 150 ceiling
    }
    case_state = ReasoningCaseState(observables=observables)

    rendered = engine.render_case_model(case_state)

    # Every key surfaces.
    for i in range(160):
        assert f"scratch_key_{i} = " in rendered, (
            f"scratchpad key {i} missing -- former scratchpad_ceiling still capping"
        )
    # Full value renders (no 240-char truncation).
    assert long_value in rendered
    # Header total reflects the full count.
    assert "agent scratchpad (160 total)" in rendered
    # No overflow note.
    assert "scratchpad rendering ceiling" not in rendered


def test_render_case_model_renders_all_tool_readings_past_former_400_12_4000() -> None:
    """Former caps: index_ceiling=400 (drop past 400 tool keys),
    recent_full_count=12 (only last 12 in full-body block), and
    recent_full_cap=4000 (per-body preview truncation). Removed:
    every tool key renders in full both in the INDEX and in the
    full-body block; large bodies render verbatim so file:line
    anchors survive."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    # 450 tool readings past the former 400 index ceiling. Each body
    # is 4500 chars past the former 4000 full-body preview cap so we
    # can also assert per-body cap removal on the last one.
    big_body = "BODY_LINE_1\nBODY_LINE_2\n" + ("Z" * 4500)
    observables: dict[str, object] = {
        f"audit_mcp.read_function.k{i}": big_body for i in range(450)
    }
    case_state = ReasoningCaseState(observables=observables)

    rendered = engine.render_case_model(case_state)

    # Every key surfaces in the INDEX (past former 400 cap).
    for i in (0, 200, 399, 400, 449):
        assert f"audit_mcp.read_function.k{i}" in rendered, (
            f"tool key {i} missing -- former index_ceiling still capping"
        )
    # Header total reflects the full count.
    assert "tool readings INDEX (450 total" in rendered
    # No overflow note.
    assert "indexing ceiling" not in rendered
    # Full-body section: keys past former 12-recent window render in
    # full without the "preview; recall this key" tail.
    assert "[preview; recall this key for full body]" not in rendered
    # Body is preserved verbatim (past former 4000 cap).
    assert ("Z" * 4500) in rendered


def test_render_case_model_first_line_preview_uncapped() -> None:
    """Former index_firstline_cap=80: the INDEX line's preview was
    cropped to 80 chars. Removed: the first line renders verbatim so
    an operator scanning the INDEX sees the full label."""
    engine = CyberReasoningEngine(_FakeLLMClient(_FakeResponse("{}")))  # type: ignore[arg-type]
    long_first_line = "first-line marker: " + ("F" * 300)  # > former 80 cap
    case_state = ReasoningCaseState(
        observables={"audit_mcp.k": long_first_line + "\nsecond line"},
    )

    rendered = engine.render_case_model(case_state)

    assert long_first_line in rendered, (
        "first-line preview truncated -- former index_firstline_cap still capping"
    )
