"""Wave-2 VR-truth deferred/partial gate coverage.

Pure-unit tests for the submit-time gates added to
:mod:`aila.modules.vr.agents.vuln_researcher` and the deterministic
distinctness score in :mod:`aila.modules.vr.services.distinctness`.
No DB, no engine, no live LLM: the gates read a decision + case_state
in memory and either pass, swap the action to ``reasoning`` carrying the
rejection text, or stamp the payload.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.modules.vr.agents.vuln_researcher import (
    HonestVulnResearcher,
    _extract_cited_tool_pairs,
)
from aila.modules.vr.services.distinctness import (
    compute_distinctness_score,
    extract_candidate_text,
    extract_corpus_texts,
    tokenize,
)
from aila.platform.agents.prompt_sections import render_active_directives_section
from aila.platform.contracts.reasoning import (
    EvidenceProvenance,
    Hypothesis,
    ReasoningCaseState,
    ReasoningTurnDecision,
)


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------


def _make_researcher() -> HonestVulnResearcher:
    """Instantiate a researcher with wave-2 knobs enabled without a live engine.

    ``HonestVulnResearcher.__init__`` only stores its arguments -- the
    engine is not consulted at construction time. Passing ``None`` for
    the engine is safe because none of the wave-2 gate methods touch
    it. Loop config knobs are set by hand to mirror the
    ``_load_turn_config`` output.
    """
    r = HonestVulnResearcher(
        reasoning_engine=None,  # type: ignore[arg-type]
        investigation_id="inv-test",
        branch_id="br-test",
    )
    r._unresolved_hyp_reject_cap = 3
    r._promote_confirmed_findings = True
    r._require_confirmed_evidence_on_positive_submit = True
    r._contradiction_gate_enabled = True
    r._tool_telemetry_crosscheck_enabled = True
    r._tool_work_floor_probes = 1
    r._kill_criterion_scan_cap = 20
    r._kill_criterion_overlap_threshold = 0.5
    r._distinctness_score_enabled = True
    return r


def _make_submit(
    *,
    answer: str = "found a heap overflow in decode_frame",
    confidence: str = "strong",
    payload: dict[str, Any] | None = None,
) -> ReasoningTurnDecision:
    return ReasoningTurnDecision(
        action="submit",
        answer=answer,
        reasoning="test",
        confidence=confidence,
        provenance=EvidenceProvenance(),
        payload=dict(payload or {}),
    )


def _empty_case() -> ReasoningCaseState:
    return ReasoningCaseState()


def _assert_gate_reset(
    r: HonestVulnResearcher,
    case: ReasoningCaseState,
    gate: str,
) -> None:
    assert f"_gate.{gate}.reject_count" not in case.observables
    assert f"_directive.gate.{gate}.rejected" not in case.observables
    assert f"gate.{gate}.rejected" not in render_active_directives_section(case)
    assert gate not in r._wave2_rejections
    assert gate not in r._settled_wave2_gates


# ---------------------------------------------------------------------------
# Distinctness metric.
# ---------------------------------------------------------------------------


def test_distinctness_score_is_zero_on_exact_restatement() -> None:
    corpus = ["heap overflow in decode_frame parsing input header field"]
    score = compute_distinctness_score(
        "heap overflow in decode_frame parsing input header field", corpus,
    )
    assert score == 0.0


def test_distinctness_score_is_one_on_empty_corpus() -> None:
    assert (
        compute_distinctness_score(
            "arbitrary write via oob store in codec plugin", [],
        )
        == 1.0
    )


def test_distinctness_score_is_inconclusive_below_min_tokens() -> None:
    assert compute_distinctness_score("rce here", ["long corpus entry"]) == 0.5


def test_distinctness_score_is_deterministic() -> None:
    corpus = ["seed hypothesis A about parser", "prior outcome B about decoder"]
    text = "novel finding about a totally distinct sink in the runtime"
    a = compute_distinctness_score(text, corpus)
    b = compute_distinctness_score(text, corpus)
    assert a == b


def test_extract_helpers_skip_non_string_entries() -> None:
    payload = {
        "answer": "buffer overflow in parse_header",
        "reasoning": None,
        "provenance": {"primary_artifact": "audit_mcp:read_function#123"},
    }
    text = extract_candidate_text(payload)
    assert "parse_header" in text and "audit_mcp:read_function" in text
    corpus = extract_corpus_texts(
        seed_hypotheses=[{"claim": "overflow in parser"}, {"claim": None}],
        prior_outcomes=[{"answer": ""}, {"answer": "prior finding"}],
    )
    assert corpus == ["overflow in parser", "prior finding"]


def test_tokenize_drops_stopwords_and_short_tokens() -> None:
    tokens = tokenize("The and buffer of an in decode_frame X")
    assert "buffer" in tokens
    assert "decode_frame" in tokens
    assert "the" not in tokens
    assert "an" not in tokens


# ---------------------------------------------------------------------------
# F1 positive-submit-needs-confirmed-evidence gate (#254 W3).
# ---------------------------------------------------------------------------


def test_positive_submit_rejected_when_refs_and_confirmation_missing() -> None:
    r = _make_researcher()
    case = _empty_case()
    decision = _make_submit(payload={})
    out = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=1,
    )
    assert out.action == "reasoning"
    assert out.payload["_gate.positive_submit_refs.rejected"] is True
    assert case.observables["_gate.positive_submit_refs.reject_count"] == 1
    assert isinstance(
        case.observables["_directive.gate.positive_submit_refs.rejected"], str,
    )


def test_rejected_positive_submit_surfaces_directive_in_active_directives_section() -> None:
    r = _make_researcher()
    case = _empty_case()
    decision = _make_submit(answer="heap overflow in decode_frame", payload={})
    out = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=1,
    )
    assert out.action == "reasoning"
    assert "Original submit attempt:\nheap overflow in decode_frame" in out.reasoning
    body = case.observables["_directive.gate.positive_submit_refs.rejected"]
    assert "Rejection 1/3 on this branch" in body
    section = render_active_directives_section(case)
    assert "## directive: gate.positive_submit_refs.rejected" in section
    assert body in section


def test_rejected_positive_submit_directive_tracks_latest_rejection() -> None:
    r = _make_researcher()
    case = _empty_case()
    r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=_make_submit(payload={}), case_state=case, turn_number=1,
    )
    out = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=_make_submit(payload={}), case_state=case, turn_number=2,
    )
    assert out.action == "reasoning"
    body = case.observables["_directive.gate.positive_submit_refs.rejected"]
    assert "Rejection 2/3 on this branch" in body
    assert case.observables["_gate.positive_submit_refs.reject_count"] == 2
    assert body in render_active_directives_section(case)


def test_positive_submit_passes_when_refs_and_confirmation_present() -> None:
    r = _make_researcher()
    case = _empty_case()
    case.hypotheses = [
        Hypothesis(id="h1", claim="stack overflow", confirmed_by="foo.c:42"),
    ]
    decision = _make_submit(
        payload={"evidence_refs": ["audit_mcp:read_function#42"]},
    )
    out = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=1,
    )
    assert out.action == "submit"
    assert "_gate.positive_submit_refs.reject_count" not in case.observables


def test_positive_submit_forces_through_over_cap() -> None:
    r = _make_researcher()
    r._unresolved_hyp_reject_cap = 1
    case = _empty_case()
    case.observables["_gate.positive_submit_refs.reject_count"] = 1
    case.observables["_directive.gate.positive_submit_refs.rejected"] = "stale"
    decision = _make_submit(payload={})
    out = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=2,
    )
    assert out.action == "submit"
    assert "positive_submit_evidence_advisory" in out.payload
    assert out.payload["positive_submit_evidence_advisory"][
        "forced_through_after_rejects"
    ] == 1
    assert "_directive.gate.positive_submit_refs.rejected" not in case.observables
    assert "_gate.positive_submit_refs.reject_count" not in case.observables


def test_positive_gate_off_when_toggle_disabled() -> None:
    r = _make_researcher()
    r._require_confirmed_evidence_on_positive_submit = False
    decision = _make_submit(payload={})
    out = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=_empty_case(), turn_number=1,
    )
    assert out is decision


# ---------------------------------------------------------------------------
# F3 pre-draft contradiction gate (#249 W7 cited-observable variant).
# ---------------------------------------------------------------------------


def test_negative_submit_rejected_when_cited_observable_has_positive_marker() -> None:
    r = _make_researcher()
    case = _empty_case()
    case.observables["audit_mcp:read_function#42"] = (
        "trace shows ASan: heap-buffer-overflow at decode_frame+0x14"
    )
    decision = ReasoningTurnDecision(
        action="submit",
        answer="no vulnerability found",
        reasoning="test",
        confidence="strong",
        provenance=EvidenceProvenance(),
        payload={"evidence_refs": ["audit_mcp:read_function#42"]},
    )
    out = r._maybe_reject_negative_submit_contradicting_observable(
        decision=decision, case_state=case, turn_number=1,
    )
    assert out.action == "reasoning"
    assert out.payload["_gate.contradiction_observable.rejected"] is True
    assert isinstance(
        case.observables["_directive.gate.contradiction_observable.rejected"], str,
    )


def test_negative_submit_passes_when_no_positive_marker_in_cited_observable() -> None:
    r = _make_researcher()
    case = _empty_case()
    case.observables["audit_mcp:read_function#42"] = (
        "function has a length check before the copy; no oob write reachable"
    )
    decision = ReasoningTurnDecision(
        action="submit",
        answer="no vulnerability found",
        reasoning="test",
        confidence="strong",
        provenance=EvidenceProvenance(),
        payload={"evidence_refs": ["audit_mcp:read_function#42"]},
    )
    out = r._maybe_reject_negative_submit_contradicting_observable(
        decision=decision, case_state=case, turn_number=1,
    )
    assert out is decision


# ---------------------------------------------------------------------------
# F4 tool-telemetry helper (issue #247 B3).
# ---------------------------------------------------------------------------


def test_extract_cited_tool_pairs_reads_string_dict_and_provenance() -> None:
    payload = {
        "evidence_refs": [
            "audit_mcp:read_function#abc",
            {"tool": "ida_headless", "action": "callers_of"},
        ],
        "provenance": {
            "primary_artifact": "audit_mcp.semantic_search#12",
            "corroboration": ["android_mcp:list_permissions"],
        },
        "tool_calls": [{"tool": "knowledge", "action": "search"}],
    }
    pairs = _extract_cited_tool_pairs(payload)
    assert ("audit_mcp", "read_function") in pairs
    assert ("ida_headless", "callers_of") in pairs
    assert ("audit_mcp", "semantic_search") in pairs
    assert ("android_mcp", "list_permissions") in pairs
    assert ("knowledge", "search") in pairs


def test_extract_cited_tool_pairs_empty_on_bare_prose() -> None:
    payload = {"answer": "just prose, no tool cite here"}
    assert _extract_cited_tool_pairs(payload) == set()


# ---------------------------------------------------------------------------
# F7 distinctness stamp.
# ---------------------------------------------------------------------------


def test_distinctness_stamp_lands_on_positive_submit() -> None:
    r = _make_researcher()
    decision = _make_submit(
        answer="fresh heap overflow in libcodec decoder parsing loop",
    )
    out = r._stamp_distinctness_score(
        decision=decision,
        prior_outcomes=[{"answer": "totally unrelated recon note"}],
    )
    assert out.payload["distinctness_score"] > 0.5
    assert out.payload["distinctness_corpus_size"] == 1


def test_distinctness_stamp_skipped_when_disabled() -> None:
    r = _make_researcher()
    r._distinctness_score_enabled = False
    decision = _make_submit()
    out = r._stamp_distinctness_score(decision=decision, prior_outcomes=[])
    assert "distinctness_score" not in (out.payload or {})


def test_distinctness_stamp_skipped_on_negative_polarity() -> None:
    r = _make_researcher()
    decision = ReasoningTurnDecision(
        action="submit",
        answer="no vulnerability found",  # coerces to AUDIT_MEMO
        reasoning="test",
        confidence="strong",
        provenance=EvidenceProvenance(),
        payload={},
    )
    out = r._stamp_distinctness_score(decision=decision, prior_outcomes=[])
    assert "distinctness_score" not in (out.payload or {})


# ---------------------------------------------------------------------------
# Gate counter and directive lifecycle.
# ---------------------------------------------------------------------------


def test_gate_pass_clears_counter_and_directive() -> None:
    r = _make_researcher()
    case = _empty_case()
    case.observables["_gate.positive_submit_refs.reject_count"] = 2
    case.observables["_directive.gate.positive_submit_refs.rejected"] = "stale"
    case.hypotheses = [
        Hypothesis(id="h1", claim="x", confirmed_by="foo:1"),
    ]
    decision = _make_submit(
        payload={"evidence_refs": ["audit_mcp:read_function#42"]},
    )
    r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=3,
    )
    assert "_gate.positive_submit_refs.reject_count" not in case.observables
    assert "_directive.gate.positive_submit_refs.rejected" not in case.observables
    assert "gate.positive_submit_refs.rejected" not in render_active_directives_section(case)


# ---------------------------------------------------------------------------
# F2 kill_criterion evaluator (pure token-overlap logic).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_kill_criterion_scan_skipped_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _make_researcher()
    r._kill_criterion_scan_cap = 0
    case = _empty_case()
    case.hypotheses = [
        Hypothesis(
            id="h1", claim="oob write", kill_criterion="check for bounds guard",
        ),
    ]
    case.observables["audit_mcp:read_function#42"] = (
        "no bounds check present; unchecked copy into stack buffer"
    )
    called: list[str] = []

    class _FakeLedger:
        async def append_general(self, *args: Any, **kwargs: Any) -> int:
            called.append("general")
            return 1

        async def append_adjudication(self, *args: Any, **kwargs: Any) -> int:
            called.append("adjudication")
            return 1

    monkeypatch.setattr(
        "aila.modules.vr.agents.vuln_researcher.LedgerService",
        lambda: _FakeLedger(),
    )
    await r._evaluate_kill_criteria_this_turn(
        case_state=case, turn_number=1,
    )
    assert called == []


@pytest.mark.asyncio
async def test_kill_criterion_writes_refuted_adjudication_on_guard_vs_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r = _make_researcher()
    case = _empty_case()
    case.hypotheses = [
        Hypothesis(
            id="h1",
            claim="oob write",
            kill_criterion="a bounds check would guard the copy",
        ),
    ]
    case.observables["audit_mcp:read_function#42"] = (
        "the copy proceeds with no bounds check; buffer size unchecked"
    )
    calls: list[tuple[str, dict[str, Any]]] = []

    class _FakeLedger:
        async def append_general(self, *args: Any, **kwargs: Any) -> int:
            calls.append(("general", kwargs))
            return 1

        async def append_adjudication(
            self, investigation_id: str, branch_id: str, **kwargs: Any,
        ) -> int:
            calls.append(("adjudication", {
                "verdict": kwargs.get("verdict"),
                "target": kwargs.get("target_hypothesis_id"),
                "cites": list(kwargs.get("cited_evidence") or []),
            }))
            return 1

    monkeypatch.setattr(
        "aila.modules.vr.agents.vuln_researcher.LedgerService",
        lambda: _FakeLedger(),
    )
    await r._evaluate_kill_criteria_this_turn(
        case_state=case, turn_number=5,
    )
    kinds = [k for k, _ in calls]
    assert "adjudication" in kinds
    ad = next(v for k, v in calls if k == "adjudication")
    assert ad["verdict"] == "refuted"
    assert ad["target"] == "h1"
    assert ad["cites"] == ["audit_mcp:read_function#42"]


@pytest.mark.asyncio
async def test_kill_criterion_writes_discovery_when_not_refuted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r = _make_researcher()
    case = _empty_case()
    case.hypotheses = [
        Hypothesis(
            id="h2",
            claim="parser mishandles length field",
            kill_criterion="parser handles length field correctly",
        ),
    ]
    case.observables["audit_mcp:read_function#7"] = (
        "the parser handles the length field correctly with a size cap"
    )
    calls: list[tuple[str, dict[str, Any]]] = []

    class _FakeLedger:
        async def append_general(
            self, investigation_id: str, branch_id: str, kind: str,
            payload: dict[str, Any], **kwargs: Any,
        ) -> int:
            calls.append((kind, payload))
            return 1

        async def append_adjudication(self, *args: Any, **kwargs: Any) -> int:
            calls.append(("adjudication", kwargs))
            return 1

    monkeypatch.setattr(
        "aila.modules.vr.agents.vuln_researcher.LedgerService",
        lambda: _FakeLedger(),
    )
    await r._evaluate_kill_criteria_this_turn(
        case_state=case, turn_number=9,
    )
    kinds = [k for k, _ in calls]
    assert "discovery" in kinds
    _, payload = next((k, v) for k, v in calls if k == "discovery")
    assert payload["hypothesis_id"] == "h2"
    assert payload["matched_observable"] == "audit_mcp:read_function#7"


# ---------------------------------------------------------------------------
# #298 / #299 settled wave-2 gates: a same-turn force-through must not be
# re-armed by the fanout hook, and each gate evaluates once per turn.
# ---------------------------------------------------------------------------


async def _passthrough_draft_pending(
    *, decision: ReasoningTurnDecision, case_state: ReasoningCaseState, turn_number: int,
) -> ReasoningTurnDecision:
    return decision


async def _no_prior_outcomes() -> list[dict[str, Any]]:
    return []


def _stub_async_hooks(monkeypatch: pytest.MonkeyPatch, r: HonestVulnResearcher) -> None:
    monkeypatch.setattr(r, "_draft_pending_check", _passthrough_draft_pending)
    monkeypatch.setattr(r, "_load_prior_outcomes", _no_prior_outcomes)


def _isolate_positive_gate(r: HonestVulnResearcher) -> None:
    """Disable the DB-reading, telemetry, and distinctness-stamp paths so only
    the in-memory positive/negative gates are exercised (no UnitOfWork, no engine)."""
    r._tool_telemetry_crosscheck_enabled = False
    r._tool_work_floor_probes = 0
    r._distinctness_score_enabled = False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("gate", "method_name", "toggle", "disabled_value", "is_async"),
    [
        (
            "positive_submit_refs",
            "_maybe_reject_positive_submit_without_confirmed_evidence",
            "_require_confirmed_evidence_on_positive_submit",
            False,
            False,
        ),
        (
            "contradiction_observable",
            "_maybe_reject_negative_submit_contradicting_observable",
            "_contradiction_gate_enabled",
            False,
            False,
        ),
        (
            "tool_telemetry",
            "_maybe_reject_submit_with_uncalled_tool_cite",
            "_tool_telemetry_crosscheck_enabled",
            False,
            True,
        ),
        (
            "tool_work_floor",
            "_maybe_reject_positive_submit_below_tool_work_floor",
            "_tool_work_floor_probes",
            0,
            True,
        ),
    ],
)
async def test_disabled_wave2_gate_resets_rejection_without_settling(
    gate: str,
    method_name: str,
    toggle: str,
    disabled_value: bool | int,
    is_async: bool,
) -> None:
    r = _make_researcher()
    case = _empty_case()
    decision = _make_submit(payload={})
    rejected = r._reject_or_force(
        gate=gate,
        decision=decision,
        case_state=case,
        turn_number=4,
        directive="mandatory rejection",
        payload_advisory_key=f"{gate}_advisory",
        advisory_payload={},
        log_label=gate,
    )
    assert rejected.action == "reasoning"
    assert r._settled_wave2_gates[gate] == 4

    setattr(r, toggle, disabled_value)
    method = getattr(r, method_name)
    out = method(decision=decision, case_state=case, turn_number=4)
    if is_async:
        out = await out

    assert out is decision
    _assert_gate_reset(r, case, gate)


def test_disabled_positive_gate_reevaluates_when_reenabled() -> None:
    r = _make_researcher()
    case = _empty_case()
    decision = _make_submit(payload={})
    first = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=1,
    )
    assert first.action == "reasoning"

    r._require_confirmed_evidence_on_positive_submit = False
    disabled = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=1,
    )
    assert disabled is decision
    _assert_gate_reset(r, case, "positive_submit_refs")

    r._require_confirmed_evidence_on_positive_submit = True
    same_turn = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=1,
    )
    assert same_turn.action == "reasoning"
    assert same_turn is not first
    assert case.observables["_gate.positive_submit_refs.reject_count"] == 1

    r._require_confirmed_evidence_on_positive_submit = False
    r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=1,
    )
    _assert_gate_reset(r, case, "positive_submit_refs")
    r._require_confirmed_evidence_on_positive_submit = True
    later_turn = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=decision, case_state=case, turn_number=2,
    )
    assert later_turn.action == "reasoning"
    assert case.observables["_gate.positive_submit_refs.reject_count"] == 1


def test_disabled_contradiction_gate_reevaluates_same_turn_when_reenabled() -> None:
    r = _make_researcher()
    case = _empty_case()
    case.observables["audit_mcp:read_function#42"] = (
        "trace shows ASan: heap-buffer-overflow at decode_frame+0x14"
    )
    decision = ReasoningTurnDecision(
        action="submit",
        answer="no vulnerability found",
        reasoning="test",
        confidence="strong",
        provenance=EvidenceProvenance(),
        payload={"evidence_refs": ["audit_mcp:read_function#42"]},
    )
    first = r._maybe_reject_negative_submit_contradicting_observable(
        decision=decision, case_state=case, turn_number=1,
    )
    assert first.action == "reasoning"

    r._contradiction_gate_enabled = False
    disabled = r._maybe_reject_negative_submit_contradicting_observable(
        decision=decision, case_state=case, turn_number=1,
    )
    assert disabled is decision
    _assert_gate_reset(r, case, "contradiction_observable")

    r._contradiction_gate_enabled = True
    reenabled = r._maybe_reject_negative_submit_contradicting_observable(
        decision=decision, case_state=case, turn_number=1,
    )
    assert reenabled.action == "reasoning"
    assert reenabled is not first
    assert case.observables["_gate.contradiction_observable.reject_count"] == 1


@pytest.mark.asyncio
async def test_forced_positive_gate_settles_through_async_and_fanout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r = _make_researcher()
    _isolate_positive_gate(r)
    _stub_async_hooks(monkeypatch, r)
    r._unresolved_hyp_reject_cap = 1
    case = _empty_case()
    case.observables["_gate.positive_submit_refs.reject_count"] = 1

    decision = await r._maybe_reject_submit_when_draft_pending(
        decision=_make_submit(payload={}), case_state=case, turn_number=1,
    )
    assert decision.action == "submit"
    assert "positive_submit_evidence_advisory" in decision.payload
    assert "_gate.positive_submit_refs.reject_count" not in case.observables

    out = r._maybe_reject_fanout_submit(
        decision=decision, inv=None, case_state=case, turn_number=1,
    )
    assert out.action == "submit"
    assert "positive_submit_evidence_advisory" in out.payload
    assert "_gate.positive_submit_refs.reject_count" not in case.observables


def test_forced_positive_gate_does_not_skip_independent_negative_gate() -> None:
    r = _make_researcher()
    _isolate_positive_gate(r)
    r._unresolved_hyp_reject_cap = 1
    case = _empty_case()
    case.observables["_gate.positive_submit_refs.reject_count"] = 1
    case.observables["audit_mcp:read_function#42"] = (
        "trace shows ASan: heap-buffer-overflow at decode_frame+0x14"
    )

    forced = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=_make_submit(payload={}), case_state=case, turn_number=1,
    )
    assert forced.action == "submit"

    negative = ReasoningTurnDecision(
        action="submit",
        answer="no vulnerability found",
        reasoning="test",
        confidence="strong",
        provenance=EvidenceProvenance(),
        payload={"evidence_refs": ["audit_mcp:read_function#42"]},
    )
    out = r._maybe_reject_fanout_submit(
        decision=negative, inv=None, case_state=case, turn_number=1,
    )
    assert out.action == "reasoning"
    assert out.payload["_gate.contradiction_observable.rejected"] is True
    assert case.observables["_gate.contradiction_observable.reject_count"] == 1


def test_forced_positive_gate_reevaluates_next_turn() -> None:
    r = _make_researcher()
    _isolate_positive_gate(r)
    r._unresolved_hyp_reject_cap = 1
    case = _empty_case()
    case.observables["_gate.positive_submit_refs.reject_count"] = 1

    forced = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=_make_submit(payload={}), case_state=case, turn_number=1,
    )
    assert forced.action == "submit"

    out = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=_make_submit(payload={}), case_state=case, turn_number=2,
    )
    assert out.action == "reasoning"
    assert case.observables["_gate.positive_submit_refs.reject_count"] == 1


def test_fanout_fallback_evaluates_unsettled_positive_gate() -> None:
    r = _make_researcher()
    _isolate_positive_gate(r)
    case = _empty_case()

    out = r._maybe_reject_fanout_submit(
        decision=_make_submit(payload={}), inv=None, case_state=case, turn_number=1,
    )
    assert out.action == "reasoning"
    assert case.observables["_gate.positive_submit_refs.reject_count"] == 1


@pytest.mark.asyncio
async def test_forced_positive_chain_and_fanout_evaluate_kind_once_per_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    r = _make_researcher()
    _isolate_positive_gate(r)
    _stub_async_hooks(monkeypatch, r)
    r._unresolved_hyp_reject_cap = 1
    case = _empty_case()
    case.observables["_gate.positive_submit_refs.reject_count"] = 1

    kind_calls: list[str] = []
    original_kind = r._terminal_outcome_kind

    def _counting_kind(decision: ReasoningTurnDecision) -> Any:
        kind_calls.append(decision.action)
        return original_kind(decision)

    r._terminal_outcome_kind = _counting_kind  # type: ignore[method-assign]

    decision = await r._maybe_reject_submit_when_draft_pending(
        decision=_make_submit(payload={}), case_state=case, turn_number=1,
    )
    r._maybe_reject_fanout_submit(
        decision=decision, inv=None, case_state=case, turn_number=1,
    )
    # Async chain: positive gate (forced, settled) + negative gate (positive
    # polarity, settled). Fanout: both gates already settled this turn, so
    # neither re-derives the terminal kind.
    assert len(kind_calls) == 2


def test_rejected_positive_submit_replays_same_turn_decision() -> None:
    r = _make_researcher()
    _isolate_positive_gate(r)
    r._unresolved_hyp_reject_cap = 1
    case = _empty_case()
    original_submit = _make_submit(payload={})

    kind_calls: list[str] = []
    original_kind = r._terminal_outcome_kind

    def _counting_kind(decision: ReasoningTurnDecision) -> Any:
        kind_calls.append(decision.action)
        return original_kind(decision)

    r._terminal_outcome_kind = _counting_kind  # type: ignore[method-assign]

    first = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=original_submit, case_state=case, turn_number=1,
    )
    second = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=original_submit, case_state=case, turn_number=1,
    )

    assert first.action == "reasoning"
    assert "Original submit attempt:\nfound a heap overflow in decode_frame" in first.reasoning
    assert second == first
    assert kind_calls == ["submit"]
    assert case.observables["_gate.positive_submit_refs.reject_count"] == 1
    assert case.observables["_directive.gate.positive_submit_refs.rejected"] in (
        render_active_directives_section(case)
    )

    later = r._maybe_reject_positive_submit_without_confirmed_evidence(
        decision=original_submit, case_state=case, turn_number=2,
    )
    assert later.action == "submit"
    assert "positive_submit_evidence_advisory" in later.payload
    assert kind_calls == ["submit", "submit"]


def test_rejected_contradiction_gate_replays_same_turn_decision() -> None:
    r = _make_researcher()
    _isolate_positive_gate(r)
    r._unresolved_hyp_reject_cap = 1
    case = _empty_case()
    case.observables["audit_mcp:read_function#42"] = (
        "trace shows ASan: heap-buffer-overflow at decode_frame+0x14"
    )
    original_submit = ReasoningTurnDecision(
        action="submit",
        answer="no vulnerability found",
        reasoning="test",
        confidence="strong",
        provenance=EvidenceProvenance(),
        payload={"evidence_refs": ["audit_mcp:read_function#42"]},
    )

    kind_calls: list[str] = []
    original_kind = r._terminal_outcome_kind

    def _counting_kind(decision: ReasoningTurnDecision) -> Any:
        kind_calls.append(decision.action)
        return original_kind(decision)

    r._terminal_outcome_kind = _counting_kind  # type: ignore[method-assign]

    first = r._maybe_reject_negative_submit_contradicting_observable(
        decision=original_submit, case_state=case, turn_number=1,
    )
    second = r._maybe_reject_negative_submit_contradicting_observable(
        decision=original_submit, case_state=case, turn_number=1,
    )

    assert first.action == "reasoning"
    assert second == first
    assert kind_calls == ["submit"]
    assert case.observables["_gate.contradiction_observable.reject_count"] == 1
    assert case.observables["_directive.gate.contradiction_observable.rejected"] in (
        render_active_directives_section(case)
    )

    later = r._maybe_reject_negative_submit_contradicting_observable(
        decision=original_submit, case_state=case, turn_number=2,
    )
    assert later.action == "submit"
    assert "contradiction_observable_advisory" in later.payload
    assert kind_calls == ["submit", "submit"]
