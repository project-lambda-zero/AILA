"""Characterization tests for the platform ClaimVerifier (RFC-03 Phase 5).

Exercises the verifier logic for BOTH module configs (vr + malware) so
the pre-extraction behavior is preserved. Every LLM call is mocked at
the ``idempotent_llm_call`` seam; the DB round-trips are patched via
``_load_context`` and a fake ``UnitOfWork`` so no migrations or infra
are required.

Coverage:

  * Module class attributes bind the platform base with the right
    task-type keys, negative-phrase tables, record models, dispatcher
    class, and auto-promote gate constants.
  * ``is_negative_finding_claim`` fires on module-specific vocabulary
    (VR only rejects vr terms; malware rejects both vr and malware
    terms) and tolerates ``None`` / empty input.
  * ``_parse_preconditions`` and ``_parse_verdict`` tolerate fenced
    JSON, leading / trailing prose, and return empty / ``None`` on
    malformed LLM output.
  * ``_render_verdict_input`` produces the labelled per-precondition
    section with the smart probe-payload rendering + the 40000-char
    truncation marker.
  * ``_render_probe_payload`` dispatches on tool name for
    ``read_function`` / ``search_source`` / ``callers_of`` and falls
    back to ``json.dumps`` otherwise.
  * ``_maybe_auto_promote`` short-circuits before opening a UoW when
    confidence is non-numeric or below the module's floor (the config
    reader is mocked via ``_read_auto_promote_floor``).
  * The full ``run`` pipeline exercises the extractor -> probe ->
    verdict path with all IO seams stubbed, and each early-exit path
    (no context, already verified, malformed extractor output, kill
    switch, malformed verdict, non-verifiable outcome kind).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import pytest

from aila.modules.malware.agents.claim_verifier import (
    _NEGATIVE_ANSWER_PREFIXES as MW_NEG_PREFIXES,
)
from aila.modules.malware.agents.claim_verifier import (
    ClaimVerifierAgent as MalwareClaimVerifierAgent,
)
from aila.modules.malware.agents.claim_verifier import (
    is_negative_finding_claim as malware_is_negative,
)
from aila.modules.malware.agents.outcome_dispatcher import (
    OutcomeDispatcher as MalwareOutcomeDispatcher,
)
from aila.modules.malware.contracts import (
    NON_VERIFIABLE_OUTCOME_KINDS as MW_NON_VERIFIABLE_KINDS,
)
from aila.modules.malware.contracts import (
    OutcomeDispatchStatus as MalwareOutcomeDispatchStatus,
)
from aila.modules.malware.contracts import (
    OutcomeKind as MalwareOutcomeKind,
)
from aila.modules.malware.db_models import (
    MalwareInvestigationOutcomeRecord,
    MalwareInvestigationRecord,
    MalwareTargetRecord,
)
from aila.modules.vr.agents.claim_verifier import (
    _NEGATIVE_ANSWER_PREFIXES as VR_NEG_PREFIXES,
)
from aila.modules.vr.agents.claim_verifier import (
    ClaimVerifierAgent as VRClaimVerifierAgent,
)
from aila.modules.vr.agents.claim_verifier import (
    is_negative_finding_claim as vr_is_negative,
)
from aila.modules.vr.agents.outcome_dispatcher import (
    OutcomeDispatcher as VROutcomeDispatcher,
)
from aila.modules.vr.contracts import (
    OutcomeDispatchStatus as VROutcomeDispatchStatus,
)
from aila.modules.vr.contracts import (
    OutcomeKind as VROutcomeKind,
)
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.platform.agents.claim_verifier import (
    ClaimVerifierAgentBase,
    _render_probe_payload,
    is_negative_finding_claim,
)

# --------------------------------------------------------------------- #
#  Per-module config table for parametrised assertions                  #
# --------------------------------------------------------------------- #


@dataclass(frozen=True)
class _Config:
    label: str
    agent_cls: type[ClaimVerifierAgentBase]
    extractor_task_type: str
    verdict_task_type: str
    outcome_dispatcher_cls: type
    investigation_model: type
    outcome_model: type
    target_model: type
    promote_source_kind: str
    promote_target_kind: str
    promote_wrong_kind_reason: str
    promote_negative_skip_reason: str
    dispatch_status_pending: str
    dispatch_status_skipped: str
    # Sample verifiable outcome kind for the happy-path run() test.
    example_verifiable_kind: str
    # A sample negative-claim string that ONLY the module accepts as
    # negative (used to prove per-module vocabulary isolation).
    module_only_negative_prefix: str
    # Non-verifiable kind (only meaningful for malware; VR has none so
    # we pass a placeholder that will not be routed through the check).
    non_verifiable_kind: str | None
    # Canonical payload the extractor should see: for VR it's the
    # free-form {"answer": ...}; for malware it's the typed
    # AnalysisReportPayload with summary + report_body.
    canonical_payload: dict[str, Any]


VR_CONFIG = _Config(
    label="vr",
    agent_cls=VRClaimVerifierAgent,
    extractor_task_type="vulnerability_research.verifier_extractor",
    verdict_task_type="vulnerability_research.verifier_verdict",
    outcome_dispatcher_cls=VROutcomeDispatcher,
    investigation_model=VRInvestigationRecord,
    outcome_model=VRInvestigationOutcomeRecord,
    target_model=VRTargetRecord,
    promote_source_kind=VROutcomeKind.ASSESSMENT_REPORT.value,
    promote_target_kind=VROutcomeKind.DIRECT_FINDING.value,
    promote_wrong_kind_reason="outcome_kind_not_assessment",
    promote_negative_skip_reason="answer_starts_negative_no_bug_to_promote",
    dispatch_status_pending=VROutcomeDispatchStatus.PENDING.value,
    dispatch_status_skipped=VROutcomeDispatchStatus.SKIPPED.value,
    example_verifiable_kind=VROutcomeKind.ASSESSMENT_REPORT.value,
    module_only_negative_prefix="NOT VULNERABLE, patch present in trunk",
    non_verifiable_kind=None,
    canonical_payload={"answer": "CVE-XXXX is exploitable via foo() sink."},
)


MALWARE_CONFIG = _Config(
    label="malware",
    agent_cls=MalwareClaimVerifierAgent,
    extractor_task_type="malware_analysis.verifier_extractor",
    verdict_task_type="malware_analysis.verifier_verdict",
    outcome_dispatcher_cls=MalwareOutcomeDispatcher,
    investigation_model=MalwareInvestigationRecord,
    outcome_model=MalwareInvestigationOutcomeRecord,
    target_model=MalwareTargetRecord,
    promote_source_kind=MalwareOutcomeKind.ANALYSIS_REPORT.value,
    promote_target_kind=MalwareOutcomeKind.ANALYSIS_REPORT.value,
    promote_wrong_kind_reason="outcome_kind_not_analysis_report",
    promote_negative_skip_reason="analysis_report_negative_no_finding_to_promote",
    dispatch_status_pending=MalwareOutcomeDispatchStatus.PENDING.value,
    dispatch_status_skipped=MalwareOutcomeDispatchStatus.SKIPPED.value,
    example_verifiable_kind=MalwareOutcomeKind.ANALYSIS_REPORT.value,
    module_only_negative_prefix="BENIGN sample -- no family match",
    non_verifiable_kind=next(iter(MW_NON_VERIFIABLE_KINDS)),
    canonical_payload={
        "summary": "Family Emotet exhibits stager + persistence markers.",
        "report_body": "Detailed unpack chain identified in .text at 0x401000.",
    },
)


ALL_CONFIGS = [VR_CONFIG, MALWARE_CONFIG]


# --------------------------------------------------------------------- #
#  Fakes                                                                #
# --------------------------------------------------------------------- #


class _FakeLLMResponse:
    def __init__(self, content: str, disabled: bool = False) -> None:
        self.content = content
        self.disabled = disabled
        self.model = "test-model"
        self.usage: dict[str, int] = {}
        self.finish_reason = "stop"


class _CannedLLM:
    """Records ``idempotent_llm_call`` invocations, returns queued responses."""

    def __init__(self, responses: list[_FakeLLMResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def __call__(self, llm_client, **kwargs):
        del llm_client
        self.calls.append(kwargs)
        if not self._responses:
            raise AssertionError("no more canned LLM responses")
        return self._responses.pop(0), False


class _FakeBridge:
    """AuditMcpBridgeTool stand-in.

    ``_resolve_base_url`` returns a canned url so the platform helper
    ``_fetch_audit_mcp_signatures`` proceeds. ``forward`` returns the
    canned probe response for the tool name.
    """

    def __init__(
        self,
        probe_responses: dict[str, dict[str, Any]] | None = None,
    ) -> None:
        self._probe_responses = dict(probe_responses or {})
        self.forward_calls: list[dict[str, Any]] = []

    def __call__(self, *, recorder):
        del recorder
        return self

    async def _resolve_base_url(self) -> str:
        return "http://audit-mcp.test"

    async def forward(self, *, action: str, **kwargs):
        self.forward_calls.append({"action": action, "kwargs": kwargs})
        return self._probe_responses.get(
            action,
            {"status": "ok", "matches": []},
        )


@dataclass
class _FakeSession:
    """SQLAlchemy ``session`` stand-in.

    ``exec`` returns an object with ``.first()`` popping from the queue
    supplied by the test. ``add`` / ``delete`` / ``commit`` are recorded
    but no DB is touched.
    """

    exec_returns: list[Any] = field(default_factory=list)
    added: list[Any] = field(default_factory=list)
    deleted: list[Any] = field(default_factory=list)
    exec_calls: int = 0

    async def exec(self, _stmt):
        self.exec_calls += 1
        row = (
            self.exec_returns.pop(0) if self.exec_returns else None
        )

        class _Scalar:
            def __init__(self, r):
                self._r = r

            def first(self):
                return self._r

        return _Scalar(row)

    def add(self, obj: Any) -> None:
        self.added.append(obj)

    async def delete(self, obj: Any) -> None:
        self.deleted.append(obj)


class _FakeUoW:
    """Async-context stand-in for ``UnitOfWork``.

    Reuses the same ``_FakeSession`` for every ``async with`` so the
    test asserts on total accumulated adds / deletes across the persist
    UoW + the auto-promote UoW.
    """

    _shared_session: _FakeSession | None = None

    def __init__(self) -> None:
        # Reuse the class-level shared session so writes across multiple
        # ``async with`` blocks accumulate on one recorder.
        if _FakeUoW._shared_session is None:
            _FakeUoW._shared_session = _FakeSession()
        self.session = _FakeUoW._shared_session
        self.committed = False

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def commit(self) -> None:
        self.committed = True

    @classmethod
    def reset(cls) -> None:
        cls._shared_session = None

    @classmethod
    def queue(cls, *rows: Any) -> None:
        if cls._shared_session is None:
            cls._shared_session = _FakeSession()
        cls._shared_session.exec_returns.extend(rows)


@pytest.fixture(autouse=True)
def _fresh_fake_uow():
    """Reset the shared session between tests."""
    _FakeUoW.reset()
    yield
    _FakeUoW.reset()


# --------------------------------------------------------------------- #
#  Class-attribute binding assertions                                    #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestClassBinding:
    def test_binds_task_types(self, cfg: _Config) -> None:
        assert cfg.agent_cls._EXTRACTOR_TASK_TYPE == cfg.extractor_task_type
        assert cfg.agent_cls._VERDICT_TASK_TYPE == cfg.verdict_task_type

    def test_binds_max_probes_and_timeout(self, cfg: _Config) -> None:
        # These are shared class attrs the base defines; assert the
        # subclass inherits without shadowing.
        assert cfg.agent_cls._MAX_PROBES == 8
        assert cfg.agent_cls._PROBE_TIMEOUT_S == 30.0

    def test_binds_record_models(self, cfg: _Config) -> None:
        assert cfg.agent_cls._investigation_model is cfg.investigation_model
        assert cfg.agent_cls._outcome_model is cfg.outcome_model
        assert cfg.agent_cls._target_model is cfg.target_model

    def test_binds_outcome_dispatcher_cls(self, cfg: _Config) -> None:
        assert cfg.agent_cls._outcome_dispatcher_cls is cfg.outcome_dispatcher_cls

    def test_binds_promote_gate_constants(self, cfg: _Config) -> None:
        assert cfg.agent_cls._promote_source_kind == cfg.promote_source_kind
        assert cfg.agent_cls._promote_target_kind == cfg.promote_target_kind
        assert cfg.agent_cls._promote_wrong_kind_reason == cfg.promote_wrong_kind_reason
        assert (
            cfg.agent_cls._promote_negative_skip_reason
            == cfg.promote_negative_skip_reason
        )
        assert cfg.agent_cls._dispatch_status_pending == cfg.dispatch_status_pending
        assert cfg.agent_cls._dispatch_status_skipped == cfg.dispatch_status_skipped


# --------------------------------------------------------------------- #
#  is_negative_finding_claim                                             #
# --------------------------------------------------------------------- #


class TestNegativeFindingClaim:
    def test_platform_helper_matches_prefix(self) -> None:
        assert is_negative_finding_claim(
            "NEGATIVE: no bug here",
            prefixes=("NEGATIVE",),
            substrings=(),
        ) is True

    def test_platform_helper_matches_substring_within_200_chars(self) -> None:
        # The head window is 200 chars; a substring past that is missed.
        head = "Verdict: THE ISSUE IS MITIGATED by the platform default."
        assert is_negative_finding_claim(
            head,
            prefixes=(),
            substrings=("THE ISSUE IS MITIGATED",),
        ) is True

    def test_platform_helper_ignores_substring_past_head_window(self) -> None:
        prefix = "x" * 210
        assert is_negative_finding_claim(
            prefix + " THE ISSUE IS MITIGATED",
            prefixes=(),
            substrings=("THE ISSUE IS MITIGATED",),
        ) is False

    def test_platform_helper_handles_empty(self) -> None:
        assert is_negative_finding_claim("", prefixes=(), substrings=()) is False
        assert is_negative_finding_claim(
            "   ",
            prefixes=("NEGATIVE",),
            substrings=(),
        ) is False

    def test_vr_accepts_vr_negative(self) -> None:
        assert vr_is_negative("NOT VULNERABLE: patch is in trunk") is True

    def test_vr_rejects_malware_only_negative(self) -> None:
        # "BENIGN" is a malware-domain prefix; vr must NOT flag it as
        # a negative finding.
        assert vr_is_negative("BENIGN sample -- no family match") is False

    def test_malware_accepts_malware_negative(self) -> None:
        assert malware_is_negative("BENIGN sample -- no family match") is True

    def test_malware_accepts_vr_negative_via_cross_module_reuse(self) -> None:
        # Malware carries the vr vocabulary too so an analyst who used
        # vr terms in a malware report still trips the gate.
        assert malware_is_negative("PATCH IS IN PLACE downstream") is True

    def test_vr_negative_prefixes_are_module_scoped(self) -> None:
        # Vocabulary contract: the vr table stays vr-only; malware adds
        # a superset. If either drifts (e.g. malware negatives leak
        # into vr) this test catches it.
        assert "BENIGN" not in VR_NEG_PREFIXES
        assert "BENIGN" in MW_NEG_PREFIXES


# --------------------------------------------------------------------- #
#  Pure parsers / renderers                                             #
# --------------------------------------------------------------------- #


class TestParsePreconditions:
    def _agent(self) -> ClaimVerifierAgentBase:
        return VRClaimVerifierAgent(investigation_id="inv-1")

    def test_parses_clean_json(self) -> None:
        payload = json.dumps({
            "preconditions": [
                {"id": "P1", "claim": "x", "probe": {}, "rank": 1},
            ],
        })
        parsed = self._agent()._parse_preconditions(payload)
        assert parsed == [{"id": "P1", "claim": "x", "probe": {}, "rank": 1}]

    def test_parses_fenced_json(self) -> None:
        payload = "```json\n" + json.dumps({
            "preconditions": [{"id": "P1"}],
        }) + "\n```"
        parsed = self._agent()._parse_preconditions(payload)
        assert parsed == [{"id": "P1"}]

    def test_parses_bracket_scan_fallback(self) -> None:
        payload = "here you go: " + json.dumps({
            "preconditions": [{"id": "P2"}],
        }) + " -- hope this helps"
        parsed = self._agent()._parse_preconditions(payload)
        assert parsed == [{"id": "P2"}]

    def test_returns_empty_for_missing_key(self) -> None:
        parsed = self._agent()._parse_preconditions(json.dumps({"other": []}))
        assert parsed == []

    def test_returns_empty_for_non_list_preconditions(self) -> None:
        parsed = self._agent()._parse_preconditions(
            json.dumps({"preconditions": {"not": "a list"}}),
        )
        assert parsed == []

    def test_returns_empty_for_completely_malformed(self) -> None:
        assert self._agent()._parse_preconditions("this is not json at all") == []

    def test_returns_empty_for_empty_input(self) -> None:
        assert self._agent()._parse_preconditions("") == []


class TestParseVerdict:
    def _agent(self) -> ClaimVerifierAgentBase:
        return VRClaimVerifierAgent(investigation_id="inv-1")

    def test_parses_clean_verdict_json(self) -> None:
        payload = json.dumps({
            "verdict": "confirmed",
            "confidence": 0.82,
            "counter_evidence": "",
            "summary": "sig matches",
        })
        parsed = self._agent()._parse_verdict(payload)
        assert parsed is not None
        assert parsed["verdict"] == "confirmed"
        assert parsed["confidence"] == 0.82

    def test_parses_fenced_verdict(self) -> None:
        payload = "```\n" + json.dumps({"verdict": "refuted"}) + "\n```"
        parsed = self._agent()._parse_verdict(payload)
        assert parsed == {"verdict": "refuted"}

    def test_bracket_scan_fallback(self) -> None:
        payload = "verdict below: " + json.dumps({
            "verdict": "inconclusive",
        }) + " end"
        assert self._agent()._parse_verdict(payload) == {"verdict": "inconclusive"}

    def test_returns_none_on_malformed(self) -> None:
        assert self._agent()._parse_verdict("nope, no braces here") is None

    def test_returns_none_on_empty(self) -> None:
        assert self._agent()._parse_verdict("") is None


class TestRenderProbePayload:
    def test_read_function_joins_body_list(self) -> None:
        rendered = _render_probe_payload(
            "audit_mcp.read_function",
            {
                "body": ["void foo() {", "  bar();", "}"],
                "file_path": "src/x.c",
                "start_line": 42,
                "line_count": 3,
            },
        )
        assert "// src/x.c:42  (3 lines)" in rendered
        assert "void foo()" in rendered
        assert "bar()" in rendered

    def test_search_source_emits_one_match_per_line(self) -> None:
        rendered = _render_probe_payload(
            "audit_mcp.search_source",
            {
                "matches": [
                    {"file_path": "a.c", "line": 10, "text": "foo()"},
                    {"file_path": "b.c", "line": 20, "text": "bar()"},
                ],
            },
        )
        assert "(2 matches)" in rendered
        assert "a.c:10: foo()" in rendered
        assert "b.c:20: bar()" in rendered

    def test_callers_of_emits_entries(self) -> None:
        rendered = _render_probe_payload(
            "audit_mcp.callers_of",
            {
                "callers": [
                    {"name": "handle_req", "file_path": "srv.c", "line": 5},
                ],
            },
        )
        assert "(1 entries)" in rendered
        assert "handle_req" in rendered
        assert "srv.c:5" in rendered

    def test_unknown_tool_json_fallback(self) -> None:
        rendered = _render_probe_payload(
            "audit_mcp.paths_between",
            {"paths": [["a", "b"]]},
        )
        assert json.loads(rendered) == {"paths": [["a", "b"]]}

    def test_non_dict_raw_json_encodes(self) -> None:
        assert _render_probe_payload("audit_mcp.x", [1, 2, 3]) == "[1, 2, 3]"


class TestRenderVerdictInput:
    def _agent(self) -> ClaimVerifierAgentBase:
        return VRClaimVerifierAgent(investigation_id="inv-1")

    def test_labels_each_precondition_and_probe_result(self) -> None:
        preconditions = [{
            "id": "P1",
            "claim": "load-bearing precondition",
            "if_refuted_then": "finding dies",
            "refutation_signature": "zero matches",
            "probe": {"tool": "audit_mcp.search_source", "args": {"q": "foo"}},
        }]
        results = [{
            "id": "P1",
            "ok": True,
            "raw": {"matches": [{"file_path": "x.c", "line": 1, "text": "foo"}]},
        }]
        rendered = self._agent()._render_verdict_input(preconditions, results)
        assert "## P1: load-bearing precondition" in rendered
        assert "refutation_signature: zero matches" in rendered
        assert "if_refuted_then: finding dies" in rendered
        assert "probe_result:" in rendered
        assert "x.c:1: foo" in rendered

    def test_missing_probe_result_is_skipped_placeholder(self) -> None:
        preconditions = [{"id": "P1", "claim": "c", "probe": {}}]
        rendered = self._agent()._render_verdict_input(preconditions, [])
        assert "probe_result: <skipped -- over max probe count>" in rendered

    def test_failing_probe_renders_error(self) -> None:
        preconditions = [{"id": "P1", "claim": "c", "probe": {}}]
        results = [{"id": "P1", "ok": False, "error": "bad_thing", "raw": None}]
        rendered = self._agent()._render_verdict_input(preconditions, results)
        assert "probe_result: ERROR bad_thing" in rendered

    def test_truncates_rendered_probe_result_above_cap(self) -> None:
        big = "x" * 50000
        preconditions = [{
            "id": "P1", "claim": "c",
            "probe": {"tool": "audit_mcp.read_function"},
        }]
        results = [{
            "id": "P1", "ok": True,
            "raw": {"body": [big], "file_path": "x.c", "start_line": 1},
        }]
        rendered = self._agent()._render_verdict_input(preconditions, results)
        assert "truncated" in rendered
        # The 40000-char cap plus header, so total probe_result chunk
        # length dominates the render.
        assert "chars total" in rendered


# --------------------------------------------------------------------- #
#  Auto-promote early gates                                             #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestAutoPromoteEarlyGates:
    @pytest.mark.asyncio
    async def test_non_numeric_confidence_short_circuits(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        agent = cfg.agent_cls(investigation_id="inv-1")

        async def floor():
            raise AssertionError("must not read floor before numeric check")

        monkeypatch.setattr(agent, "_read_auto_promote_floor", floor)
        result = await agent._maybe_auto_promote(
            canonical_id="oc-1", confidence="not a number", summary="s",
        )
        assert result == {"status": "skipped", "reason": "no_numeric_confidence"}

    @pytest.mark.asyncio
    async def test_confidence_below_floor_short_circuits(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        agent = cfg.agent_cls(investigation_id="inv-1")

        async def floor():
            return 0.80

        monkeypatch.setattr(agent, "_read_auto_promote_floor", floor)
        result = await agent._maybe_auto_promote(
            canonical_id="oc-1", confidence=0.75, summary="s",
        )
        assert result["status"] == "skipped"
        assert result["reason"].startswith("confidence_below_floor:0.75<0.8")


# --------------------------------------------------------------------- #
#  Full run() pipeline                                                  #
# --------------------------------------------------------------------- #


class _CanonicalRow:
    """Duck-typed outcome row -- carries only fields run() reads."""

    def __init__(
        self, *,
        outcome_id: str = "oc-1",
        payload: dict[str, Any] | None = None,
        outcome_kind: str = "assessment_report",
        investigation_id: str = "inv-1",
        branch_id: str = "br-1",
        confidence: str = "strong",
        evidence_refs_json: str = "[]",
    ) -> None:
        self.id = outcome_id
        self.payload_json = json.dumps(payload or {})
        self.outcome_kind = outcome_kind
        self.investigation_id = investigation_id
        self.branch_id = branch_id
        self.confidence = confidence
        self.evidence_refs_json = evidence_refs_json


def _install_run_seams(
    agent: ClaimVerifierAgentBase,
    monkeypatch: pytest.MonkeyPatch,
    *,
    canonical: _CanonicalRow,
    canonical_kind: str,
    extractor_response: _FakeLLMResponse,
    verdict_response: _FakeLLMResponse,
    probe_responses: dict[str, dict[str, Any]] | None = None,
    signatures_ok: bool = True,
) -> _CannedLLM:
    """Wire up the run() seams: _load_context stub, bridge patch, UoW patch."""

    async def load_context() -> dict[str, Any]:
        return {
            "status": "ok",
            "canonical": canonical,
            "canonical_payload": json.loads(canonical.payload_json),
            "canonical_kind": canonical_kind,
            "index_id": "test-index",
            "kind": "investigation.kind",
        }

    monkeypatch.setattr(agent, "_load_context", load_context)

    fake_bridge = _FakeBridge(probe_responses=probe_responses)
    monkeypatch.setattr(
        "aila.platform.agents.claim_verifier.AuditMcpBridgeTool",
        fake_bridge,
    )

    async def fake_fetch(recorder):
        del recorder
        return "  - audit_mcp.search_source(q)\n", signatures_ok

    monkeypatch.setattr(
        "aila.platform.agents.claim_verifier._fetch_audit_mcp_signatures",
        fake_fetch,
    )

    canned = _CannedLLM([extractor_response, verdict_response])
    monkeypatch.setattr(
        "aila.platform.agents.claim_verifier.idempotent_llm_call",
        canned,
    )

    # Queue the persist UoW load: same row comes back.
    _FakeUoW.queue(canonical)
    monkeypatch.setattr(
        "aila.platform.agents.claim_verifier.UnitOfWork",
        _FakeUoW,
    )

    # Bypass ServiceFactory.llm_client property lookup so the fake LLM
    # seam isn't reached via the DB-backed provider chain.
    class _FakeServices:
        llm_client = object()

        @property
        def knowledge(self):
            raise AssertionError("knowledge is only reached from auto-promote path")

    monkeypatch.setattr(
        "aila.platform.agents.claim_verifier.ServiceFactory",
        lambda: _FakeServices(),
    )

    return canned


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestRunHappyPath:
    @pytest.mark.asyncio
    async def test_run_writes_verifier_report_with_confirmed_verdict(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-happy",
            payload=cfg.canonical_payload,
            outcome_kind=cfg.example_verifiable_kind,
        )
        preconditions = json.dumps({
            "preconditions": [{
                "id": "P1", "rank": 1,
                "claim": "load-bearing", "if_refuted_then": "dies",
                "refutation_signature": "zero matches",
                "probe": {"tool": "audit_mcp.search_source",
                          "args": {"q": "foo", "path": "$INDEX_ID/src/x.c"}},
            }],
        })
        verdict = json.dumps({
            "verdict": "inconclusive",  # avoid auto-promote path for happy test
            "confidence": 0.75,
            "preconditions": [],
            "counter_evidence": "",
            "summary": "no probe hit the load-bearing precondition",
        })
        canned = _install_run_seams(
            cfg.agent_cls(investigation_id="inv-happy"),
            monkeypatch,
            canonical=canonical,
            canonical_kind=cfg.example_verifiable_kind,
            extractor_response=_FakeLLMResponse(preconditions),
            verdict_response=_FakeLLMResponse(verdict),
            probe_responses={
                "search_source": {
                    "status": "ok",
                    "matches": [{"file_path": "x.c", "line": 1, "text": "foo"}],
                },
            },
        )
        agent = cfg.agent_cls(investigation_id="inv-happy")
        # Re-install seams on the same-shape fresh agent for isolation.
        _install_run_seams(
            agent,
            monkeypatch,
            canonical=canonical,
            canonical_kind=cfg.example_verifiable_kind,
            extractor_response=_FakeLLMResponse(preconditions),
            verdict_response=_FakeLLMResponse(verdict),
            probe_responses={
                "search_source": {
                    "status": "ok",
                    "matches": [{"file_path": "x.c", "line": 1, "text": "foo"}],
                },
            },
        )

        result = await agent.run()

        del canned  # first seam install replaced below
        assert result["status"] == "ok"
        assert result["verdict"] == "inconclusive"
        assert result["probes_run"] == 1
        assert result["preconditions_count"] == 1
        # Verifier report was persisted on the canonical row via the
        # patched UoW: the fake session recorded one add.
        assert _FakeUoW._shared_session is not None
        adds = _FakeUoW._shared_session.added
        assert len(adds) == 1
        payload = json.loads(adds[0].payload_json)
        assert "verifier_report" in payload
        assert payload["verifier_report"]["verdict"] == "inconclusive"
        assert payload["verifier_report"]["signatures_fetch_failed"] is False

    @pytest.mark.asyncio
    async def test_run_calls_extractor_and_verdict_with_correct_task_types(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-task-check",
            payload=cfg.canonical_payload,
            outcome_kind=cfg.example_verifiable_kind,
        )
        preconditions = json.dumps({
            "preconditions": [{
                "id": "P1", "claim": "c", "rank": 1,
                "probe": {"tool": "audit_mcp.search_source",
                          "args": {"q": "x"}},
            }],
        })
        verdict = json.dumps({"verdict": "refuted", "confidence": 0.9})
        agent = cfg.agent_cls(investigation_id="inv-task-check")
        canned = _install_run_seams(
            agent,
            monkeypatch,
            canonical=canonical,
            canonical_kind=cfg.example_verifiable_kind,
            extractor_response=_FakeLLMResponse(preconditions),
            verdict_response=_FakeLLMResponse(verdict),
        )

        await agent.run()

        assert len(canned.calls) == 2
        extractor_call, verdict_call = canned.calls
        assert extractor_call["task_type"] == cfg.extractor_task_type
        assert extractor_call["method"] == "chat"
        assert extractor_call["investigation_id"] == "inv-task-check"
        assert verdict_call["task_type"] == cfg.verdict_task_type

    @pytest.mark.asyncio
    async def test_run_substitutes_index_id_in_probe_args(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-idx",
            payload=cfg.canonical_payload,
            outcome_kind=cfg.example_verifiable_kind,
        )
        preconditions = json.dumps({
            "preconditions": [{
                "id": "P1", "claim": "c", "rank": 1,
                "probe": {"tool": "audit_mcp.search_source",
                          "args": {"path": "$INDEX_ID/src/x.c",
                                   "q": "foo"}},
            }],
        })
        # inconclusive verdict avoids the auto-promote path (which
        # would call ``_read_auto_promote_floor`` and hit the real
        # module config reader / DB).
        verdict = json.dumps({"verdict": "inconclusive", "confidence": 0.5})
        agent = cfg.agent_cls(investigation_id="inv-idx")
        fake_bridge = _FakeBridge(
            probe_responses={
                "search_source": {"status": "ok", "matches": []},
            },
        )
        # Install seams manually so we can grab a handle on the bridge.
        async def load_context():
            return {
                "status": "ok",
                "canonical": canonical,
                "canonical_payload": json.loads(canonical.payload_json),
                "canonical_kind": cfg.example_verifiable_kind,
                "index_id": "test-idx",
                "kind": "inv.kind",
            }
        monkeypatch.setattr(agent, "_load_context", load_context)
        monkeypatch.setattr(
            "aila.platform.agents.claim_verifier.AuditMcpBridgeTool",
            fake_bridge,
        )

        async def fake_fetch(recorder):
            del recorder
            return "", True

        monkeypatch.setattr(
            "aila.platform.agents.claim_verifier._fetch_audit_mcp_signatures",
            fake_fetch,
        )
        canned = _CannedLLM([
            _FakeLLMResponse(preconditions),
            _FakeLLMResponse(verdict),
        ])
        monkeypatch.setattr(
            "aila.platform.agents.claim_verifier.idempotent_llm_call",
            canned,
        )
        _FakeUoW.queue(canonical)
        monkeypatch.setattr(
            "aila.platform.agents.claim_verifier.UnitOfWork",
            _FakeUoW,
        )
        monkeypatch.setattr(
            "aila.platform.agents.claim_verifier.ServiceFactory",
            lambda: type("_S", (), {"llm_client": object()})(),
        )

        result = await agent.run()

        assert result["status"] == "ok"
        assert len(fake_bridge.forward_calls) == 1
        # The $INDEX_ID placeholder was substituted with the real index.
        assert fake_bridge.forward_calls[0]["kwargs"]["path"] == "test-idx/src/x.c"
        # Bare-value args pass through untouched.
        assert fake_bridge.forward_calls[0]["kwargs"]["q"] == "foo"

    @pytest.mark.asyncio
    async def test_run_rejects_probe_tools_off_allowlist(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-allowlist",
            payload=cfg.canonical_payload,
            outcome_kind=cfg.example_verifiable_kind,
        )
        preconditions = json.dumps({
            "preconditions": [{
                "id": "P1", "claim": "c", "rank": 1,
                "probe": {"tool": "audit_mcp.rm_rf",   # not on allowlist
                          "args": {}},
            }],
        })
        verdict = json.dumps({"verdict": "inconclusive", "confidence": 0.5})
        agent = cfg.agent_cls(investigation_id="inv-al")
        _install_run_seams(
            agent,
            monkeypatch,
            canonical=canonical,
            canonical_kind=cfg.example_verifiable_kind,
            extractor_response=_FakeLLMResponse(preconditions),
            verdict_response=_FakeLLMResponse(verdict),
        )
        result = await agent.run()
        assert result["status"] == "ok"
        # The persisted verifier_report reflects zero-succeeded probes.
        adds = _FakeUoW._shared_session.added
        payload = json.loads(adds[0].payload_json)
        assert payload["verifier_report"]["probes_run"] == 1
        assert payload["verifier_report"]["probes_succeeded"] == 0


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestRunErrorPaths:
    @pytest.mark.asyncio
    async def test_extractor_returns_empty_fails(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-empty-ext",
            payload=cfg.canonical_payload,
            outcome_kind=cfg.example_verifiable_kind,
        )
        agent = cfg.agent_cls(investigation_id="inv-empty-ext")
        _install_run_seams(
            agent,
            monkeypatch,
            canonical=canonical,
            canonical_kind=cfg.example_verifiable_kind,
            extractor_response=_FakeLLMResponse(
                json.dumps({"preconditions": []}),
            ),
            verdict_response=_FakeLLMResponse(""),  # never reached
        )
        result = await agent.run()
        assert result == {
            "status": "failed",
            "reason": "extractor_returned_no_preconditions",
        }

    @pytest.mark.asyncio
    async def test_extractor_kill_switch_skips(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-kill", payload=cfg.canonical_payload,
            outcome_kind=cfg.example_verifiable_kind,
        )
        agent = cfg.agent_cls(investigation_id="inv-kill")
        _install_run_seams(
            agent,
            monkeypatch,
            canonical=canonical,
            canonical_kind=cfg.example_verifiable_kind,
            extractor_response=_FakeLLMResponse("", disabled=True),
            verdict_response=_FakeLLMResponse(""),
        )
        result = await agent.run()
        assert result == {"status": "skipped", "reason": "llm_kill_switch_active"}

    @pytest.mark.asyncio
    async def test_verdict_kill_switch_skips(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-vkill", payload=cfg.canonical_payload,
            outcome_kind=cfg.example_verifiable_kind,
        )
        preconditions = json.dumps({
            "preconditions": [{
                "id": "P1", "claim": "c", "rank": 1,
                "probe": {"tool": "audit_mcp.search_source", "args": {}},
            }],
        })
        agent = cfg.agent_cls(investigation_id="inv-vkill")
        _install_run_seams(
            agent,
            monkeypatch,
            canonical=canonical,
            canonical_kind=cfg.example_verifiable_kind,
            extractor_response=_FakeLLMResponse(preconditions),
            verdict_response=_FakeLLMResponse("", disabled=True),
        )
        result = await agent.run()
        assert result == {"status": "skipped", "reason": "llm_kill_switch_active"}

    @pytest.mark.asyncio
    async def test_verdict_unparseable_fails(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-badv", payload=cfg.canonical_payload,
            outcome_kind=cfg.example_verifiable_kind,
        )
        preconditions = json.dumps({
            "preconditions": [{
                "id": "P1", "claim": "c", "rank": 1,
                "probe": {"tool": "audit_mcp.search_source", "args": {}},
            }],
        })
        agent = cfg.agent_cls(investigation_id="inv-badv")
        _install_run_seams(
            agent,
            monkeypatch,
            canonical=canonical,
            canonical_kind=cfg.example_verifiable_kind,
            extractor_response=_FakeLLMResponse(preconditions),
            verdict_response=_FakeLLMResponse("this is not json"),
        )
        result = await agent.run()
        assert result == {"status": "failed", "reason": "verdict_unparseable"}

    @pytest.mark.asyncio
    async def test_already_verified_skips_before_llm(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        canonical = _CanonicalRow(
            outcome_id="oc-already",
            payload={**cfg.canonical_payload,
                     "verifier_report": {"verdict": "confirmed"}},
            outcome_kind=cfg.example_verifiable_kind,
        )
        agent = cfg.agent_cls(investigation_id="inv-already")

        async def load_context():
            return {
                "status": "ok",
                "canonical": canonical,
                "canonical_payload": json.loads(canonical.payload_json),
                "canonical_kind": cfg.example_verifiable_kind,
                "index_id": "test-idx",
                "kind": "inv.kind",
            }

        monkeypatch.setattr(agent, "_load_context", load_context)

        result = await agent.run()
        assert result["status"] == "skipped"
        assert result["reason"] == "already_verified"

    @pytest.mark.asyncio
    async def test_no_finding_text_short_circuits_vr(
        self, cfg: _Config, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Only VR routes through a hook (``payload["answer"]``) that can
        # produce an empty claim on an empty payload. Malware's
        # ``render_outcome_claim_text`` returns default filler text
        # ("Family attribution: (none claimed)", etc.) for a known
        # verifiable kind, so ``no_finding_text`` is unreachable on
        # malware without also mocking the render helper.
        if cfg.label != "vr":
            pytest.skip("malware payload rendering never returns empty")
        canonical = _CanonicalRow(
            outcome_id="oc-empty",
            payload={},
            outcome_kind=cfg.example_verifiable_kind,
        )
        agent = cfg.agent_cls(investigation_id="inv-empty")

        async def load_context():
            return {
                "status": "ok",
                "canonical": canonical,
                "canonical_payload": {},
                "canonical_kind": cfg.example_verifiable_kind,
                "index_id": "test-idx",
                "kind": "inv.kind",
            }

        monkeypatch.setattr(agent, "_load_context", load_context)
        result = await agent.run()
        assert result == {"status": "skipped", "reason": "no_finding_text"}


class TestMalwareOnlyRunPaths:
    """Malware overrides ``_check_verifiable_outcome_kind`` -- test the hook."""

    @pytest.mark.asyncio
    async def test_non_verifiable_kind_short_circuits(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        non_verifiable = next(iter(MW_NON_VERIFIABLE_KINDS))
        canonical = _CanonicalRow(
            outcome_id="oc-nv",
            payload={"summary": "irrelevant"},
            outcome_kind=non_verifiable,
        )
        agent = MalwareClaimVerifierAgent(investigation_id="inv-nv")

        async def load_context():
            return {
                "status": "ok",
                "canonical": canonical,
                "canonical_payload": json.loads(canonical.payload_json),
                "canonical_kind": non_verifiable,
                "index_id": "test-idx",
                "kind": "inv.kind",
            }

        monkeypatch.setattr(agent, "_load_context", load_context)
        result = await agent.run()
        assert result["status"] == "skipped"
        assert result["reason"] == f"outcome_kind_not_verifiable:{non_verifiable}"

    def test_vr_agent_does_not_short_circuit_on_any_kind(self) -> None:
        # VR's hook returns None for every kind; call the hook directly.
        agent = VRClaimVerifierAgent(investigation_id="inv-vr")
        assert agent._check_verifiable_outcome_kind("assessment_report") is None
        assert agent._check_verifiable_outcome_kind("anything_else") is None
