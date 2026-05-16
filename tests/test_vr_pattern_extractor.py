"""PatternExtractor unit tests — pure helpers + the entry-to-create converter.

The full DB round-trip (load outcome → load transcript → call LLM → persist
patterns) is exercised by integration tests once the test fixtures stand
up an investigation. Here we cover the deterministic pieces.
"""
from __future__ import annotations

import json
from dataclasses import dataclass

import pytest

from aila.modules.vr.agents.pattern_extractor import (
    PatternExtractor,
    PatternExtractorError,
    _entry_to_create,
)
from aila.modules.vr.contracts import (
    OutcomeKind,
    PatternConfidence,
    PatternKind,
    PatternScope,
)


class TestShouldExtract:
    @pytest.mark.parametrize("kind", [
        OutcomeKind.DIRECT_FINDING,
        OutcomeKind.AUDIT_MEMO,
        OutcomeKind.CRASH_TRIAGE_REPORT,
        OutcomeKind.PROFILE_SPEC_DRAFT,
        OutcomeKind.STRATEGY_DESCRIPTOR,
        OutcomeKind.PATCH_ASSESSMENT_REPORT,
    ])
    def test_extractable_kinds(self, kind: OutcomeKind) -> None:
        assert PatternExtractor.should_extract(kind) is True

    @pytest.mark.parametrize("kind", [
        OutcomeKind.ASSESSMENT_REPORT,      # low-signal self-aborts
        OutcomeKind.VARIANT_HUNT_ORDER,     # child investigation extracts
        OutcomeKind.SUB_INVESTIGATION,
        OutcomeKind.CONFIG_DELTA,
        OutcomeKind.CAMPAIGN_LAUNCH,
    ])
    def test_non_extractable_kinds(self, kind: OutcomeKind) -> None:
        assert PatternExtractor.should_extract(kind) is False


class TestEntryToCreate:
    def test_full_valid_entry(self) -> None:
        entry = {
            "kind": "exploitation_technique",
            "summary": "V8 type confusion via aliased descriptors",
            "body": "Pass aliased descriptors after warmup; triggers JIT confusion.",
            "applicability": {
                "target_kinds": ["native_binary"],
                "languages": ["javascript"],
                "bug_classes": ["type_confusion"],
            },
            "confidence": "strong",
            "evidence_refs": ["msg-1", "outcome-2"],
        }
        create = _entry_to_create(
            entry, workspace_id="ws-1", investigation_id="inv-1",
        )
        assert create.kind == PatternKind.EXPLOITATION_TECHNIQUE
        assert create.confidence == PatternConfidence.STRONG
        assert create.summary.startswith("V8 type confusion")
        assert create.workspace_id == "ws-1"
        assert create.investigation_id == "inv-1"
        assert create.scope == PatternScope.LOCAL
        assert create.evidence_refs == ["msg-1", "outcome-2"]
        assert create.applicability["bug_classes"] == ["type_confusion"]

    def test_missing_summary_raises(self) -> None:
        with pytest.raises(ValueError, match="summary or body missing"):
            _entry_to_create(
                {
                    "kind": "exploitation_technique",
                    "summary": "   ",
                    "body": "non-empty body",
                    "confidence": "strong",
                },
                workspace_id="w", investigation_id="i",
            )

    def test_missing_body_raises(self) -> None:
        with pytest.raises(ValueError, match="summary or body missing"):
            _entry_to_create(
                {
                    "kind": "exploitation_technique",
                    "summary": "non-empty summary",
                    "body": "",
                    "confidence": "strong",
                },
                workspace_id="w", investigation_id="i",
            )

    def test_unknown_kind_raises(self) -> None:
        with pytest.raises(ValueError):
            _entry_to_create(
                {
                    "kind": "not_a_real_kind",
                    "summary": "x",
                    "body": "y",
                    "confidence": "strong",
                },
                workspace_id="w", investigation_id="i",
            )

    def test_unknown_confidence_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown confidence"):
            _entry_to_create(
                {
                    "kind": "exploitation_technique",
                    "summary": "x",
                    "body": "y",
                    "confidence": "very-certain",
                },
                workspace_id="w", investigation_id="i",
            )

    def test_missing_confidence_defaults_to_medium(self) -> None:
        create = _entry_to_create(
            {
                "kind": "tool_recipe",
                "summary": "x",
                "body": "y",
            },
            workspace_id="w", investigation_id="i",
        )
        assert create.confidence == PatternConfidence.MEDIUM

    def test_summary_truncated_to_512(self) -> None:
        long_summary = "x" * 1000
        create = _entry_to_create(
            {
                "kind": "search_heuristic",
                "summary": long_summary,
                "body": "y",
                "confidence": "medium",
            },
            workspace_id="w", investigation_id="i",
        )
        assert len(create.summary) == 512

    def test_invalid_applicability_type_normalised_to_empty(self) -> None:
        create = _entry_to_create(
            {
                "kind": "search_heuristic",
                "summary": "x",
                "body": "y",
                "applicability": "not a dict",
                "confidence": "medium",
            },
            workspace_id="w", investigation_id="i",
        )
        assert create.applicability == {}

    def test_invalid_evidence_refs_type_normalised_to_empty(self) -> None:
        create = _entry_to_create(
            {
                "kind": "search_heuristic",
                "summary": "x",
                "body": "y",
                "evidence_refs": "not-a-list",
                "confidence": "medium",
            },
            workspace_id="w", investigation_id="i",
        )
        assert create.evidence_refs == []


class _FakeLLMResponse:
    def __init__(self, content: str, disabled: bool = False) -> None:
        self.content = content
        self.disabled = disabled


class _FakeLLM:
    def __init__(self, response: _FakeLLMResponse) -> None:
        self.calls: list[dict] = []
        self._response = response

    async def chat_json(self, **kwargs) -> _FakeLLMResponse:
        self.calls.append(kwargs)
        return self._response


class _FakeStore:
    def __init__(self) -> None:
        self.created: list = []

    async def create(self, body, team_id):  # type: ignore[no-untyped-def]
        from aila.modules.vr.contracts import VRPatternSummary  # noqa: PLC0415
        summary = VRPatternSummary(
            id=f"pat-{len(self.created) + 1}",
            workspace_id=body.workspace_id,
            investigation_id=body.investigation_id,
            kind=body.kind,
            summary=body.summary,
            body=body.body,
            applicability=body.applicability,
            confidence=body.confidence,
            evidence_refs=body.evidence_refs,
            status="draft",  # type: ignore[arg-type]
            scope=body.scope,
            superseded_by=None,
            knowledge_entry_id=None,
            times_retrieved=0,
        )
        self.created.append(body)
        return summary


class TestExtractorMalformedLLMResponse:
    @pytest.mark.asyncio
    async def test_non_json_response_raises(self) -> None:
        extractor = PatternExtractor(
            llm_client=_FakeLLM(_FakeLLMResponse("not json at all")),
            pattern_store=_FakeStore(),  # type: ignore[arg-type]
        )
        # Patch _load to skip DB
        async def fake_load(_id: str):

            @dataclass
            class _O:
                outcome_kind: str = OutcomeKind.DIRECT_FINDING.value
                confidence: str = "strong"
                payload_json: str = "{}"

            @dataclass
            class _I:
                id: str = "inv-x"
                team_id: str | None = "team-x"

            @dataclass
            class _T:
                id: str = "tgt-x"
                workspace_id: str = "ws-x"

            return _O(), _I(), _T()

        async def fake_transcript(_id: str) -> str:
            return "msg content"

        extractor._load = fake_load  # type: ignore[method-assign]
        extractor._load_transcript = fake_transcript  # type: ignore[method-assign]

        with pytest.raises(PatternExtractorError, match="non-JSON"):
            await extractor.extract("oc-1", team_id="team-x")

    @pytest.mark.asyncio
    async def test_non_list_response_raises(self) -> None:
        # patterns key missing → not a list
        extractor = PatternExtractor(
            llm_client=_FakeLLM(_FakeLLMResponse(json.dumps({"wrong_key": []}))),
            pattern_store=_FakeStore(),  # type: ignore[arg-type]
        )

        @dataclass
        class _O:
            outcome_kind: str = OutcomeKind.DIRECT_FINDING.value
            confidence: str = "strong"
            payload_json: str = "{}"

        @dataclass
        class _I:
            id: str = "inv-x"
            team_id: str | None = "team-x"

        @dataclass
        class _T:
            id: str = "tgt-x"
            workspace_id: str = "ws-x"

        async def fake_load(_id: str):
            return _O(), _I(), _T()

        async def fake_transcript(_id: str) -> str:
            return "msg content"

        extractor._load = fake_load  # type: ignore[method-assign]
        extractor._load_transcript = fake_transcript  # type: ignore[method-assign]

        with pytest.raises(PatternExtractorError, match="not a pattern list"):
            await extractor.extract("oc-2", team_id="team-x")


class TestExtractorSkipsNonExtractableKinds:
    @pytest.mark.asyncio
    async def test_assessment_report_returns_skipped(self) -> None:
        fake_llm = _FakeLLM(_FakeLLMResponse(json.dumps({"patterns": []})))
        extractor = PatternExtractor(
            llm_client=fake_llm,
            pattern_store=_FakeStore(),  # type: ignore[arg-type]
        )

        @dataclass
        class _O:
            outcome_kind: str = OutcomeKind.ASSESSMENT_REPORT.value
            confidence: str = "medium"
            payload_json: str = "{}"

        @dataclass
        class _I:
            id: str = "inv-x"
            team_id: str | None = "team-x"

        @dataclass
        class _T:
            id: str = "tgt-x"
            workspace_id: str = "ws-x"

        async def fake_load(_id: str):
            return _O(), _I(), _T()

        extractor._load = fake_load  # type: ignore[method-assign]

        result = await extractor.extract("oc-skip", team_id="team-x")
        assert result.extracted_count == 0
        assert "not_extractable" in result.skipped_reason
        # LLM never called for non-extractable kinds
        assert len(fake_llm.calls) == 0


class TestExtractorHappyPath:
    @pytest.mark.asyncio
    async def test_persists_extracted_patterns(self) -> None:
        llm_response = json.dumps({
            "patterns": [
                {
                    "kind": "exploitation_technique",
                    "summary": "V8 alias check missing on InferMaps",
                    "body": "When InferMaps is reached without alias check, TurboFan misses the type confusion.",
                    "applicability": {
                        "target_kinds": ["native_binary"],
                        "languages": ["javascript"],
                        "bug_classes": ["type_confusion"],
                    },
                    "confidence": "strong",
                    "evidence_refs": ["msg-1"],
                },
                {
                    "kind": "search_heuristic",
                    "summary": "grep InferMaps callsites without alias precondition",
                    "body": "Use audit-mcp search_functions InferMaps then audit each callsite for alias-checking pattern.",
                    "applicability": {},
                    "confidence": "medium",
                    "evidence_refs": ["msg-3"],
                },
            ],
        })
        store = _FakeStore()
        fake_llm = _FakeLLM(_FakeLLMResponse(llm_response))
        extractor = PatternExtractor(
            llm_client=fake_llm,
            pattern_store=store,  # type: ignore[arg-type]
        )


        @dataclass
        class _O:
            outcome_kind: str = OutcomeKind.DIRECT_FINDING.value
            confidence: str = "strong"
            payload_json: str = '{"vulnerable_function":"InferMaps"}'

        @dataclass
        class _I:
            id: str = "inv-x"
            team_id: str | None = "team-x"

        @dataclass
        class _T:
            id: str = "tgt-x"
            workspace_id: str = "ws-x"

        async def fake_load(_id: str):
            return _O(), _I(), _T()

        async def fake_transcript(_id: str) -> str:
            return "msg-1: hypothesis...\nmsg-3: search result..."

        extractor._load = fake_load  # type: ignore[method-assign]
        extractor._load_transcript = fake_transcript  # type: ignore[method-assign]

        result = await extractor.extract("oc-happy", team_id="team-x")
        assert result.extracted_count == 2
        assert len(store.created) == 2
        kinds = [c.kind for c in store.created]
        assert PatternKind.EXPLOITATION_TECHNIQUE in kinds
        assert PatternKind.SEARCH_HEURISTIC in kinds
        for c in store.created:
            assert c.investigation_id == "inv-x"
            assert c.workspace_id == "ws-x"
            assert c.scope == PatternScope.LOCAL

    @pytest.mark.asyncio
    async def test_empty_pattern_list_returns_zero_count(self) -> None:
        fake_llm = _FakeLLM(_FakeLLMResponse(json.dumps({"patterns": []})))
        store = _FakeStore()
        extractor = PatternExtractor(
            llm_client=fake_llm,
            pattern_store=store,  # type: ignore[arg-type]
        )

        @dataclass
        class _O:
            outcome_kind: str = OutcomeKind.AUDIT_MEMO.value
            confidence: str = "medium"
            payload_json: str = "{}"

        @dataclass
        class _I:
            id: str = "inv-x"
            team_id: str | None = "team-x"

        @dataclass
        class _T:
            id: str = "tgt-x"
            workspace_id: str = "ws-x"

        async def fake_load(_id: str):
            return _O(), _I(), _T()

        async def fake_transcript(_id: str) -> str:
            return "no patterns here"

        extractor._load = fake_load  # type: ignore[method-assign]
        extractor._load_transcript = fake_transcript  # type: ignore[method-assign]

        result = await extractor.extract("oc-empty", team_id="team-x")
        assert result.extracted_count == 0
        assert result.skipped_reason == ""
        assert len(store.created) == 0
