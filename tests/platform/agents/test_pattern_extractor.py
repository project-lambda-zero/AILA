"""Characterization tests for the platform PatternExtractor (RFC-03 Phase 5).

Exercises the extraction logic for BOTH module configs (vr + malware) so
the pre-extraction behavior is preserved. Every LLM call is mocked; the
DB round-trip is patched via ``_load`` / ``_load_transcript`` so no
migrations or infra are required.

Coverage:
  * ``should_extract`` accepts each module's extractable OutcomeKind
    set (and rejects the non-extractable ones).
  * ``_entry_to_create`` builds the module-specific PatternCreate row
    with the correct enum types, workspace_id / investigation_id
    plumbing, ``PatternScope.LOCAL`` scope, summary truncation, and the
    defensive normalisation of malformed applicability / evidence_refs.
  * ``_extraction_schema`` reflects the module's PatternKind +
    PatternConfidence enums (LLM never sees a value the module has no
    definition for).
  * The happy-path ``extract`` persists each LLM-emitted pattern via the
    store and returns the persisted ids in the result.
  * The empty-list, non-JSON, wrong-shape, non-extractable, and
    kill-switch skip paths return the expected ``PatternExtractionResult``
    without crashing.

The test parametrises on a small ``_Config`` struct so both modules run
through the identical assertion set -- any drift between the vr and
malware subclass classes would immediately break one variant.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from aila.modules.malware.agents.pattern_extractor import (
    PatternExtractor as MalwarePatternExtractor,
)
from aila.modules.malware.contracts.outcome import OutcomeKind as MalwareOutcomeKind
from aila.modules.malware.contracts.pattern import (
    MalwarePatternCreate,
)
from aila.modules.malware.contracts.pattern import (
    PatternConfidence as MalwarePatternConfidence,
)
from aila.modules.malware.contracts.pattern import (
    PatternKind as MalwarePatternKind,
)
from aila.modules.malware.contracts.pattern import (
    PatternScope as MalwarePatternScope,
)
from aila.modules.vr.agents.pattern_extractor import (
    PatternExtractor as VRPatternExtractor,
)
from aila.modules.vr.contracts.outcome import OutcomeKind as VROutcomeKind
from aila.modules.vr.contracts.pattern import (
    PatternConfidence as VRPatternConfidence,
)
from aila.modules.vr.contracts.pattern import (
    PatternKind as VRPatternKind,
)
from aila.modules.vr.contracts.pattern import (
    PatternScope as VRPatternScope,
)
from aila.modules.vr.contracts.pattern import (
    VRPatternCreate,
)
from aila.platform.agents.pattern_extractor import (
    PatternExtractionResult,
    PatternExtractorBase,
    PatternExtractorError,
)


@dataclass(frozen=True)
class _Config:
    """One module's binding + a per-module example entry.

    ``example_entry`` is a dict shaped exactly like what the LLM emits
    for that module (uses a real PatternKind value from the module's
    enum). ``expected_kind`` is the parsed enum after
    ``_entry_to_create`` runs.
    """

    label: str
    extractor_cls: type[PatternExtractorBase]
    outcome_kind_enum: type[Any]
    pattern_kind_enum: type[Any]
    pattern_confidence_enum: type[Any]
    pattern_scope_enum: type[Any]
    pattern_create_cls: type[Any]
    task_type: str
    extractable_kinds: frozenset[Any]
    non_extractable_kind: Any
    example_entry: dict[str, Any]
    expected_kind: Any


VR_CONFIG = _Config(
    label="vr",
    extractor_cls=VRPatternExtractor,
    outcome_kind_enum=VROutcomeKind,
    pattern_kind_enum=VRPatternKind,
    pattern_confidence_enum=VRPatternConfidence,
    pattern_scope_enum=VRPatternScope,
    pattern_create_cls=VRPatternCreate,
    task_type="vulnerability_research.pattern_extraction",
    extractable_kinds=frozenset({
        VROutcomeKind.DIRECT_FINDING,
        VROutcomeKind.AUDIT_MEMO,
        VROutcomeKind.CRASH_TRIAGE_REPORT,
        VROutcomeKind.PROFILE_SPEC_DRAFT,
        VROutcomeKind.STRATEGY_DESCRIPTOR,
        VROutcomeKind.PATCH_ASSESSMENT_REPORT,
    }),
    non_extractable_kind=VROutcomeKind.ASSESSMENT_REPORT,
    example_entry={
        "kind": "exploitation_technique",
        "summary": "V8 alias check missing on InferMaps",
        "body": "When InferMaps runs without alias check, TurboFan misses the confusion.",
        "applicability": {
            "target_kinds": ["native_binary"],
            "languages": ["javascript"],
            "bug_classes": ["type_confusion"],
        },
        "confidence": "strong",
        "evidence_refs": ["msg-1", "outcome-2"],
    },
    expected_kind=VRPatternKind.EXPLOITATION_TECHNIQUE,
)

MALWARE_CONFIG = _Config(
    label="malware",
    extractor_cls=MalwarePatternExtractor,
    outcome_kind_enum=MalwareOutcomeKind,
    pattern_kind_enum=MalwarePatternKind,
    pattern_confidence_enum=MalwarePatternConfidence,
    pattern_scope_enum=MalwarePatternScope,
    pattern_create_cls=MalwarePatternCreate,
    task_type="malware_analysis.pattern_extraction",
    extractable_kinds=frozenset({
        MalwareOutcomeKind.ANALYSIS_REPORT,
        MalwareOutcomeKind.CONFIG_EXTRACTOR_SCRIPT,
        MalwareOutcomeKind.YARA_RULE,
        MalwareOutcomeKind.TRIAGE_VERDICT,
        MalwareOutcomeKind.FAMILY_VERDICT_OUTCOME,
    }),
    non_extractable_kind=MalwareOutcomeKind.STALLED_REPORT,
    example_entry={
        "kind": "yara_template",
        "summary": "Emotet 32-byte XOR-decoder prologue signature",
        "body": "Family YARA template keyed on the 32-byte XOR-decoder prologue.",
        "applicability": {
            "target_kinds": ["pe_sample"],
            "families": ["emotet"],
            "capabilities": ["string_xor_decoder"],
        },
        "confidence": "strong",
        "evidence_refs": ["obs-1", "outcome-2"],
    },
    expected_kind=MalwarePatternKind.YARA_TEMPLATE,
)


ALL_CONFIGS = [VR_CONFIG, MALWARE_CONFIG]


class _FakeLLMResponse:
    def __init__(self, content: str, disabled: bool = False) -> None:
        self.content = content
        self.disabled = disabled
        self.model = "test-model"
        self.usage: dict[str, int] = {}
        self.finish_reason = "stop"


class _FakeLLM:
    def __init__(self, response: _FakeLLMResponse) -> None:
        self.calls: list[dict[str, Any]] = []
        self._response = response

    async def chat_json(self, task_type, messages, schema, **kwargs) -> _FakeLLMResponse:
        self.calls.append({
            "task_type": task_type,
            "messages": messages,
            "schema": schema,
            **kwargs,
        })
        return self._response


@pytest.fixture(autouse=True)
def _bypass_idempotent_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bypass the RFC-03 Phase 2 idempotency wrapper.

    The real ``idempotent_llm_call`` opens a UnitOfWork for the cache
    lookup, which needs the ``aila_test`` Postgres fixture. These
    characterization tests target the extraction logic, not the
    wrapper -- the wrapper has its own coverage in
    ``tests/platform/llm/``. The shim just calls ``chat_json`` with
    the same kwargs the wrapper would forward and returns
    ``(response, False)`` to mimic a cache miss.
    """

    async def _bypass(llm_client, *, method, task_type, messages, **kwargs):
        assert method == "chat_json", (
            f"pattern_extractor always calls chat_json; got {method}"
        )
        schema = kwargs.get("schema")
        resp = await llm_client.chat_json(
            task_type, messages, schema,
            run_id=kwargs.get("run_id"),
            team_id=kwargs.get("team_id"),
        )
        return resp, False

    monkeypatch.setattr(
        "aila.platform.agents.pattern_extractor.idempotent_llm_call",
        _bypass,
    )


class _FakePatternSummary:
    """Duck-typed drop-in for the module's PatternSummary contract.

    Only ``id`` is read downstream (``persisted.append(summary.id)``),
    so the test doesn't need to build a full Pydantic row for each
    module.
    """

    def __init__(self, sid: str) -> None:
        self.id = sid


class _FakeStore:
    def __init__(self) -> None:
        self.created: list[Any] = []

    async def create(self, body: Any, team_id: str | None) -> _FakePatternSummary:
        self.created.append(body)
        return _FakePatternSummary(f"pat-{len(self.created)}")


class _Outcome:
    """Duck-typed outcome row -- carries only the fields extract() reads."""

    def __init__(self, kind: Any, payload_json: str = "{}") -> None:
        self.outcome_kind = kind.value if hasattr(kind, "value") else kind
        self.confidence = "strong"
        self.payload_json = payload_json


class _Investigation:
    def __init__(self, iid: str = "inv-x") -> None:
        self.id = iid


class _Target:
    def __init__(self, workspace_id: str = "ws-x") -> None:
        self.workspace_id = workspace_id


def _install_fakes(
    extractor: PatternExtractorBase,
    outcome_kind: Any,
    transcript: str = "msg-1: hypothesis...\nmsg-3: search result...",
) -> None:
    outcome = _Outcome(outcome_kind, payload_json='{"vulnerable_function":"InferMaps"}')
    inv = _Investigation()
    tgt = _Target()

    async def fake_load(_oid: str) -> tuple[_Outcome, _Investigation, _Target]:
        return outcome, inv, tgt

    async def fake_transcript(_iid: str) -> str:
        return transcript

    async def fake_skip_event(**_kwargs) -> None:
        return None

    extractor._load = fake_load  # type: ignore[method-assign]
    extractor._load_transcript = fake_transcript  # type: ignore[method-assign]
    extractor._emit_skip_event = fake_skip_event  # type: ignore[method-assign]


# --------------------------------------------------------------------- #
#  Config-class-level assertions (no infra)                             #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestClassBinding:
    def test_binds_expected_task_type(self, cfg: _Config) -> None:
        assert cfg.extractor_cls._task_type == cfg.task_type

    def test_binds_extractable_kinds_set(self, cfg: _Config) -> None:
        assert cfg.extractor_cls._extraction_outcome_kinds == cfg.extractable_kinds

    def test_binds_outcome_kind_enum(self, cfg: _Config) -> None:
        assert cfg.extractor_cls._outcome_kind_enum is cfg.outcome_kind_enum

    def test_binds_pattern_enums(self, cfg: _Config) -> None:
        assert cfg.extractor_cls._pattern_kind_enum is cfg.pattern_kind_enum
        assert cfg.extractor_cls._pattern_confidence_enum is cfg.pattern_confidence_enum
        assert cfg.extractor_cls._pattern_scope_enum is cfg.pattern_scope_enum

    def test_binds_pattern_create_cls(self, cfg: _Config) -> None:
        assert cfg.extractor_cls._pattern_create_cls is cfg.pattern_create_cls

    def test_prompt_path_resolves_to_module_local_file(self, cfg: _Config) -> None:
        # The prompt template lives next to each module's thin subclass
        # -- resolving with ``Path(__file__).parent / "prompts"`` at
        # class-attribute time.
        assert cfg.extractor_cls._prompt_path.exists()
        assert cfg.extractor_cls._prompt_path.name == "pattern_extraction.md"


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestShouldExtract:
    def test_extractable_kinds_pass(self, cfg: _Config) -> None:
        for kind in cfg.extractable_kinds:
            assert cfg.extractor_cls.should_extract(kind) is True

    def test_non_extractable_kind_rejected(self, cfg: _Config) -> None:
        assert cfg.extractor_cls.should_extract(cfg.non_extractable_kind) is False


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestEntryToCreate:
    def test_full_valid_entry_builds_module_create(self, cfg: _Config) -> None:
        create = cfg.extractor_cls._entry_to_create(
            cfg.example_entry,
            workspace_id="ws-1",
            investigation_id="inv-1",
        )
        assert isinstance(create, cfg.pattern_create_cls)
        assert create.kind == cfg.expected_kind
        assert create.confidence == cfg.pattern_confidence_enum("strong")
        assert create.workspace_id == "ws-1"
        assert create.investigation_id == "inv-1"
        assert create.scope == cfg.pattern_scope_enum.LOCAL
        assert create.summary == cfg.example_entry["summary"]
        assert create.body == cfg.example_entry["body"]
        assert create.evidence_refs == [
            str(r) for r in cfg.example_entry["evidence_refs"]
        ]
        assert create.applicability == cfg.example_entry["applicability"]

    def test_missing_summary_raises(self, cfg: _Config) -> None:
        entry = dict(cfg.example_entry)
        entry["summary"] = "   "
        with pytest.raises(ValueError, match="summary or body missing"):
            cfg.extractor_cls._entry_to_create(
                entry, workspace_id="w", investigation_id="i",
            )

    def test_missing_body_raises(self, cfg: _Config) -> None:
        entry = dict(cfg.example_entry)
        entry["body"] = ""
        with pytest.raises(ValueError, match="summary or body missing"):
            cfg.extractor_cls._entry_to_create(
                entry, workspace_id="w", investigation_id="i",
            )

    def test_unknown_kind_raises(self, cfg: _Config) -> None:
        entry = dict(cfg.example_entry)
        entry["kind"] = "not_a_real_kind_for_this_module"
        with pytest.raises(ValueError):
            cfg.extractor_cls._entry_to_create(
                entry, workspace_id="w", investigation_id="i",
            )

    def test_unknown_confidence_raises(self, cfg: _Config) -> None:
        entry = dict(cfg.example_entry)
        entry["confidence"] = "very-certain"
        with pytest.raises(ValueError, match="unknown confidence"):
            cfg.extractor_cls._entry_to_create(
                entry, workspace_id="w", investigation_id="i",
            )

    def test_missing_confidence_defaults_to_medium(self, cfg: _Config) -> None:
        entry = dict(cfg.example_entry)
        entry.pop("confidence")
        create = cfg.extractor_cls._entry_to_create(
            entry, workspace_id="w", investigation_id="i",
        )
        assert create.confidence == cfg.pattern_confidence_enum.MEDIUM

    def test_summary_truncated_to_512(self, cfg: _Config) -> None:
        entry = dict(cfg.example_entry)
        entry["summary"] = "x" * 1000
        create = cfg.extractor_cls._entry_to_create(
            entry, workspace_id="w", investigation_id="i",
        )
        assert len(create.summary) == 512

    def test_invalid_applicability_type_normalised_to_empty(self, cfg: _Config) -> None:
        entry = dict(cfg.example_entry)
        entry["applicability"] = "not a dict"
        create = cfg.extractor_cls._entry_to_create(
            entry, workspace_id="w", investigation_id="i",
        )
        assert create.applicability == {}

    def test_invalid_evidence_refs_type_normalised_to_empty(self, cfg: _Config) -> None:
        entry = dict(cfg.example_entry)
        entry["evidence_refs"] = "not-a-list"
        create = cfg.extractor_cls._entry_to_create(
            entry, workspace_id="w", investigation_id="i",
        )
        assert create.evidence_refs == []


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestExtractionSchema:
    def test_schema_lists_module_pattern_kinds(self, cfg: _Config) -> None:
        schema = cfg.extractor_cls._extraction_schema()
        item = schema["properties"]["patterns"]["items"]
        assert set(item["properties"]["kind"]["enum"]) == {
            k.value for k in cfg.pattern_kind_enum
        }

    def test_schema_lists_module_confidences(self, cfg: _Config) -> None:
        schema = cfg.extractor_cls._extraction_schema()
        item = schema["properties"]["patterns"]["items"]
        assert set(item["properties"]["confidence"]["enum"]) == {
            c.value for c in cfg.pattern_confidence_enum
        }

    def test_schema_strict_mode_shape(self, cfg: _Config) -> None:
        schema = cfg.extractor_cls._extraction_schema()
        # Top-level object gate for OpenAI strict mode.
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert schema["required"] == ["patterns"]
        item = schema["properties"]["patterns"]["items"]
        assert item["additionalProperties"] is False
        assert set(item["required"]) == {
            "kind",
            "summary",
            "body",
            "applicability",
            "confidence",
            "evidence_refs",
        }


# --------------------------------------------------------------------- #
#  extract() paths -- happy path + every skip/error branch              #
# --------------------------------------------------------------------- #


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestExtractHappyPath:
    @pytest.mark.asyncio
    async def test_persists_extracted_patterns(self, cfg: _Config) -> None:
        llm_response = json.dumps({"patterns": [cfg.example_entry]})
        fake_llm = _FakeLLM(_FakeLLMResponse(llm_response))
        store = _FakeStore()
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=store,
        )
        # Use one of the module's extractable kinds so should_extract passes.
        extractable_kind = next(iter(cfg.extractable_kinds))
        _install_fakes(extractor, extractable_kind)

        result = await extractor.extract("oc-happy", team_id="team-x")

        assert isinstance(result, PatternExtractionResult)
        assert result.extracted_count == 1
        assert result.pattern_ids == ["pat-1"]
        assert result.skipped_reason == ""
        assert result.investigation_id == "inv-x"
        # Persisted body is the module's PatternCreate with vr/malware
        # enums; applicability / workspace_id / scope wired through
        # from the fake target row.
        assert len(store.created) == 1
        created = store.created[0]
        assert isinstance(created, cfg.pattern_create_cls)
        assert created.workspace_id == "ws-x"
        assert created.investigation_id == "inv-x"
        assert created.kind == cfg.expected_kind
        assert created.scope == cfg.pattern_scope_enum.LOCAL

    @pytest.mark.asyncio
    async def test_llm_gets_module_task_type_and_schema(self, cfg: _Config) -> None:
        fake_llm = _FakeLLM(_FakeLLMResponse(json.dumps({"patterns": []})))
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=_FakeStore(),
        )
        _install_fakes(extractor, next(iter(cfg.extractable_kinds)))

        await extractor.extract("oc-task", team_id="team-x")

        assert len(fake_llm.calls) == 1
        call = fake_llm.calls[0]
        assert call["task_type"] == cfg.task_type
        # Schema enum list is the module's PatternKind set -- proves the
        # per-module binding reaches the LLM strict-mode gate.
        kind_enum = call["schema"]["properties"]["patterns"]["items"][
            "properties"
        ]["kind"]["enum"]
        assert set(kind_enum) == {k.value for k in cfg.pattern_kind_enum}

    @pytest.mark.asyncio
    async def test_empty_pattern_list_returns_zero_count(self, cfg: _Config) -> None:
        fake_llm = _FakeLLM(_FakeLLMResponse(json.dumps({"patterns": []})))
        store = _FakeStore()
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=store,
        )
        _install_fakes(extractor, next(iter(cfg.extractable_kinds)))

        result = await extractor.extract("oc-empty", team_id="team-x")

        assert result.extracted_count == 0
        assert result.pattern_ids == []
        assert result.skipped_reason == ""
        assert store.created == []

    @pytest.mark.asyncio
    async def test_malformed_entry_dropped_but_others_persist(
        self, cfg: _Config,
    ) -> None:
        # First entry is malformed (missing body); second is valid.
        malformed = dict(cfg.example_entry)
        malformed["body"] = ""
        llm_response = json.dumps({
            "patterns": [malformed, cfg.example_entry],
        })
        fake_llm = _FakeLLM(_FakeLLMResponse(llm_response))
        store = _FakeStore()
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=store,
        )
        _install_fakes(extractor, next(iter(cfg.extractable_kinds)))

        result = await extractor.extract("oc-mixed", team_id="team-x")

        assert result.extracted_count == 1
        assert len(store.created) == 1


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestExtractSkipPaths:
    @pytest.mark.asyncio
    async def test_non_extractable_kind_skipped_without_llm_call(
        self, cfg: _Config,
    ) -> None:
        fake_llm = _FakeLLM(_FakeLLMResponse(json.dumps({"patterns": []})))
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=_FakeStore(),
        )
        _install_fakes(extractor, cfg.non_extractable_kind)

        result = await extractor.extract("oc-skip", team_id="team-x")

        assert result.extracted_count == 0
        assert "not_extractable" in result.skipped_reason
        # LLM never invoked when should_extract rejects the kind.
        assert fake_llm.calls == []

    @pytest.mark.asyncio
    async def test_empty_transcript_skipped_without_llm_call(
        self, cfg: _Config,
    ) -> None:
        fake_llm = _FakeLLM(_FakeLLMResponse(json.dumps({"patterns": []})))
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=_FakeStore(),
        )
        _install_fakes(
            extractor,
            next(iter(cfg.extractable_kinds)),
            transcript="   \n\t  ",
        )

        result = await extractor.extract("oc-empty-tx", team_id="team-x")

        assert result.extracted_count == 0
        assert result.skipped_reason == "empty_transcript"
        assert fake_llm.calls == []

    @pytest.mark.asyncio
    async def test_kill_switch_disabled_response_returns_llm_disabled(
        self, cfg: _Config,
    ) -> None:
        disabled = _FakeLLMResponse("", disabled=True)
        fake_llm = _FakeLLM(disabled)
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=_FakeStore(),
        )
        _install_fakes(extractor, next(iter(cfg.extractable_kinds)))

        result = await extractor.extract("oc-kill", team_id="team-x")

        assert result.extracted_count == 0
        assert result.skipped_reason == "llm_disabled"


@pytest.mark.parametrize("cfg", ALL_CONFIGS, ids=[c.label for c in ALL_CONFIGS])
class TestExtractErrorPaths:
    @pytest.mark.asyncio
    async def test_non_json_response_raises(self, cfg: _Config) -> None:
        fake_llm = _FakeLLM(_FakeLLMResponse("not json at all"))
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=_FakeStore(),
        )
        _install_fakes(extractor, next(iter(cfg.extractable_kinds)))

        with pytest.raises(PatternExtractorError, match="non-JSON"):
            await extractor.extract("oc-bad-json", team_id="team-x")

    @pytest.mark.asyncio
    async def test_non_list_response_raises(self, cfg: _Config) -> None:
        # ``patterns`` key missing -> parsed.get("patterns") is None.
        fake_llm = _FakeLLM(
            _FakeLLMResponse(json.dumps({"wrong_key": []})),
        )
        extractor = cfg.extractor_cls(
            llm_client=fake_llm, pattern_store=_FakeStore(),
        )
        _install_fakes(extractor, next(iter(cfg.extractable_kinds)))

        with pytest.raises(PatternExtractorError, match="not a pattern list"):
            await extractor.extract("oc-not-list", team_id="team-x")
