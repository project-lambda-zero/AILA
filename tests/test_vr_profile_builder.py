"""M3.T-4 -- Capability profile builder tests.

Covers the pure helpers (`_mitigations_from_dict`,
`_infer_language_from_survey`) plus the rule-engine composition logic
via constructed VRTargetRecord instances + signal dicts (no DB).
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest

from aila.modules.vr.contracts.enrichment import TargetCapabilityProfile
from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.enrichment.services import (
    CapabilityProfileBuilder,
    ProfileBuilderError,  # noqa: F401 -- surfaced by StageTracker wrap; kept for reader clarity
)
from aila.modules.vr.enrichment.services.profile_builder import (
    _APPLICABLE_FUZZING_ENGINES,
    _APPLICABLE_MCP_BY_KIND,
    _DEFAULT_DISCLOSURE_TRACKS,
    _DEFAULT_PATTERN_KINDS,
    _DEFAULT_REASONING_STRATEGY,
    _infer_language_from_survey,
    _mitigations_from_dict,
)


class _FakeMcp:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        self.calls.append((action or "", kwargs))
        resp = self._responses.get(action)
        if callable(resp):
            return resp(**kwargs)
        if resp is None:
            return {"status": "error", "error": f"no stub for {action!r}"}
        return resp


def _target(kind: TargetKind, language: str | None = None) -> VRTargetRecord:
    """Build a VRTargetRecord instance for unit tests (not persisted)."""
    return VRTargetRecord(
        id=str(uuid.uuid4()),
        workspace_id="ws-1",
        team_id=None,
        display_name="t",
        kind=kind.value,
        descriptor_json="{}",
        primary_language=language,
        secondary_languages_json="[]",
        status="active",
        capability_profile_json="{}",
        tags_json="[]",
    )


class TestMitigationsFromDict:
    def test_all_bools(self) -> None:
        flags = _mitigations_from_dict(
            {"nx": True, "aslr": True, "canary": False, "cet": True, "cfi": True, "pie": True},
        )
        assert flags.nx is True
        assert flags.aslr is True
        assert flags.canary is False
        assert flags.cet is True
        assert flags.cfi is True
        assert flags.pie is True

    def test_relro_no_longer_parsed(self) -> None:
        # _mitigations_from_dict was reduced to the six boolean checksec fields;
        # relro is no longer parsed, so relro_partial/relro_full stay at their
        # None defaults regardless of the input value.
        for value in ("full", "partial", "no", "weird"):
            flags = _mitigations_from_dict({"relro": value})
            assert flags.relro_partial is None
            assert flags.relro_full is None

    def test_sanitizers_no_longer_parsed(self) -> None:
        # The sanitizers list is no longer extracted; the field keeps its default.
        flags = _mitigations_from_dict({"sanitizers": ["asan", None, 42, "ubsan"]})
        assert flags.sanitizers == []

    def test_notes_no_longer_parsed(self) -> None:
        # notes is no longer extracted; the field keeps its default.
        flags = _mitigations_from_dict({"notes": "partial CFI"})
        assert flags.notes == ""

    def test_string_bool_parsed(self) -> None:
        # String booleans are now recognized (true/1/enabled/on/yes -> True).
        assert _mitigations_from_dict({"nx": "yes"}).nx is True
        assert _mitigations_from_dict({"nx": "false"}).nx is False

    def test_unrecognized_type_silently_dropped(self) -> None:
        # A non-bool, non-string value is dropped to the None default.
        flags = _mitigations_from_dict({"nx": [1]})
        assert flags.nx is None


class TestInferLanguageFromSurvey:
    # _infer_language_from_survey was deliberately simplified: it now
    # ONLY reads explicit survey keys ('primary_language' / 'language'
    # / 'detected_language') and returns '' for everything else. The
    # older compiler-string / mangled-imports heuristics were removed
    # because they produced too many false positives on stripped and
    # LTO'd binaries; the caller now trusts IDA's own
    # `primary_language` field instead.

    def test_explicit_primary_language(self) -> None:
        assert _infer_language_from_survey({"primary_language": "rust"}) == "rust"

    def test_explicit_language_key(self) -> None:
        assert _infer_language_from_survey({"language": "go"}) == "go"

    def test_explicit_detected_language_key(self) -> None:
        assert _infer_language_from_survey({"detected_language": "c++"}) == "c++"

    def test_first_present_key_wins(self) -> None:
        # `primary_language` beats `language` beats `detected_language`.
        assert _infer_language_from_survey({
            "primary_language": "rust",
            "language": "go",
            "detected_language": "c",
        }) == "rust"

    def test_empty_string_falls_through(self) -> None:
        # An empty explicit value doesn't count as a signal.
        assert _infer_language_from_survey({
            "primary_language": "",
            "language": "kotlin",
        }) == "kotlin"

    def test_compiler_string_no_longer_inferred(self) -> None:
        # Deliberate reduction: compiler strings are no longer parsed.
        # Every one of these used to map to a language and now returns ''.
        for compiler in (
            "rustc 1.78", "go compiler 1.22", "msvc 19.36", "g++ 13",
            "clang++ 18", "gcc 12", "clang 17", "unknown",
        ):
            assert _infer_language_from_survey({"compiler": compiler}) == ""

    def test_imports_no_longer_inferred(self) -> None:
        # Deliberate reduction: mangled import names are no longer parsed.
        assert _infer_language_from_survey({"imports": ["_ZN5stdcc2fooEv"]}) == ""
        assert _infer_language_from_survey({"imports": ["runtime.rt_init"]}) == ""

    def test_empty_when_no_signal(self) -> None:
        assert _infer_language_from_survey({}) == ""

    def test_non_dict_survey(self) -> None:
        # Guarded: bad input never raises, just returns ''.
        assert _infer_language_from_survey(None) == ""
        assert _infer_language_from_survey("junk") == ""


class TestRuleTables:
    def test_every_target_kind_has_mcp_entry(self) -> None:
        for kind in TargetKind:
            assert kind.value in _APPLICABLE_MCP_BY_KIND, f"missing MCP mapping for {kind.value}"

    def test_every_target_kind_has_disclosure_tracks(self) -> None:
        for kind in TargetKind:
            assert kind.value in _DEFAULT_DISCLOSURE_TRACKS, (
                f"missing disclosure tracks for {kind.value}"
            )

    def test_default_pattern_kinds_match_d43(self) -> None:
        # GA-41 defined 5 kinds
        assert set(_DEFAULT_PATTERN_KINDS) == {
            "exploitation_technique",
            "fuzzing_strategy",
            "search_heuristic",
            "tool_recipe",
            "triage_rule",
        }

    def test_source_repo_engine_coverage(self) -> None:
        # Every reasonable source-repo language should have at least one fuzzer
        for lang in ("c", "c++", "rust", "go", "java", "kotlin", "python", "javascript"):
            engines = _APPLICABLE_FUZZING_ENGINES.get(
                (TargetKind.SOURCE_REPO.value, lang)
            )
            assert engines, f"no fuzzing engines for source_repo / {lang}"

    def test_wildcard_reasoning_strategy_for_cve(self) -> None:
        assert (TargetKind.CVE.value, "*") in _DEFAULT_REASONING_STRATEGY

    def test_v04_audit_only_languages_have_empty_fuzz_engines(self) -> None:
        # PHP + Ruby are audit-only -- explicit empty entry means we
        # surface 'no fuzz engines' rather than falling through to
        # an unrelated default.
        for lang in ("php", "ruby"):
            key = (TargetKind.SOURCE_REPO.value, lang)
            assert key in _APPLICABLE_FUZZING_ENGINES
            assert _APPLICABLE_FUZZING_ENGINES[key] == []

    def test_v04_swift_has_libfuzzer_swift(self) -> None:
        assert _APPLICABLE_FUZZING_ENGINES.get(
            (TargetKind.SOURCE_REPO.value, "swift"),
        ) == ["libfuzzer-swift"]
        assert _APPLICABLE_FUZZING_ENGINES.get(
            (TargetKind.IPA.value, "swift"),
        ) == ["libfuzzer-swift"]

    def test_v04_android_native_libs_get_libfuzzer_android(self) -> None:
        for lang in ("c", "c++"):
            assert _APPLICABLE_FUZZING_ENGINES.get(
                (TargetKind.ANDROID_APK.value, lang),
            ) == ["libfuzzer-android"]

    def test_v04_dotnet_uses_sharpfuzz(self) -> None:
        for lang in ("c#", "f#"):
            assert _APPLICABLE_FUZZING_ENGINES.get(
                (TargetKind.DOTNET_ASSEMBLY.value, lang),
            ) == ["sharpfuzz"]

    def test_v04_audit_only_strategy_for_php_ruby_python(self) -> None:
        for lang in ("php", "ruby", "python", "java", "kotlin"):
            assert _DEFAULT_REASONING_STRATEGY.get(
                (TargetKind.SOURCE_REPO.value, lang),
            ) == "vulnerability_research.source_audit"

    def test_v04_wildcard_strategies_for_mobile_and_dotnet(self) -> None:
        for kind in (
            TargetKind.ANDROID_APK, TargetKind.IPA, TargetKind.DOTNET_ASSEMBLY,
        ):
            assert _DEFAULT_REASONING_STRATEGY.get(
                (kind.value, "*"),
            ) == "vulnerability_research.discovery_research"


class TestComposeProfile:
    def test_v8_binary_gets_fuzzilli(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        target = _target(TargetKind.NATIVE_BINARY, "javascript")
        signals = {"primary_language": "javascript", "mitigations": {"nx": True}}
        profile = builder._compose_profile(target, signals)
        assert "fuzzilli_v8" in profile.applicable_fuzzing_engines
        assert "fuzzilli" in profile.applicable_strategies
        assert "v8MapInference" in profile.applicable_strategies
        assert "differential" in profile.applicable_strategies
        assert profile.mitigations.nx is True
        assert "ida_headless" in profile.applicable_mcp_servers
        assert "audit_mcp" in profile.applicable_mcp_servers

    def test_source_rust_repo(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        target = _target(TargetKind.SOURCE_REPO)
        signals = {"primary_language": "rust"}
        profile = builder._compose_profile(target, signals)
        assert "cargo-fuzz" in profile.applicable_fuzzing_engines
        assert profile.primary_language == "rust"
        assert "audit_mcp" in profile.applicable_mcp_servers
        assert "ida_headless" not in profile.applicable_mcp_servers
        # rust source repo defaults to GitHub Security Advisory + vendor + blog
        assert "cna_github_gsa" in profile.default_disclosure_tracks

    def test_cve_uses_variant_hunt_strategy(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        target = _target(TargetKind.CVE)
        profile = builder._compose_profile(target, {})
        assert profile.default_reasoning_strategy == "vulnerability_research.variant_hunt"

    def test_patch_diff_uses_patch_strategy(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        target = _target(TargetKind.PATCH_DIFF)
        profile = builder._compose_profile(target, {})
        assert profile.default_reasoning_strategy == "vulnerability_research.patch_diff_analysis"

    def test_unknown_language_yields_empty_engines(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        target = _target(TargetKind.NATIVE_BINARY)
        signals = {"primary_language": "ada"}
        profile = builder._compose_profile(target, signals)
        assert profile.applicable_fuzzing_engines == []
        # Still gets a default reasoning strategy (discovery)
        assert profile.default_reasoning_strategy == "vulnerability_research.discovery_research"
        # Cost baseline still set
        assert profile.estimated_cost_per_investigation_usd > 0

    def test_apk_target(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        target = _target(TargetKind.ANDROID_APK, "kotlin")
        profile = builder._compose_profile(target, {"primary_language": "kotlin"})
        assert "jazzer" in profile.applicable_fuzzing_engines
        # ANDROID_APK now routes through both android_mcp (APK-level
        # facets) and audit_mcp (source-graph over jadx-decompiled
        # Java). See _APPLICABLE_MCP_BY_KIND in profile_builder.py.
        assert profile.applicable_mcp_servers == ["android_mcp", "audit_mcp"]

    def test_profile_round_trips(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        target = _target(TargetKind.NATIVE_BINARY, "c")
        profile = builder._compose_profile(target, {"primary_language": "c"})
        dumped = profile.model_dump(mode="json")
        restored = TargetCapabilityProfile.model_validate(dumped)
        assert restored == profile


class TestBuilderErrorPaths:
    async def test_target_not_found_raises(self, test_db) -> None:
        # build() now enters StageTracker before hitting the builder's
        # own _load(), so the missing-target error surfaces as
        # StageTrackerError ("target <id> not found") rather than the
        # legacy ProfileBuilderError. See:
        #   src/aila/modules/vr/services/stage_tracker.py::StageTracker.__aenter__
        #   src/aila/modules/vr/enrichment/services/profile_builder.py::build
        # The _load() ProfileBuilderError branch is now unreachable dead
        # code; noted in the migration report.
        del test_db  # fixture activates the aila_test PostgreSQL engine
        from aila.modules.vr.services.stage_tracker import StageTrackerError

        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        with pytest.raises(StageTrackerError, match="not found"):
            await builder.build(str(uuid.uuid4()))
