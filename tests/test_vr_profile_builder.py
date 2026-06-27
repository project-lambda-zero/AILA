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
    ProfileBuilderError,
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

    def test_relro_full(self) -> None:
        flags = _mitigations_from_dict({"relro": "full"})
        assert flags.relro_partial is True
        assert flags.relro_full is True

    def test_relro_partial(self) -> None:
        flags = _mitigations_from_dict({"relro": "partial"})
        assert flags.relro_partial is True
        assert flags.relro_full is False

    def test_relro_no(self) -> None:
        flags = _mitigations_from_dict({"relro": "no"})
        assert flags.relro_partial is False
        assert flags.relro_full is False

    def test_relro_unknown_silent(self) -> None:
        flags = _mitigations_from_dict({"relro": "weird"})
        assert flags.relro_partial is None
        assert flags.relro_full is None

    def test_sanitizers_list_filter(self) -> None:
        flags = _mitigations_from_dict({"sanitizers": ["asan", None, 42, "ubsan"]})
        assert flags.sanitizers == ["asan", "ubsan"]

    def test_notes(self) -> None:
        flags = _mitigations_from_dict({"notes": "partial CFI"})
        assert flags.notes == "partial CFI"

    def test_wrong_type_silently_dropped(self) -> None:
        flags = _mitigations_from_dict({"nx": "yes"})
        assert flags.nx is None


class TestInferLanguageFromSurvey:
    def test_rust_compiler(self) -> None:
        assert _infer_language_from_survey({"compiler": "rustc 1.78"}) == "rust"

    def test_go_compiler(self) -> None:
        assert _infer_language_from_survey({"compiler": "go compiler 1.22"}) == "go"

    def test_cxx_compiler(self) -> None:
        assert _infer_language_from_survey({"compiler": "msvc 19.36"}) == "c++"
        assert _infer_language_from_survey({"compiler": "g++ 13"}) == "c++"
        assert _infer_language_from_survey({"compiler": "clang++ 18"}) == "c++"

    def test_c_compiler(self) -> None:
        assert _infer_language_from_survey({"compiler": "gcc 12"}) == "c"
        assert _infer_language_from_survey({"compiler": "clang 17"}) == "c"

    def test_cxx_via_mangled_imports(self) -> None:
        assert _infer_language_from_survey({"imports": ["_ZN5stdcc2fooEv"]}) == "c++"

    def test_go_via_imports(self) -> None:
        assert _infer_language_from_survey({"imports": ["runtime.rt_init"]}) == "go"

    def test_empty_when_no_signal(self) -> None:
        assert _infer_language_from_survey({}) == ""
        assert _infer_language_from_survey({"compiler": "unknown"}) == ""


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
                (TargetKind.APK.value, lang),
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
        for kind in (TargetKind.APK, TargetKind.IPA, TargetKind.DOTNET_ASSEMBLY):
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
        target = _target(TargetKind.APK, "kotlin")
        profile = builder._compose_profile(target, {"primary_language": "kotlin"})
        assert "jazzer" in profile.applicable_fuzzing_engines
        assert profile.applicable_mcp_servers == ["ida_headless"]

    def test_profile_round_trips(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        target = _target(TargetKind.NATIVE_BINARY, "c")
        profile = builder._compose_profile(target, {"primary_language": "c"})
        dumped = profile.model_dump(mode="json")
        restored = TargetCapabilityProfile.model_validate(dumped)
        assert restored == profile


class TestBuilderErrorPaths:
    @pytest.mark.asyncio
    async def test_target_not_found_raises(self) -> None:
        builder = CapabilityProfileBuilder(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        with pytest.raises(ProfileBuilderError):
            await builder.build(str(uuid.uuid4()))
