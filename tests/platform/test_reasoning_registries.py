"""RFC-05 (d): module-declared reasoning strategy/domain registries.

The platform seeds only the ``generic`` strategy; every domain-specific
strategy family and domain profile is module-owned and registered at load.
resolve_domain_profile reads the DomainProfileRegistry and keeps its
graceful generic fallback for unregistered domains.
"""
from __future__ import annotations

import pytest

from aila.modules.forensics.module import ForensicsModule
from aila.modules.vr.module import VRModule
from aila.platform.contracts.reasoning import (
    ReasoningDomainProfile,
    ReasoningStrategyDeclaration,
)
from aila.platform.services.reasoning import (
    CyberReasoningEngine,
    DomainProfileRegistry,
    StrategyRegistry,
    UnknownStrategyError,
    register_reasoning_domain_profile,
    reset_reasoning_registries,
)


class TestStrategyRegistry:
    def test_seeds_generic(self) -> None:
        reg = StrategyRegistry()
        assert reg.is_registered("generic")
        assert reg.resolve("generic").family == "generic"

    def test_register_then_resolve(self) -> None:
        reg = StrategyRegistry()
        reg.register(ReasoningStrategyDeclaration(family="foo", task_type="foo"))
        assert reg.resolve("foo").family == "foo"

    def test_unknown_family_raises(self) -> None:
        reg = StrategyRegistry()
        with pytest.raises(UnknownStrategyError):
            reg.resolve("does_not_exist")

    def test_clear_reseeds_generic_only(self) -> None:
        reg = StrategyRegistry()
        reg.register(ReasoningStrategyDeclaration(family="foo", task_type="foo"))
        reg.clear()
        assert reg.is_registered("generic")
        assert not reg.is_registered("foo")


class TestDomainProfileRegistry:
    def test_register_then_resolve(self) -> None:
        reg = DomainProfileRegistry()
        reg.register(
            ReasoningDomainProfile(domain_id="d", task_type="d", default_strategy="generic"),
        )
        assert reg.resolve("d") is not None
        assert reg.resolve("d").domain_id == "d"

    def test_unknown_domain_resolves_none(self) -> None:
        reg = DomainProfileRegistry()
        assert reg.resolve("missing") is None


class TestModuleDeclarations:
    def test_vr_declares_its_families_and_profiles(self) -> None:
        families = {d.family for d in VRModule().reasoning_strategies()}
        assert families == {"vulnerability_research", "web_pentest", "mobile_reverse"}
        domains = {p.domain_id for p in VRModule().reasoning_domain_profiles()}
        assert domains == {"vulnerability_research", "web_pentest", "mobile_reverse"}

    def test_forensics_declares_its_families_and_profile(self) -> None:
        families = {d.family for d in ForensicsModule().reasoning_strategies()}
        assert families == {
            "filesystem_triage",
            "persistence_hunt",
            "memory_forensics",
            "network_forensics",
            "malware_static",
        }
        domains = {p.domain_id for p in ForensicsModule().reasoning_domain_profiles()}
        assert domains == {"forensics"}


class TestResolveDomainProfile:
    """resolve_domain_profile reads the platform DomainProfileRegistry and
    preserves the legacy profile values + the generic fallback."""

    def teardown_method(self) -> None:
        reset_reasoning_registries()

    @staticmethod
    def _engine() -> CyberReasoningEngine:
        # resolve_domain_profile never touches the llm client; a bare stub
        # is enough and config_registry defaults to None (no override).
        return CyberReasoningEngine(llm_client=object())

    def test_registered_vr_profile_matches_legacy(self) -> None:
        reset_reasoning_registries()
        for profile in VRModule().reasoning_domain_profiles():
            register_reasoning_domain_profile(profile)
        resolved = self._engine().resolve_domain_profile("vulnerability_research")
        assert resolved.task_type == "vulnerability_research"
        assert resolved.default_strategy == "vulnerability_research"
        assert resolved.allowed_strategies == ["vulnerability_research", "generic"]

    def test_registered_forensics_profile_matches_legacy(self) -> None:
        reset_reasoning_registries()
        for profile in ForensicsModule().reasoning_domain_profiles():
            register_reasoning_domain_profile(profile)
        resolved = self._engine().resolve_domain_profile("forensics")
        assert resolved.task_type == "forensics_freeflow"
        assert resolved.default_strategy == "filesystem_triage"

    def test_unregistered_domain_falls_back_to_generic(self) -> None:
        reset_reasoning_registries()
        resolved = self._engine().resolve_domain_profile("brand_new_domain")
        assert resolved.default_strategy == "generic"
        assert resolved.allowed_strategies == ["generic"]
