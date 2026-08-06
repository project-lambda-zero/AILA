"""Characterization tests for the extracted persona router (RFC-03 Phase 5).

These tests pin the pre-extraction behavior of the two duplicated
copies (``modules/vr/agents/persona_router.py`` and
``modules/malware/agents/persona_router.py``) so the platform lift
cannot regress either module's routing.

The two shapes covered:

* vr -- personas sharing a role share a task_type
  (:attr:`PersonaRouter.role_task_type`).
* malware -- each persona voice carries its own task_type
  (:attr:`PersonaRouter.persona_task_type`).

The shared table (persona -> role) and resolution logic live once in
:mod:`aila.platform.agents.persona_router`.
"""
from __future__ import annotations

import pytest

from aila.modules.malware.agents.persona_router import (
    PersonaRouter as MalwarePersonaRouter,
)
from aila.modules.malware.agents.persona_router import (
    default_task_type as malware_default_task_type,
)
from aila.modules.malware.agents.persona_router import (
    resolve_task_type as malware_resolve,
)
from aila.modules.vr.agents.persona_router import (
    PersonaRouter as VRPersonaRouter,
)
from aila.modules.vr.agents.persona_router import (
    default_task_type as vr_default_task_type,
)
from aila.modules.vr.agents.persona_router import (
    resolve_task_type as vr_resolve,
)
from aila.platform.agents.persona_router import (
    PERSONA_ROLE_MAP,
    PersonaRole,
    PersonaRouter,
    persona_to_role,
)
from aila.platform.contracts.enums import PersonaVoice

# Synthetic voices added after v0.4 GA-52 (unspecified / merge_result /
# fork_unnamed) are structural markers written by branch_manager when
# no agent persona is meaningful -- they intentionally have no role,
# because no LLM call is dispatched under them.
_SYNTHETIC_VOICES: frozenset[PersonaVoice] = frozenset({
    PersonaVoice.UNSPECIFIED,
    PersonaVoice.MERGE_RESULT,
    PersonaVoice.FORK_UNNAMED,
})


class TestSharedPersonaRoleMap:
    """The persona -> role table is byte-identical across both modules."""

    @pytest.mark.parametrize("persona,expected_role", [
        (PersonaVoice.HALVAR, PersonaRole.RESEARCHER),
        (PersonaVoice.NOOR, PersonaRole.RESEARCHER),
        (PersonaVoice.RENZO, PersonaRole.IMPLEMENTER),
        (PersonaVoice.WEI, PersonaRole.IMPLEMENTER),
        (PersonaVoice.MADDIE, PersonaRole.CRITIC),
        (PersonaVoice.YUKI, PersonaRole.CRITIC),
    ])
    def test_known_persona_maps_to_role(
        self, persona: PersonaVoice, expected_role: PersonaRole,
    ) -> None:
        assert persona_to_role(persona) == expected_role
        assert PERSONA_ROLE_MAP[persona] == expected_role

    def test_string_persona_accepted(self) -> None:
        assert persona_to_role("halvar") == PersonaRole.RESEARCHER
        assert persona_to_role("maddie") == PersonaRole.CRITIC

    def test_unknown_string_returns_none(self) -> None:
        assert persona_to_role("not-a-persona") is None

    def test_none_returns_none(self) -> None:
        assert persona_to_role(None) is None

    def test_synthetic_voices_have_no_role(self) -> None:
        for voice in _SYNTHETIC_VOICES:
            assert persona_to_role(voice) is None


class TestVRPersonaRouter:
    """VR: role-based routing (personas sharing a role share a task_type)."""

    def test_no_persona_returns_default(self) -> None:
        assert (
            VRPersonaRouter.resolve_task_type(None)
            == "vulnerability_research.audit"
        )

    def test_unknown_string_returns_default(self) -> None:
        assert (
            VRPersonaRouter.resolve_task_type("nobody")
            == "vulnerability_research.audit"
        )

    def test_synthetic_voice_returns_default(self) -> None:
        assert (
            VRPersonaRouter.resolve_task_type(PersonaVoice.UNSPECIFIED)
            == "vulnerability_research.audit"
        )

    @pytest.mark.parametrize("persona,expected", [
        (PersonaVoice.HALVAR, "vulnerability_research.researcher"),
        (PersonaVoice.NOOR, "vulnerability_research.researcher"),
        (PersonaVoice.RENZO, "vulnerability_research.implementer"),
        (PersonaVoice.WEI, "vulnerability_research.implementer"),
        (PersonaVoice.MADDIE, "vulnerability_research.critic"),
        (PersonaVoice.YUKI, "vulnerability_research.critic"),
    ])
    def test_representative_persona_resolution(
        self, persona: PersonaVoice, expected: str,
    ) -> None:
        assert VRPersonaRouter.resolve_task_type(persona) == expected

    def test_string_persona_resolves_through_role(self) -> None:
        assert (
            VRPersonaRouter.resolve_task_type("halvar")
            == "vulnerability_research.researcher"
        )

    def test_subclass_uses_role_table_not_persona_table(self) -> None:
        # Guard against a regression where the vr subclass would
        # accidentally populate persona_task_type (which would win
        # over the role table).
        assert VRPersonaRouter.persona_task_type == {}
        assert VRPersonaRouter.role_task_type


class TestMalwarePersonaRouter:
    """Malware: per-persona routing (each voice picks its own task_type)."""

    def test_no_persona_returns_default(self) -> None:
        assert (
            MalwarePersonaRouter.resolve_task_type(None)
            == "malware_analysis.panel"
        )

    def test_unknown_string_returns_default(self) -> None:
        assert (
            MalwarePersonaRouter.resolve_task_type("nobody")
            == "malware_analysis.panel"
        )

    def test_synthetic_voice_returns_default(self) -> None:
        assert (
            MalwarePersonaRouter.resolve_task_type(PersonaVoice.UNSPECIFIED)
            == "malware_analysis.panel"
        )

    @pytest.mark.parametrize("persona,expected", [
        (PersonaVoice.HALVAR, "malware_analysis.halvar"),
        (PersonaVoice.NOOR, "malware_analysis.noor"),
        (PersonaVoice.RENZO, "malware_analysis.renzo"),
        (PersonaVoice.WEI, "malware_analysis.wei"),
        (PersonaVoice.MADDIE, "malware_analysis.maddie"),
        (PersonaVoice.YUKI, "malware_analysis.yuki"),
    ])
    def test_representative_persona_resolution(
        self, persona: PersonaVoice, expected: str,
    ) -> None:
        assert MalwarePersonaRouter.resolve_task_type(persona) == expected

    def test_string_persona_resolves_directly(self) -> None:
        assert (
            MalwarePersonaRouter.resolve_task_type("renzo")
            == "malware_analysis.renzo"
        )

    def test_persona_table_wins_over_role_table(self) -> None:
        # The malware subclass populates persona_task_type; the base
        # role_task_type stays empty so the persona lookup path is
        # exercised (see PersonaRouter.resolve_task_type precedence).
        assert MalwarePersonaRouter.persona_task_type
        assert MalwarePersonaRouter.role_task_type == {}


class TestModuleLevelFacade:
    """The pre-extraction module-level names remain importable."""

    def test_vr_module_level_resolve_task_type(self) -> None:
        assert vr_resolve(PersonaVoice.HALVAR) == "vulnerability_research.researcher"
        assert vr_resolve(None) == "vulnerability_research.audit"

    def test_malware_module_level_resolve_task_type(self) -> None:
        assert malware_resolve(PersonaVoice.HALVAR) == "malware_analysis.halvar"
        assert malware_resolve(None) == "malware_analysis.panel"

    def test_vr_module_level_default_task_type(self) -> None:
        assert vr_default_task_type() == "vulnerability_research.audit"

    def test_malware_module_level_default_task_type(self) -> None:
        assert malware_default_task_type() == "malware_analysis.panel"


class TestPlatformBaseRequiresSubclass:
    """The base class must not be usable without subclass configuration."""

    def test_base_class_lacks_default_task_type(self) -> None:
        # ClassVar declared without a value; the base is not directly
        # usable, subclasses must set default_task_type.
        with pytest.raises(AttributeError):
            _ = PersonaRouter.default_task_type
