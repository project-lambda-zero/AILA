"""Unit tests for persona_router (v0.4 GA-52)."""
from __future__ import annotations

import pytest

from aila.modules.vr.agents.persona_router import (
    PersonaRole,
    default_task_type,
    persona_to_role,
    resolve_task_type,
)
from aila.modules.vr.contracts import PersonaVoice


class TestPersonaToRole:
    @pytest.mark.parametrize("persona,expected_role", [
        (PersonaVoice.HALVAR, PersonaRole.RESEARCHER),
        (PersonaVoice.NOOR, PersonaRole.RESEARCHER),
        (PersonaVoice.RENZO, PersonaRole.IMPLEMENTER),
        (PersonaVoice.WEI, PersonaRole.IMPLEMENTER),
        (PersonaVoice.MADDIE, PersonaRole.CRITIC),
        (PersonaVoice.YUKI, PersonaRole.CRITIC),
    ])
    def test_known_persona(
        self, persona: PersonaVoice, expected_role: PersonaRole,
    ) -> None:
        assert persona_to_role(persona) == expected_role

    def test_string_persona(self) -> None:
        assert persona_to_role("halvar") == PersonaRole.RESEARCHER
        assert persona_to_role("renzo") == PersonaRole.IMPLEMENTER

    def test_unknown_string_returns_none(self) -> None:
        assert persona_to_role("not-a-persona") is None

    def test_none_returns_none(self) -> None:
        assert persona_to_role(None) is None


class TestResolveTaskType:
    def test_no_persona_falls_back_to_default(self) -> None:
        assert resolve_task_type(None) == "vulnerability_research.audit"

    def test_unknown_string_falls_back_to_default(self) -> None:
        assert resolve_task_type("nobody") == "vulnerability_research.audit"

    def test_researcher_personas_route_to_researcher_task_type(self) -> None:
        assert (
            resolve_task_type(PersonaVoice.HALVAR)
            == "vulnerability_research.researcher"
        )
        assert (
            resolve_task_type(PersonaVoice.NOOR)
            == "vulnerability_research.researcher"
        )

    def test_implementer_personas_route_to_implementer_task_type(self) -> None:
        assert (
            resolve_task_type(PersonaVoice.RENZO)
            == "vulnerability_research.implementer"
        )
        assert (
            resolve_task_type(PersonaVoice.WEI)
            == "vulnerability_research.implementer"
        )

    def test_critic_personas_route_to_critic_task_type(self) -> None:
        assert (
            resolve_task_type(PersonaVoice.MADDIE)
            == "vulnerability_research.critic"
        )
        assert (
            resolve_task_type(PersonaVoice.YUKI)
            == "vulnerability_research.critic"
        )


class TestDefaultTaskType:
    def test_default(self) -> None:
        assert default_task_type() == "vulnerability_research.audit"


class TestAllPersonasCovered:
    """Every PersonaVoice must map to a role — no silent fallthrough."""

    def test_no_persona_without_role(self) -> None:
        for persona in PersonaVoice:
            role = persona_to_role(persona)
            assert role is not None, f"PersonaVoice.{persona.name} has no role"

    def test_every_role_has_task_type(self) -> None:
        for role in PersonaRole:
            tt = next(
                (resolve_task_type(p) for p in PersonaVoice if persona_to_role(p) == role),
                None,
            )
            assert tt is not None
            assert tt.startswith("vulnerability_research.")
            assert role.value in tt
