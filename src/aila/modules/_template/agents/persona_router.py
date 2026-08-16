"""Template persona -> LLM task_type router.

Thin subclass of :class:`aila.platform.agents.persona_router.PersonaRouter`.
The template ships the vr-shaped role-based routing table but scoped to
the ``template.*`` namespace so operator LLM routing overrides don't
collide with a live module. Copiers replace both the ``persona_role_map``
and the ``role_task_type`` values with the module's real voices and
task-type keys (or delete the map and switch to ``persona_task_type``
for per-voice routing).
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.agents.persona_router import PersonaRole
from aila.platform.agents.persona_router import (
    PersonaRouter as _PlatformPersonaRouter,
)
from aila.platform.contracts.enums import PersonaVoice

__all__ = [
    "PersonaRole",
    "PersonaRouter",
    "default_task_type",
    "resolve_task_type",
]


class PersonaRouter(_PlatformPersonaRouter):
    """Template-bound router: persona -> role -> task_type.

    The ``persona_role_map`` and ``role_task_type`` below are the
    two hooks copiers replace when scaffolding a new module. The
    six D-39 / GA-52 voices are the current platform enum set;
    copiers may retain them, swap in domain-specific voices, or
    drop the map and populate ``persona_task_type`` instead.
    """

    default_task_type: ClassVar[str] = "template.audit"
    persona_role_map: ClassVar[dict[PersonaVoice, PersonaRole]] = {
        PersonaVoice.HALVAR: PersonaRole.RESEARCHER,
        PersonaVoice.NOOR: PersonaRole.RESEARCHER,
        PersonaVoice.RENZO: PersonaRole.IMPLEMENTER,
        PersonaVoice.WEI: PersonaRole.IMPLEMENTER,
        PersonaVoice.MADDIE: PersonaRole.CRITIC,
        PersonaVoice.YUKI: PersonaRole.CRITIC,
    }
    role_task_type: ClassVar[dict[PersonaRole, str]] = {
        PersonaRole.RESEARCHER: "template.researcher",
        PersonaRole.IMPLEMENTER: "template.implementer",
        PersonaRole.CRITIC: "template.critic",
    }


resolve_task_type = PersonaRouter.resolve_task_type


def default_task_type() -> str:
    """Task type used when no persona is assigned."""
    return PersonaRouter.default_task_type
