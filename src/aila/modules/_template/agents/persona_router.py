"""Template persona -> LLM task_type router.

Thin subclass of :class:`aila.platform.agents.persona_router.PersonaRouter`.
The template ships the vr-shaped role -> task_type table but scoped to
the ``template.*`` namespace so operator LLM routing overrides don't
collide with a live module. Copiers replace these values with the
module's real task-type keys.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.agents.persona_router import (
    PersonaRole,
    persona_to_role,
)
from aila.platform.agents.persona_router import (
    PersonaRouter as _PlatformPersonaRouter,
)

__all__ = [
    "PersonaRole",
    "PersonaRouter",
    "default_task_type",
    "persona_to_role",
    "resolve_task_type",
]


class PersonaRouter(_PlatformPersonaRouter):
    """Template-bound router: persona -> role -> task_type."""

    default_task_type: ClassVar[str] = "template.audit"
    role_task_type: ClassVar[dict[PersonaRole, str]] = {
        PersonaRole.RESEARCHER: "template.researcher",
        PersonaRole.IMPLEMENTER: "template.implementer",
        PersonaRole.CRITIC: "template.critic",
    }


resolve_task_type = PersonaRouter.resolve_task_type


def default_task_type() -> str:
    """Task type used when no persona is assigned."""
    return PersonaRouter.default_task_type
