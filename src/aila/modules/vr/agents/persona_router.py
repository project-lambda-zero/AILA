"""VR persona -> LLM task_type router (RFC-03 Phase 5 thin binding).

The persona -> role table, the resolution logic, and the base class
live once in :mod:`aila.platform.agents.persona_router`. This module
binds the vr-specific task_type table: personas that share a role
share a task_type (researcher / implementer / critic).

Default role -> task_type bindings:

  researcher (halvar, noor)      -> vulnerability_research.researcher
  implementer (renzo, wei)       -> vulnerability_research.implementer
  critic (maddie, yuki)          -> vulnerability_research.critic

The task_type values resolve through the platform's existing LLM
routing config. Operators tune them via the standard config UI:
which model (Claude vs GPT-5), what temperature, what context window.
When no persona is assigned (legacy single-persona flow), routing
falls back to ``vulnerability_research.audit``.
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
    """VR-bound router: personas grouped by role, one task_type per role."""

    default_task_type: ClassVar[str] = "vulnerability_research.audit"
    role_task_type: ClassVar[dict[PersonaRole, str]] = {
        PersonaRole.RESEARCHER: "vulnerability_research.researcher",
        PersonaRole.IMPLEMENTER: "vulnerability_research.implementer",
        PersonaRole.CRITIC: "vulnerability_research.critic",
    }


# Module-level facade preserved so existing call sites
# (``vuln_researcher.py`` imports ``resolve_task_type``) keep working
# without churn. Both bindings are the classmethods on the vr subclass;
# there is no wrapper function in between.
resolve_task_type = PersonaRouter.resolve_task_type


def default_task_type() -> str:
    """Task type used when no persona is assigned."""
    return PersonaRouter.default_task_type
