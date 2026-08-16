"""VR persona -> LLM task_type router (RFC-03 Phase 5 thin binding).

The persona -> role table, the resolution logic, and the base class
live once in :mod:`aila.platform.agents.persona_router`. This module
binds the vr-specific ``persona_role_map`` (the six D-39 / GA-52
persona voices grouped into researcher / implementer / critic roles)
and the vr-specific ``role_task_type`` table (personas sharing a role
share a task_type).

Default persona -> role bindings (issue #136 -- module-supplied
vocabulary; the platform base ships an empty map):

  halvar, noor           -> researcher
  renzo,  wei            -> implementer
  maddie, yuki           -> critic

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
    """VR-bound router: personas grouped by role, one task_type per role.

    The persona -> role map (:attr:`persona_role_map`) is VR domain
    vocabulary. Migrated out of the platform base under issue #136 so
    the platform reasoning layer never carries module-specific names.
    """

    default_task_type: ClassVar[str] = "vulnerability_research.audit"
    persona_role_map: ClassVar[dict[PersonaVoice, PersonaRole]] = {
        # Tuned by D-39 + GA-52:
        #   halvar = deliberate, considers fundamentals -> researcher
        #   noor   = unconventional angles -> researcher
        #   renzo  = builds PoCs + scripts -> implementer
        #   wei    = systems engineer mindset -> implementer
        #   maddie = adversarial, picks holes -> critic
        #   yuki   = methodical verifier -> critic
        PersonaVoice.HALVAR: PersonaRole.RESEARCHER,
        PersonaVoice.NOOR: PersonaRole.RESEARCHER,
        PersonaVoice.RENZO: PersonaRole.IMPLEMENTER,
        PersonaVoice.WEI: PersonaRole.IMPLEMENTER,
        PersonaVoice.MADDIE: PersonaRole.CRITIC,
        PersonaVoice.YUKI: PersonaRole.CRITIC,
    }
    role_task_type: ClassVar[dict[PersonaRole, str]] = {
        PersonaRole.RESEARCHER: "vulnerability_research.researcher",
        PersonaRole.IMPLEMENTER: "vulnerability_research.implementer",
        PersonaRole.CRITIC: "vulnerability_research.critic",
    }


# Module-level facade preserved so existing call sites
# (``vuln_researcher.py`` imports ``resolve_task_type``) keep working
# without churn. The binding IS the classmethod on the vr subclass;
# there is no wrapper function in between.
resolve_task_type = PersonaRouter.resolve_task_type


def default_task_type() -> str:
    """Task type used when no persona is assigned."""
    return PersonaRouter.default_task_type
