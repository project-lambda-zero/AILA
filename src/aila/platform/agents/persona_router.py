"""Platform persona router (RFC-03 Phase 5).

Per-module persona -> LLM ``task_type`` router. Extracted from the
byte-identical vr and malware copies of ``persona_router.py``.

Each strategy branch can carry a :class:`PersonaVoice`. The platform's
LLM client uses ``task_type`` per call to resolve routing (model,
temperature, max_tokens, retry policy). Modules subclass
:class:`PersonaRouter` and set two class attributes:

* ``default_task_type`` -- fallback returned when the persona is
  ``None`` or absent from the module's table (legacy single-persona
  / setup flow).
* Either ``role_task_type`` (role -> task_type, when personas that
  share a role share a task_type -- the vr shape) or
  ``persona_task_type`` (persona -> task_type, when each voice
  carries its own model + budget tuning -- the malware shape).

The persona -> role mapping is domain-agnostic and shared: it lives
here as :data:`PERSONA_ROLE_MAP` and is exposed through
:func:`persona_to_role`.
"""
from __future__ import annotations

import logging
from enum import StrEnum
from typing import ClassVar

from aila.platform.contracts.enums import PersonaVoice

_log = logging.getLogger(__name__)

__all__ = [
    "PERSONA_ROLE_MAP",
    "PersonaRole",
    "PersonaRouter",
    "persona_to_role",
]


class PersonaRole(StrEnum):
    """The 3 roles a persona maps to (GA-52)."""

    RESEARCHER = "researcher"
    IMPLEMENTER = "implementer"
    CRITIC = "critic"


# Static persona -> role table. Tuned by D-39 + GA-52:
#   halvar = deliberate, considers fundamentals -> researcher
#   noor   = unconventional angles -> researcher
#   renzo  = builds PoCs + scripts -> implementer
#   wei    = systems engineer mindset -> implementer
#   maddie = adversarial, picks holes -> critic
#   yuki   = methodical verifier -> critic
PERSONA_ROLE_MAP: dict[PersonaVoice, PersonaRole] = {
    PersonaVoice.HALVAR: PersonaRole.RESEARCHER,
    PersonaVoice.NOOR: PersonaRole.RESEARCHER,
    PersonaVoice.RENZO: PersonaRole.IMPLEMENTER,
    PersonaVoice.WEI: PersonaRole.IMPLEMENTER,
    PersonaVoice.MADDIE: PersonaRole.CRITIC,
    PersonaVoice.YUKI: PersonaRole.CRITIC,
}


def persona_to_role(persona: PersonaVoice | str | None) -> PersonaRole | None:
    """Map a :class:`PersonaVoice` (or its string form) to a :class:`PersonaRole`.

    Returns ``None`` for the synthetic voices (``unspecified``,
    ``merge_result``, ``fork_unnamed``), unknown strings, or ``None``.
    """
    if persona is None:
        return None
    if isinstance(persona, str):
        try:
            persona = PersonaVoice(persona)
        except ValueError as exc:
            _log.warning("FAILED reason=%s", exc)
            return None
    return PERSONA_ROLE_MAP.get(persona)


class PersonaRouter:
    """Per-module persona -> LLM ``task_type`` router.

    Subclasses MUST set :attr:`default_task_type` and either
    :attr:`persona_task_type` or :attr:`role_task_type`:

    * When :attr:`persona_task_type` is non-empty it wins: the persona
      is looked up directly, giving each voice its own model + budget
      tuning (malware shape).
    * When :attr:`persona_task_type` is empty and :attr:`role_task_type`
      is non-empty, the persona is first mapped to a role via
      :func:`persona_to_role`, then the role is looked up (vr shape).
    * Otherwise (unknown persona, no matching entry, ``None``) the
      subclass's :attr:`default_task_type` is returned.
    """

    default_task_type: ClassVar[str]
    role_task_type: ClassVar[dict[PersonaRole, str]] = {}
    persona_task_type: ClassVar[dict[PersonaVoice, str]] = {}

    @classmethod
    def resolve_task_type(cls, persona: PersonaVoice | str | None) -> str:
        """Resolve the LLM client ``task_type`` for a branch's persona."""
        default = cls.default_task_type
        if persona is None:
            return default
        if isinstance(persona, str):
            try:
                persona = PersonaVoice(persona)
            except ValueError as exc:
                _log.warning("FAILED reason=%s", exc)
                return default
        if cls.persona_task_type:
            return cls.persona_task_type.get(persona, default)
        role = PERSONA_ROLE_MAP.get(persona)
        if role is None:
            return default
        return cls.role_task_type.get(role, default)
