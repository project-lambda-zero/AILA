"""Platform persona router (RFC-03 Phase 5).

Per-module persona -> LLM ``task_type`` router. Extracted from the
byte-identical vr and malware copies of ``persona_router.py``.

Each strategy branch can carry a :class:`PersonaVoice`. The platform's
LLM client uses ``task_type`` per call to resolve routing (model,
temperature, max_tokens, retry policy). Modules subclass
:class:`PersonaRouter` and set attributes:

* ``default_task_type`` -- fallback returned when the persona is
  ``None``, is absent from the module's table, or is a synthetic
  voice.
* ``persona_role_map`` -- persona voice -> :class:`PersonaRole`
  mapping the module recognises. Empty on the platform base so a
  module that never carries agent personas (forensics, hello_world)
  falls through to ``default_task_type`` without ceremony. VR and the
  ``_template`` scaffold supply the six-voice roster the D-39 /
  GA-52 personas map to.
* Either ``role_task_type`` (role -> task_type, when personas that
  share a role share a task_type -- the vr shape) or
  ``persona_task_type`` (persona -> task_type, when each voice
  carries its own model + budget tuning -- the malware shape).

The persona -> role mapping is domain vocabulary supplied by each
module. The base class ships an empty :attr:`PersonaRouter.persona_role_map`
so the router degrades to ``default_task_type`` when no vocabulary is
declared.
"""
from __future__ import annotations

import logging
from enum import StrEnum
from typing import ClassVar

from aila.platform.contracts.enums import PersonaVoice

_log = logging.getLogger(__name__)

__all__ = [
    "PersonaRole",
    "PersonaRouter",
]


class PersonaRole(StrEnum):
    """The 3 roles a persona maps to (GA-52)."""

    RESEARCHER = "researcher"
    IMPLEMENTER = "implementer"
    CRITIC = "critic"


def _as_known_voice(persona: PersonaVoice | str) -> PersonaVoice | None:
    """Coerce a persona to a known core :class:`PersonaVoice`, or ``None``.

    The branch ``persona_voice`` contract is an open string: specialist
    agents carry their capability (``variant``, ``crypto``, ...) as the
    voice, and the hub routes them by that capability. Such voices are not
    in the fixed 6-persona table, so an unrecognized voice is an expected
    fallback to the default routing -- not an error. Returns the enum
    member for a core voice, else ``None``.
    """
    if isinstance(persona, PersonaVoice):
        return persona
    try:
        return PersonaVoice(persona)
    except ValueError:
        _log.debug("open-set persona_voice %r -- using default routing", persona)
        return None


class PersonaRouter:
    """Per-module persona -> LLM ``task_type`` router.

    Subclasses MUST set :attr:`default_task_type` and either
    :attr:`persona_task_type` or :attr:`role_task_type`:

    * When :attr:`persona_task_type` is non-empty it wins: the persona
      is looked up directly, giving each voice its own model + budget
      tuning (malware shape).
    * When :attr:`persona_task_type` is empty and :attr:`role_task_type`
      is non-empty, the persona is first mapped to a role via
      :attr:`persona_role_map`, then the role is looked up (vr shape).
    * Otherwise (unknown persona, empty role map, no matching entry,
      ``None``) the subclass's :attr:`default_task_type` is returned.

    The :attr:`persona_role_map` is module-supplied vocabulary. The
    base default is empty so a module with no persona-based routing
    (only ``default_task_type``) works without declaring an unused
    map, and a module that hasn't yet published a persona roster
    (forensics, hello_world) degrades gracefully.
    """

    default_task_type: ClassVar[str]
    persona_role_map: ClassVar[dict[PersonaVoice, PersonaRole]] = {}
    role_task_type: ClassVar[dict[PersonaRole, str]] = {}
    persona_task_type: ClassVar[dict[PersonaVoice, str]] = {}

    @classmethod
    def resolve_task_type(cls, persona: PersonaVoice | str | None) -> str:
        """Resolve the LLM client ``task_type`` for a branch's persona."""
        default = cls.default_task_type
        if persona is None:
            return default
        member = _as_known_voice(persona)
        if member is None:
            return default
        if cls.persona_task_type:
            return cls.persona_task_type.get(member, default)
        role = cls.persona_role_map.get(member)
        if role is None:
            return default
        return cls.role_task_type.get(role, default)

    @classmethod
    def persona_to_role(
        cls, persona: PersonaVoice | str | None,
    ) -> PersonaRole | None:
        """Map a :class:`PersonaVoice` to its role via the subclass's map.

        Returns ``None`` for ``None``, synthetic voices, open-set
        specialist voices, or any voice absent from the subclass's
        :attr:`persona_role_map`. Modules that carry no persona roster
        (empty map) always return ``None`` -- callers must fall back to
        the router's ``default_task_type`` or module-specific defaults.
        """
        if persona is None:
            return None
        member = _as_known_voice(persona)
        if member is None:
            return None
        return cls.persona_role_map.get(member)
