"""Persona-to-model routing (issue #151).

Sibling personas today share one base model, so multi-persona debate
degenerates to self-consistency: the same model rejects itself with
the same blind spots. The debate only unlocks cross-error rejection
when distinct personas can run distinct base models.

This module ships the MECHANISM for that -- an operator-populated
map from :class:`PersonaVoice` (open-string form; see
:mod:`aila.platform.contracts.enums`) to an abstract routing key the
existing LLM/route layer already understands: a ``task_type`` string
(the same shape :class:`aila.platform.llm.config.LLMConfigProvider`
resolves via ``llm_model_{task_type}``). The map is sourced from
``ConfigRegistry`` at the ``platform.persona_model_role_map`` key.

Design contract:

* Empty map, unmapped persona, or ``None`` persona ->
  :meth:`resolve_model_role` returns ``None`` and the caller keeps
  its already-resolved ``task_type`` untouched. The persona -> role
  routing that vr / malware / the module template already do
  (:mod:`aila.platform.agents.persona_router`) is unchanged.
* Populated map + a persona present in it ->
  :meth:`resolve_model_role` returns the mapped ``task_type`` /
  ``model_role`` string. The caller substitutes that value into the
  ``task_type`` it hands the LLM client; the client's existing
  ``resolve_model`` lookup then routes to whatever model the
  operator wired under ``llm_model_{model_role}``. No brand names,
  no OmniRoute combo names, and no per-persona table live in this
  module -- the map is entirely operator data.

Wiring lives at :func:`resolve_effective_task_type`. The turn runner
(:mod:`aila.platform.agents.turn_runner`) calls it immediately after
:meth:`aila.platform.agents.persona_router.PersonaRouter.resolve_task_type`
so the final ``task_type`` handed to the reasoning engine either is
the persona-mapped override or is byte-identical to today.
"""
from __future__ import annotations

import json
import logging
import threading

from ...storage.registry import ConfigRegistry
from ..contracts.enums import PersonaVoice

__all__ = [
    "PERSONA_MODEL_ROLE_MAP_KEY",
    "PersonaModelRouter",
    "get_default_persona_model_router",
    "reset_default_persona_model_router",
    "resolve_effective_task_type",
]

_log = logging.getLogger(__name__)

# ConfigRegistry lookup key. Registered as a static field on
# :class:`aila.platform.config.PlatformConfigSchema` so an operator can
# populate it via PUT /config/platform/persona_model_role_map or by env
# override (AILA_PLATFORM_PERSONA_MODEL_ROLE_MAP). Value is a JSON
# object literal mapping persona voice strings to model_role
# (task_type) strings; an empty string means "no map" and resolves as
# an empty dict (behavior-preserving).
PERSONA_MODEL_ROLE_MAP_KEY: str = "persona_model_role_map"


def _persona_to_key(persona: PersonaVoice | str) -> str:
    """Normalize a persona to its lookup key.

    Both enum members and open-set specialist voice strings resolve to
    the same lowercase form the branch row stores.
    """
    if isinstance(persona, PersonaVoice):
        return persona.value
    return str(persona).strip().lower()


class PersonaModelRouter:
    """Config-sourced persona -> model_role lookup.

    Constructed without arguments in production (a
    :class:`ConfigRegistry` is built lazily on first read); tests
    inject either an explicit ``source_map`` (bypassing the registry)
    or a stub registry to keep the router hermetic.
    """

    def __init__(
        self,
        *,
        registry: ConfigRegistry | None = None,
        source_map: dict[str, str] | None = None,
    ) -> None:
        self._registry = registry
        self._explicit_map: dict[str, str] | None = None
        if source_map is not None:
            self._explicit_map = {
                _persona_to_key(k): str(v).strip()
                for k, v in source_map.items()
                if v is not None and str(v).strip()
            }

    async def _load_map(self) -> dict[str, str]:
        """Return the current persona -> model_role map.

        An explicit constructor-supplied map wins so tests can pin the
        map without a registry round-trip. Otherwise the registry is
        consulted; a missing key, empty string, malformed JSON, or a
        non-dict payload all resolve to an empty map (the
        behavior-preserving default). The registry's own 60-second
        cache absorbs the read cost on the LLM hot path.
        """
        if self._explicit_map is not None:
            return self._explicit_map
        if self._registry is None:
            self._registry = ConfigRegistry()
        raw = await self._registry.get("platform", PERSONA_MODEL_ROLE_MAP_KEY)
        if raw is None:
            return {}
        text = str(raw).strip()
        if not text:
            return {}
        try:
            parsed = json.loads(text)
        except (ValueError, TypeError) as exc:
            _log.warning(
                "persona_model_role_map: JSON parse failed (%s: %s) -- "
                "treating as empty; no persona overrides applied.",
                type(exc).__name__, exc,
            )
            return {}
        if not isinstance(parsed, dict):
            _log.warning(
                "persona_model_role_map: expected JSON object, got %s -- "
                "treating as empty; no persona overrides applied.",
                type(parsed).__name__,
            )
            return {}
        normalized: dict[str, str] = {}
        for key, value in parsed.items():
            if value is None:
                continue
            role = str(value).strip()
            if not role:
                continue
            normalized[_persona_to_key(key)] = role
        return normalized

    async def resolve_model_role(
        self, persona: PersonaVoice | str | None,
    ) -> str | None:
        """Return the mapped model_role for ``persona`` or ``None``.

        ``None`` is the behavior-preserving default: callers replace
        their task_type ONLY when this method returns a non-None
        string, so an empty map path keeps every existing LLM call
        byte-identical to the pre-#151 behavior.
        """
        if persona is None:
            return None
        mapping = await self._load_map()
        if not mapping:
            return None
        return mapping.get(_persona_to_key(persona))


# Process-wide default so the turn runner does not thread a router
# reference through every subclass. Constructed on first access; tests
# call :func:`reset_default_persona_model_router` between cases.
_default_router_lock = threading.Lock()
_default_router: PersonaModelRouter | None = None


def get_default_persona_model_router() -> PersonaModelRouter:
    """Return the process-wide :class:`PersonaModelRouter` singleton."""
    global _default_router
    if _default_router is not None:
        return _default_router
    with _default_router_lock:
        if _default_router is None:
            _default_router = PersonaModelRouter()
        return _default_router


def reset_default_persona_model_router(
    router: PersonaModelRouter | None = None,
) -> None:
    """Replace or clear the process-wide singleton.

    Tests pass a pre-configured router (usually built with
    ``source_map=...``) to pin behavior for one case, then call with
    ``None`` in teardown to restore lazy construction.
    """
    global _default_router
    with _default_router_lock:
        _default_router = router


async def resolve_effective_task_type(
    base_task_type: str,
    persona: PersonaVoice | str | None,
    *,
    router: PersonaModelRouter | None = None,
) -> str:
    """Apply the persona -> model_role override on top of ``base_task_type``.

    Called by the shared turn runner AFTER
    :meth:`aila.platform.agents.persona_router.PersonaRouter.resolve_task_type`
    has produced the per-persona task_type. When the persona has a
    mapped model_role in the operator's map, that value replaces the
    base task_type (and downstream ``LLMConfigProvider.resolve_model``
    resolves ``llm_model_{model_role}`` -> the operator's chosen
    model). When no mapping exists, the base value is returned
    unchanged -- byte-identical to the pre-#151 call path.

    ``router`` is optional; the process-wide singleton is used when
    omitted. Injectable so tests can pin a hermetic router without
    touching global state.
    """
    active_router = router if router is not None else get_default_persona_model_router()
    override = await active_router.resolve_model_role(persona)
    if override is None:
        return base_task_type
    return override
