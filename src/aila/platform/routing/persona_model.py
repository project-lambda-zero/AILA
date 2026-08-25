"""Persona-to-model routing (issue #151, req 31).

Sibling personas today share one base model, so multi-persona debate
degenerates to self-consistency: the same model rejects itself with
the same blind spots. The debate only unlocks cross-error rejection
when distinct personas can run distinct base models.

This module ships the MECHANISM for that -- an operator-populated
nested map from ``module_id`` to ``{persona: model_role}``. The
resolver keys first on the caller's ``module_id`` (the turn runner
knows its module) and falls back to the ``"__global__"`` sentinel
bucket when no module-scoped entry is present. That fallback bucket
is also the promotion target for a legacy flat
``{persona: model_role}`` config value -- an operator who wrote the
flat shape before req 31 keeps working without a data migration.

The persona value is normalized to a ``task_type`` string (the same
shape :class:`aila.platform.llm.config.LLMConfigProvider` resolves
via ``llm_model_{task_type}``). The map is sourced from
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
* Module-scoped resolution: when the caller passes
  ``module_id="<id>"`` the resolver returns
  ``mapping["<id>"][persona]`` when present, otherwise
  ``mapping["__global__"][persona]`` when present, otherwise
  ``None``. When ``module_id`` is omitted only the ``__global__``
  bucket is consulted -- byte-identical to the pre-req-31 behavior
  for callers that have not been updated to thread their module_id.

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
    "GLOBAL_MODULE_KEY",
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
# object literal in the NESTED shape
# ``{module_id: {persona_voice: model_role}}``. An empty string means
# "no map" and resolves as an empty dict (behavior-preserving). A
# legacy flat ``{persona: model_role}`` value is still accepted at
# read time and promoted under the ``"__global__"`` sentinel bucket
# so operators who wrote the pre-req-31 shape keep working.
PERSONA_MODEL_ROLE_MAP_KEY: str = "persona_model_role_map"

# Sentinel module_id used as the fallback bucket in the nested map.
# A resolve for ``module_id="foo"`` consults ``mapping["foo"]`` first
# then falls through to ``mapping["__global__"]``. Also the promotion
# target for legacy flat map values (see :meth:`PersonaModelRouter._load_map`).
GLOBAL_MODULE_KEY: str = "__global__"


def _persona_to_key(persona: PersonaVoice | str) -> str:
    """Normalize a persona to its lookup key.

    Both enum members and open-set specialist voice strings resolve to
    the same lowercase form the branch row stores.
    """
    if isinstance(persona, PersonaVoice):
        return persona.value
    return str(persona).strip().lower()


def _normalize_inner(inner: dict) -> dict[str, str]:
    """Normalize one ``{persona: model_role}`` inner map.

    Persona keys are lowered via :func:`_persona_to_key`; empty or
    ``None`` role values are dropped so an operator half-clearing an
    entry does not leak an empty override to the caller.
    """
    out: dict[str, str] = {}
    for persona, role in inner.items():
        if role is None:
            continue
        role_str = str(role).strip()
        if not role_str:
            continue
        out[_persona_to_key(persona)] = role_str
    return out


class PersonaModelRouter:
    """Config-sourced ``{module_id: {persona: model_role}}`` lookup.

    Constructed without arguments in production (a
    :class:`ConfigRegistry` is built lazily on first read); tests
    inject either an explicit ``source_map`` (bypassing the registry)
    or a stub registry to keep the router hermetic.

    ``source_map`` accepts BOTH shapes for test ergonomics:

    * Nested ``{module_id: {persona: model_role}}`` -- stored as-is
      (inner maps normalized).
    * Flat ``{persona: model_role}`` -- promoted under
      :data:`GLOBAL_MODULE_KEY`. Mixed shapes (some values are
      strings, some are dicts) are accepted: string values go into
      the ``__global__`` bucket, dict values are that module's inner
      map.
    """

    def __init__(
        self,
        *,
        registry: ConfigRegistry | None = None,
        source_map: dict[str, str] | dict[str, dict[str, str]] | None = None,
    ) -> None:
        self._registry = registry
        self._explicit_map: dict[str, dict[str, str]] | None = None
        if source_map is not None:
            self._explicit_map = self._coerce_source_map(source_map)

    @staticmethod
    def _coerce_source_map(
        source_map: dict[str, str] | dict[str, dict[str, str]],
    ) -> dict[str, dict[str, str]]:
        """Coerce a caller-supplied map to the nested normalized form.

        Legacy flat values are promoted under :data:`GLOBAL_MODULE_KEY`;
        nested values are normalized in place. Mixed shapes are handled
        by inspecting each value.
        """
        nested: dict[str, dict[str, str]] = {}
        legacy_bucket: dict[str, str] = {}
        for key, value in source_map.items():
            if isinstance(value, dict):
                inner = _normalize_inner(value)
                if inner:
                    nested[str(key)] = inner
                continue
            if value is None:
                continue
            role_str = str(value).strip()
            if not role_str:
                continue
            legacy_bucket[_persona_to_key(key)] = role_str
        if legacy_bucket:
            existing = nested.get(GLOBAL_MODULE_KEY, {})
            merged = {**legacy_bucket, **existing}
            nested[GLOBAL_MODULE_KEY] = merged
        return nested

    async def _load_map(self) -> dict[str, dict[str, str]]:
        """Return the current nested persona-model map.

        An explicit constructor-supplied map wins so tests can pin the
        map without a registry round-trip. Otherwise the registry is
        consulted; a missing key, empty string, malformed JSON, or a
        non-object payload all resolve to an empty map (the
        behavior-preserving default). The registry's own 60-second
        cache absorbs the read cost on the LLM hot path.

        Parsed payload shapes accepted:

        * Nested ``{module_id: {persona: role}}`` -- each inner
          object is normalized via :func:`_normalize_inner`.
        * Legacy flat ``{persona: role}`` -- values that are strings
          are collected under :data:`GLOBAL_MODULE_KEY` so an
          operator with the pre-req-31 shape resolves correctly.
        * Mixed -- string values feed the ``__global__`` bucket,
          dict values are their module's inner map.
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
        return self._coerce_source_map(parsed)

    async def resolve_model_role(
        self,
        persona: PersonaVoice | str | None,
        module_id: str | None = None,
    ) -> str | None:
        """Return the mapped model_role for ``persona`` or ``None``.

        Resolution precedence for a non-None ``module_id``:
        ``mapping[module_id][persona]`` else
        ``mapping[GLOBAL_MODULE_KEY][persona]`` else ``None``. When
        ``module_id`` is ``None`` only the ``__global__`` bucket is
        consulted -- a caller that has not been updated to thread its
        module still sees the flat semantics.

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
        key = _persona_to_key(persona)
        if module_id is not None:
            module_bucket = mapping.get(module_id)
            if module_bucket is not None:
                mapped = module_bucket.get(key)
                if mapped is not None:
                    return mapped
        global_bucket = mapping.get(GLOBAL_MODULE_KEY)
        if global_bucket is None:
            return None
        return global_bucket.get(key)


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
    module_id: str | None = None,
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

    ``module_id`` scopes the lookup to that module's inner map with
    fallback through :data:`GLOBAL_MODULE_KEY`. Omitting it consults
    only the ``__global__`` bucket. ``router`` is optional; the
    process-wide singleton is used when omitted. Injectable so tests
    can pin a hermetic router without touching global state.
    """
    active_router = router if router is not None else get_default_persona_model_router()
    override = await active_router.resolve_model_role(persona, module_id=module_id)
    if override is None:
        return base_task_type
    return override
