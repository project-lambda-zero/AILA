"""Shared base for module config schemas plus the unified typed config reader.

Two pieces the module config layer used to copy per module:

* :class:`ModuleConfigBase` -- the base every module ``config_schema.py``
  model subclasses. It bakes in ``extra="forbid"`` so a config model
  constructed with an undeclared key fails closed instead of silently
  dropping it. The per-module fields (caps, timeouts, API URLs) stay on
  the subclass; the base only fixes the strictness policy so a module
  cannot regress to permissive validation. It declares no fields: LLM
  model routing is platform-owned (``platform.llm_model_<task_type>``
  with ``platform.llm_default_model`` as the fallback), not a module key.
* :class:`ModuleConfigReader` -- namespaced typed config reads via the
  shared :class:`ConfigRegistry`. It replaces the byte-identical
  per-module ``services/config_helpers.py`` singletons. ConfigRegistry
  already does the layered lookup (``AILA_<NS>_<KEY>`` env -> DB -> schema
  default); the reader coerces the resolved value to the caller's type. A
  module binds one reader at its namespace and calls the typed getters
  (``_cfg.get_int(key)`` / ``_cfg.get_float(key)`` / ``_cfg.get_str(key)``
  / ``_cfg.get_bool(key)`` / ``_cfg.get_typed(key, as_)``) directly.

The registry instance is process-wide: one :class:`ConfigRegistry` serves
every namespace (``get`` takes the namespace per call), so the modules no
longer each carry their own singleton. The registry's own cache layer
handles the in-process hot path; an operator ``PUT /config`` write
invalidates it on the next read.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict

from aila.storage.registry import ConfigRegistry

__all__ = [
    "ModuleConfigBase",
    "ModuleConfigReader",
]


class ModuleConfigBase(BaseModel):
    """Base for every module-scoped config schema.

    Subclasses declare the module's operator-tunable fields. The base
    fixes ``extra="forbid"`` so an undeclared key passed at construction
    fails closed. This is the single enforcement point for the
    fail-closed policy that module schemas previously re-declared each
    on their own (and that one module -- vulnerability -- silently
    omitted).
    """

    model_config = ConfigDict(extra="forbid")


_registry: ConfigRegistry | None = None


def _shared_registry() -> ConfigRegistry:
    """Lazy process-wide :class:`ConfigRegistry` shared by every reader.

    One instance per worker, constructed on first config read. A single
    registry serves all namespaces because ``get`` takes the namespace
    per call, so no module needs its own singleton.
    """
    global _registry
    if _registry is None:
        _registry = ConfigRegistry()
    return _registry


def _coerce_bool(value: Any) -> bool:
    """Parse a config value into a bool.

    Matches the surface the operator-facing ConfigRegistry stores at
    ``AILA_<NS>_<KEY>``: env vars are always strings, DB overrides are
    strings, schema defaults may already be typed. Accepts already-bool
    inputs, ``int``/``float`` (non-zero -> True), and string values
    ``"1"`` / ``"true"`` / ``"yes"`` case-insensitively. Anything else
    is False.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes"}


class ModuleConfigReader:
    """Namespace-bound typed config reads via the shared ConfigRegistry.

    A consuming file constructs one reader at its module namespace
    (``_cfg = ModuleConfigReader("vr")``) and calls the typed getters
    directly. The resolved schema field is the source of truth for the
    value type; these helpers coerce whatever the registry returns to
    the requested type, matching the behavior the per-module helpers
    had.
    """

    def __init__(self, namespace: str) -> None:
        self._namespace = namespace

    async def get_int(self, key: str) -> int:
        """Resolve ``<namespace>/<key>`` and coerce to int."""
        return int(await _shared_registry().get(self._namespace, key))

    async def get_float(self, key: str) -> float:
        """Resolve ``<namespace>/<key>`` and coerce to float."""
        return float(await _shared_registry().get(self._namespace, key))

    async def get_str(self, key: str) -> str:
        """Resolve ``<namespace>/<key>`` and coerce to str."""
        return str(await _shared_registry().get(self._namespace, key))

    async def get_bool(self, key: str) -> bool:
        """Resolve ``<namespace>/<key>`` and coerce to bool.

        String values ``"1"`` / ``"true"`` / ``"yes"`` (case-insensitive)
        parse as True; ``int`` / ``float`` fall through Python's truth
        value; anything else is False.
        """
        return _coerce_bool(await _shared_registry().get(self._namespace, key))

    async def get_typed(self, key: str, as_: type) -> Any:
        """Resolve ``<namespace>/<key>`` and coerce to ``as_``.

        Dispatches to :meth:`get_int` / :meth:`get_float` /
        :meth:`get_str` / :meth:`get_bool`. Any other type raises
        :class:`TypeError` -- callers that need a domain type should
        read as str and parse themselves.
        """
        if as_ is int:
            return await self.get_int(key)
        if as_ is float:
            return await self.get_float(key)
        if as_ is str:
            return await self.get_str(key)
        if as_ is bool:
            return await self.get_bool(key)
        raise TypeError(
            f"ModuleConfigReader.get_typed: unsupported type {as_!r} for key "
            f"{self._namespace}/{key}; use int / float / str / bool",
        )
