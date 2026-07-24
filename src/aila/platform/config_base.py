"""Shared base for module config schemas plus the unified typed config reader.

Two pieces the module config layer used to copy per module:

* :class:`ModuleConfigBase` -- the base every module ``config_schema.py``
  model subclasses. It bakes in ``extra="forbid"`` so a config model
  constructed with an undeclared key fails closed instead of silently
  dropping it. The per-module fields (``llm_model``, caps, timeouts, API
  URLs) stay on the subclass; the base only fixes the strictness policy so
  a module cannot regress to permissive validation.
* :class:`ModuleConfigReader` -- namespaced typed config reads via the
  shared :class:`ConfigRegistry`. It replaces the byte-identical
  per-module ``services/config_helpers.py`` singletons. ConfigRegistry
  already does the layered lookup (``AILA_<NS>_<KEY>`` env -> DB -> schema
  default); the reader coerces the resolved value to the caller's type. A
  module binds one reader at its namespace and re-exports the bound
  methods so callers keep the ``get_int(key)`` / ``get_float(key)``
  surface unchanged.

The registry instance is process-wide: one :class:`ConfigRegistry` serves
every namespace (``get`` takes the namespace per call), so the modules no
longer each carry their own singleton. The registry's own cache layer
handles the in-process hot path; an operator ``PUT /config`` write
invalidates it on the next read.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from aila.storage.registry import ConfigRegistry

__all__ = ["ModuleConfigBase", "ModuleConfigReader"]


class ModuleConfigBase(BaseModel):
    """Base for every module-scoped config schema.

    Subclasses declare the module's operator-tunable fields. The base
    fixes ``extra="forbid"`` so an undeclared key passed at construction
    fails closed. This is the single enforcement point for the
    fail-closed policy that module schemas previously re-declared each on
    their own (and that one module -- vulnerability -- silently omitted).
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


class ModuleConfigReader:
    """Namespace-bound typed config reads via the shared ConfigRegistry.

    A module constructs one reader at its namespace and re-exports the
    bound methods from its ``services/config_helpers.py`` so existing
    callers keep the ``get_int(key)`` / ``get_float(key)`` call surface.
    The resolved schema field is the source of truth for the value type;
    these helpers coerce whatever the registry returns to the requested
    type, matching the behavior the per-module helpers had.
    """

    def __init__(self, namespace: str) -> None:
        self._namespace = namespace

    async def get_int(self, key: str) -> int:
        """Resolve ``<namespace>/<key>`` and coerce to int."""
        return int(await _shared_registry().get(self._namespace, key))

    async def get_float(self, key: str) -> float:
        """Resolve ``<namespace>/<key>`` and coerce to float."""
        return float(await _shared_registry().get(self._namespace, key))
