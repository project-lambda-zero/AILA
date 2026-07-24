"""VR typed config reads -- thin binding of the platform config reader.

The typed-getter logic (layered lookup + coercion via ConfigRegistry)
lives once in :mod:`aila.platform.config_base`. This module binds a
:class:`ModuleConfigReader` at the ``vr`` namespace and re-exports its
bound methods so callers keep the ``get_int(key)`` / ``get_float(key)``
surface unchanged.
"""
from __future__ import annotations

from aila.platform.config_base import ModuleConfigReader

__all__ = ["get_float", "get_int"]

_reader = ModuleConfigReader("vr")

get_int = _reader.get_int
get_float = _reader.get_float
