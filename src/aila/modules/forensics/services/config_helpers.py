"""Forensics typed config reads -- thin binding of the platform config reader.

Introduced in #18 alongside the panel spine. The typed-getter logic
(layered lookup + coercion via :class:`ConfigRegistry`) lives once in
:mod:`aila.platform.config_base`. This module binds a
:class:`ModuleConfigReader` at the ``forensics`` namespace and re-exports
its bound methods so callers keep the ``get_int(key)`` / ``get_float(key)``
surface.
"""
from __future__ import annotations

from aila.platform.config_base import ModuleConfigReader

__all__ = ["get_float", "get_int", "get_str"]

_reader = ModuleConfigReader("forensics")

get_int = _reader.get_int
get_float = _reader.get_float
get_str = _reader.get_str
