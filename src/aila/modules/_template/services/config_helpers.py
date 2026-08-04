"""Template typed config reads -- thin binding of the platform reader.

Mirrors :mod:`aila.modules.vr.services.config_helpers`. Every ``get_int``
/ ``get_float`` call routes through :class:`ModuleConfigReader` bound to
the ``template`` namespace so operator overrides layered on top of
:class:`TemplateConfigSchema` defaults take effect at read time.
"""
from __future__ import annotations

from aila.platform.config_base import ModuleConfigReader

__all__ = ["get_float", "get_int", "get_str"]

_reader = ModuleConfigReader("template")

get_int = _reader.get_int
get_float = _reader.get_float
get_str = _reader.get_str
