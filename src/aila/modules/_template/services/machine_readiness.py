"""Template binding of the platform :class:`MachineReadinessService`.

The platform readiness service takes ``(ida_bridge, settings, *,
requirements_path)``. Only ``requirements_path`` is module-owned residue
-- the caller supplies the live ``ida_bridge`` + ``settings`` from
either the API request scope or a worker startup context. This module
pre-binds the requirements-file path so the caller writes::

    svc = MachineReadinessService(ida_bridge, settings)

A copier fills ``data/tool_requirements.json`` with the OS -> tool-def
map its module actually needs (see the malware / forensics equivalents
for the concrete shape); the scaffold ships an empty map so the probe
returns cleanly without asserting any tool the copied module hasn't
adopted yet.
"""
from __future__ import annotations

from functools import partial
from pathlib import Path

from aila.platform.services.machine_readiness import (
    MachineReadinessService as _PlatformMachineReadinessService,
)
from aila.platform.services.machine_readiness import (
    ReadinessResult,
    ToolCheckResult,
)

__all__ = ["MachineReadinessService", "ReadinessResult", "ToolCheckResult"]

# Module-owned residue: path to the OS -> tool-def-list map the
# readiness probe reads. Scaffold ships an empty map; a copier
# populates it once the module knows which analyzer-workstation tools
# its investigation flow depends on.
_TEMPLATE_REQUIREMENTS_PATH: Path = (
    Path(__file__).resolve().parent.parent / "data" / "tool_requirements.json"
)

# Thin factory: pre-binds the module's requirements-file path onto the
# platform service so callers supply only ``(ida_bridge, settings)``.
# ``functools.partial`` produces a stable object across re-imports --
# any downstream identity-keyed registration sees the same handle.
MachineReadinessService = partial(
    _PlatformMachineReadinessService,
    requirements_path=_TEMPLATE_REQUIREMENTS_PATH,
)
