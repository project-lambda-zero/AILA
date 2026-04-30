"""Tool catalog for the forensics module.

Discovers tool specs from the tools/ subpackage using the TOOL_ALIAS /
CAPABILITY / FACTORY pattern. Each tool module exposes these three
module-level constants.
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from aila.config import Settings

__all__ = ["ToolSpec", "iter_tool_specs"]


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Descriptor pairing a tool alias with its factory callable."""

    alias: str
    module_id: str
    factory_fn: Any

    def key(self) -> str:
        """Return the full registry key ``forensics.<alias_lower>``."""
        return f"{self.module_id}.{self.alias.lower()}"

    def factory(self, settings: Settings) -> Any:
        """Instantiate the tool via the registered factory callable.

        Delegates to ``factory_fn`` which may be a class constructor or a
        free function returning the configured tool instance.
        """
        instance = self.factory_fn(settings)
        return instance


def iter_tool_specs() -> Iterator[ToolSpec]:
    """Yield ToolSpec for every forensics tool module that defines TOOL_ALIAS."""
    from aila.modules.forensics.tools import (
        artifact_query,
        carving_runner,
        dd_runner,
        dissect_runner,
        evidence_intake,
        ghidra_runner,
        registry_viewer,
        script_tool,
        strings_runner,
        tshark_runner,
        volatility_runner,
        yara_runner,
        zeek_runner,
    )

    modules = [
        evidence_intake,
        artifact_query,
        dissect_runner,
        volatility_runner,
        tshark_runner,
        zeek_runner,
        strings_runner,
        script_tool,
        ghidra_runner,
        yara_runner,
        registry_viewer,
        carving_runner,
        dd_runner,
    ]
    for mod in modules:
        alias = getattr(mod, "TOOL_ALIAS", None)
        factory_fn = getattr(mod, "create_tool", None)
        if alias and factory_fn:
            yield ToolSpec(alias=alias, module_id="forensics", factory_fn=factory_fn)
