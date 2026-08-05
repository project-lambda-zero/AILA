"""Template binding of the platform McpRegistryServiceBase.

Mirrors :mod:`aila.modules.vr.services.mcp_registry`. Owns the
template-side ``MCP_SERVERS`` catalog and binds it (with the
``"template"`` :class:`ConfigRegistry` namespace) onto the platform
base. The platform base owns the resolve / probe / update logic; this
module carries only the module residue.

To add a new MCP server for a copied module, append its spec here AND
add a matching URL field to the module's ``ConfigSchema``. The
operator-facing UI auto-discovers from this list.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.mcp.descriptor import (
    McpServerDescriptor,
    descriptors_from_static_specs,
)
from aila.platform.mcp.registry import McpRegistryServiceBase

__all__ = [
    "MCP_SERVERS",
    "MODULE_CAPABILITIES",
    "SERVER_CAPABILITY_DEFAULTS",
    "McpRegistryService",
    "get_descriptors",
]


# Placeholder single-entry catalog. Kept minimal-real so the operator
# probe surface has one visible row to exercise the resolve + probe
# path end to end when the scaffold is copied; a copier replaces the
# entry with the module's real MCP server(s). See vr / malware for
# the shape when a module ships several.
MCP_SERVERS: tuple[dict[str, str], ...] = (
    {
        "id": "audit_mcp",
        "name": "audit-mcp",
        "description": (
            "Placeholder source-code audit MCP entry. Replace with the "
            "concrete MCP the copied module actually delegates to."
        ),
        "env_var": "AUDIT_MCP_URL",
        "config_key": "audit_mcp_url",
        "default_url": "http://127.0.0.1:18822",
    },
)


# RFC-11 step 3 -- capability-based module binding. Empty by default:
# the scaffold has no target-kind vocabulary yet. A copier fills this
# with the module's target-kind -> capability-tag map so the platform
# resolver can find MCP catalog rows by capability. See vr's
# ``{"source_repo": ("source_audit",), ...}`` for the concrete shape.
MODULE_CAPABILITIES: dict[str, tuple[str, ...]] = {}

# Default capability tags each seeded server row advertises. Aligned
# with the placeholder ``audit_mcp`` entry above; a copier extends the
# map as they add real servers.
SERVER_CAPABILITY_DEFAULTS: dict[str, tuple[str, ...]] = {
    "audit_mcp": ("source_audit",),
}


class McpRegistryService(McpRegistryServiceBase):
    """Resolve current URL + probe health for each registered template MCP."""

    _module_id: ClassVar[str] = "template"
    _servers: ClassVar[tuple[dict[str, str], ...]] = MCP_SERVERS


def get_descriptors() -> tuple[McpServerDescriptor, ...]:
    """Return the template module's :class:`McpServerDescriptor` set.

    Publishes ``MCP_SERVERS`` + ``SERVER_CAPABILITY_DEFAULTS`` through
    :func:`aila.platform.mcp.descriptor.descriptors_from_static_specs`
    so :class:`aila.platform.mcp.capability_registry.McpCapabilityRegistry`
    can resolve every template-declared server BY CAPABILITY (RFC-11
    step 3) without the platform hard-coding a per-module catalog. A
    copier calls this from its ``create_module()`` startup and hands
    the result to
    ``default_capability_registry().declare_all('<module>', ...)``.
    """
    return descriptors_from_static_specs(MCP_SERVERS, SERVER_CAPABILITY_DEFAULTS)
