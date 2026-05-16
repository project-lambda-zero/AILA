"""Adapter registry — maps (mcp_server_id, tool_name) -> AdapterFn."""
from __future__ import annotations

from .audit_mcp import adapt_fuzzing_targets
from .base import AdapterFn
from .ida_headless import adapt_decompile, adapt_find_api_call_sites

__all__ = [
    "get_adapter",
    "registered_tools",
]


# Keys are (server_id, tool_name). server_id matches the bridge tool's
# canonical identifier ("ida_headless" or "audit_mcp").
_ADAPTERS: dict[tuple[str, str], AdapterFn] = {
    ("ida_headless", "decompile"): adapt_decompile,
    ("ida_headless", "find_api_call_sites"): adapt_find_api_call_sites,
    ("audit_mcp", "fuzzing_targets"): adapt_fuzzing_targets,
}


def get_adapter(server_id: str, tool_name: str) -> AdapterFn | None:
    """Return the adapter for one MCP tool, or None when unregistered."""
    return _ADAPTERS.get((server_id, tool_name))


def registered_tools() -> list[str]:
    """List registered '<server>.<tool>' tool identifiers."""
    return sorted(f"{server}.{tool}" for server, tool in _ADAPTERS)
