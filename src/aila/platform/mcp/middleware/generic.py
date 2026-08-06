"""RFC-11 Tier C -- pass-through middleware for catalog-only MCP servers.

A server the operator adds to the catalog that has no bespoke plugin
(no ida/audit/android special behaviour) still needs a middleware so the
generic :class:`McpBridgeTool` can dispatch it. :class:`GenericMiddleware`
is the default: it forwards every action straight through the transport
with no kwarg rewriting, no poll loop, no dedup, no fallback. This is what
lets an operator register a brand-new MCP server advertising a capability
a module already binds and have it dispatch without a code change or a
worker restart.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient
    from aila.platform.mcp.server_specs import ServerSpec

__all__ = ["GenericMiddleware"]


class GenericMiddleware:
    """Transport-only middleware: forward every action verbatim.

    Constructed like every plugin as ``GenericMiddleware(spec=, module_id=)``.
    ``forward`` lists tools on an empty action and otherwise runs one
    recorded ``client.call_tool``; ``list_tool_specs`` is the client's
    default ``GET /tools`` projection.
    """

    def __init__(self, *, spec: ServerSpec, module_id: str) -> None:
        self.server_id = spec.server_id
        self.tool_name = spec.tool_name
        self.env_var = spec.env_var
        self.config_key = spec.config_key
        self.default_url = spec.default_url
        self.persistent_pool = spec.persistent_pool
        # A generic server MAY still honour a ``<SERVER_ID>_TIMEOUT`` env
        # override; absent it, the spec default applies.
        env_timeout = os.environ.get(f"{spec.server_id.upper()}_TIMEOUT")
        self.default_timeout = (
            float(env_timeout) if env_timeout else spec.default_timeout
        )
        self.module_id = module_id

    async def forward(
        self,
        client: McpClient,
        action: str | None,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """List tools on an empty action; otherwise one recorded call."""
        if not action:
            return {
                "status": "ready",
                "tools": await self.list_tool_specs(client),
            }
        return await client.call_tool(action, kwargs)

    async def list_tool_specs(self, client: McpClient) -> list[dict[str, Any]]:
        """Return the server's compacted tool catalogue (``GET /tools``)."""
        return await client.list_tool_specs()
