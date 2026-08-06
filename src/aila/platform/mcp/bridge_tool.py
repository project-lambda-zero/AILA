"""RFC-11 Tier C -- the one generic MCP bridge tool.

Replaces the three bespoke ``Tool`` subclasses (``IDABridgeTool``,
``AuditMcpBridgeTool``, ``AndroidMcpBridgeTool``). One
:class:`McpBridgeTool` owns an :class:`McpClient` transport and delegates
every server-specific decision to a bound :class:`McpMiddleware`.
Construct one via :func:`aila.platform.mcp.factory.make_bridge`.

The public surface matches the pre-Tier-C bridges so the callers that
read ``.name`` / ``.module_id`` or await ``.forward`` / ``.list_tool_specs``
/ ``._resolve_base_url`` / ``.base_url`` / ``.invalidate_base_url`` do not
change. The dispatch router (RFC-07 reroute) pins a specific catalog
instance by assigning ``bridge._resolved``; the proxy property threads
that write onto the underlying client so the next call targets the
router's chosen endpoint.
"""
from __future__ import annotations

from typing import Any

from aila.platform.mcp.client import McpClient, ResolvedInstance, resolve_instance
from aila.platform.mcp.middleware import McpMiddleware
from aila.platform.tools import Tool

__all__ = ["McpBridgeTool"]


class McpBridgeTool(Tool):
    """Generic MCP bridge: transport via :class:`McpClient`, behaviour via middleware.

    ``forward`` copies nothing extra -- Python's ``**kwargs`` already
    hands the middleware a fresh dict it may mutate (pop flags, normalise
    aliases). ``list_tool_specs`` delegates to the middleware so android's
    per-tool schema fetch and audit's virtual-tool spec injection are
    preserved.
    """

    def __init__(
        self,
        *,
        middleware: McpMiddleware,
        module_id: str,
        recorder: Any | None = None,
    ) -> None:
        self._mw = middleware
        self.module_id = module_id
        self.server_id = middleware.server_id
        self.name = f"{module_id}.{middleware.tool_name}"
        self._client = McpClient(
            server_id=middleware.server_id,
            resolver=lambda: resolve_instance(
                module_scope=module_id,
                server_name=middleware.server_id,
                env_var=middleware.env_var,
                config_key=middleware.config_key,
                default_url=middleware.default_url,
            ),
            timeout=middleware.default_timeout,
            recorder=recorder,
            persistent_pool=middleware.persistent_pool,
        )

    @property
    def _resolved(self) -> ResolvedInstance | None:
        """Proxy the client's cached resolution for the RFC-07 reroute.

        The dispatch router assigns ``bridge._resolved = instance`` to
        pin the bridge at a router-chosen catalog instance before calling
        ``forward``. Threading it onto the client keeps that mechanism
        working unchanged after the bespoke bridges collapse onto the
        generic tool.
        """
        return self._client._resolved

    @_resolved.setter
    def _resolved(self, value: ResolvedInstance | None) -> None:
        self._client._resolved = value

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict[str, Any]:
        """Dispatch one agent tool call through the server's middleware."""
        return await self._mw.forward(self._client, action, kwargs)

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Return the server's compacted tool catalogue via the middleware."""
        return await self._mw.list_tool_specs(self._client)

    async def _resolve_base_url(self) -> str:
        """Resolve the current base URL (env > config > catalog > default)."""
        return await self._client.base_url()

    async def base_url(self) -> str:
        """Public alias for :meth:`_resolve_base_url` (auto-steering path)."""
        return await self._client.base_url()

    def invalidate_base_url(self) -> None:
        """Drop the cached resolution so the next call re-resolves."""
        self._client.invalidate_base_url()

    async def aclose(self) -> None:
        """Close the underlying transport pool if one was opened."""
        await self._client.aclose()
