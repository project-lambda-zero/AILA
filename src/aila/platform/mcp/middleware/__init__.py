"""RFC-11 Tier C -- per-server MCP middleware plugins.

Each MCP server (ida-headless, audit-mcp, android-mcp) carries
server-specific behaviour that the generic :class:`McpClient` transport
does not model: kwarg alias maps, path rewrites, pending-poll retry
loops, dead-worker detection, dedup caches, prewarm fan-out, virtual
tools (audit-mcp ``read_lines``), per-tool schema fetch (android-mcp),
and so on. Before RFC-11 Tier C that behaviour lived inside three
bespoke ``Tool`` subclasses that each re-implemented the HTTP transport.

Tier C collapses the transport onto :class:`McpClient` and relocates the
server-specific behaviour into a :class:`McpMiddleware` plugin per
server. One generic :class:`aila.platform.mcp.bridge_tool.McpBridgeTool`
runs the transport and delegates every server-specific decision to the
bound middleware. :func:`aila.platform.mcp.factory.make_bridge` resolves
the middleware for a server id and constructs the generic tool.

The three plugins (``ida``, ``audit``, ``android``) are imported lazily
by the factory so this package has no import-time dependency on the
concrete plugins and the base contract compiles standalone.
"""
from __future__ import annotations

from ._base import McpMiddleware

__all__ = ["McpMiddleware"]
