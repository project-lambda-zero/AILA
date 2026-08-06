"""MCP bridge submodules.

RFC-11 Tier C collapsed the three bespoke HTTP bridge ``Tool`` subclasses
(``IDABridgeTool`` / ``AuditMcpBridgeTool`` / ``AndroidMcpBridgeTool``)
onto the generic :class:`aila.platform.mcp.bridge_tool.McpBridgeTool` plus
one :class:`aila.platform.mcp.middleware.McpMiddleware` plugin per server.
Construct a bridge through :func:`aila.platform.mcp.factory.make_bridge`;
the server-specific behaviour lives in
:mod:`aila.platform.mcp.middleware`.

This package now holds only the in-process ``knowledge`` bridge (RFC-12
read-only knowledge retrieval -- no HTTP transport to collapse) and the
shared ``_recorder`` protocol that the knowledge bridge consumes.
"""
from __future__ import annotations

__all__: list[str] = []
