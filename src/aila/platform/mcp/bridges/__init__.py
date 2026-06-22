"""MCP bridge clients.

Each bridge is a :class:`aila.platform.tools._common.Tool` subclass
wrapping one MCP server's HTTP surface. Bridges are stateless and
share an httpx pool per worker process.

Per-call audit logging is opt-in: pass a ``recorder`` async context
manager to the bridge constructor and the bridge will yield to it
around every dispatch. Module authors typically wire the recorder to
their own ``mcp_call_logger.record_call`` so each call lands in a
module-specific audit table. When ``recorder`` is omitted the bridge
runs without logging.
"""
from __future__ import annotations

from .android_mcp import AndroidMcpBridgeTool
from .audit_mcp import AuditMcpBridgeTool
from .ida_headless import IDABridgeTool

__all__ = [
    "AndroidMcpBridgeTool",
    "AuditMcpBridgeTool",
    "IDABridgeTool",
]
