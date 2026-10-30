"""re_analytics -- AILA-owned native MCP server for binary analysis.

Preserves the ida-headless tool surface that REA (the Ghidra-backed MCP
server) does not provide: flare-capa capability scanning, classification,
anti-analysis and dynamic-resolution detection, PE security flags, diffing,
call-graph queries, intra-procedural dataflow, and the session-scoped
mutation overlay. Tools are grouped into three modules
(:mod:`tools_capability`, :mod:`tools_crypto`, :mod:`tools_dataflow`) whose
``TOOLS`` lists :mod:`server` concatenates and serves over stdio JSON-RPC.

Run as ``python -m aila.platform.re_analytics``; the AILA bridge spawns
this module per :data:`aila.platform.mcp.server_specs.SERVER_SPECS`.
"""
from __future__ import annotations

from aila.platform.re_analytics._tooldef import ToolDef, ToolError

__all__ = ["ToolDef", "ToolError"]
