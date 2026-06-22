"""Platform-level MCP plumbing.

Two sub-packages:

* :mod:`aila.platform.mcp.bridges` — HTTP/SSE clients (one Tool subclass
  per MCP server: audit_mcp, ida_headless, android_mcp). The bridges
  are stateless dispatchers; every binary / index / session state lives
  on the MCP server itself.
* :mod:`aila.platform.mcp.adapters` — pure response→payload adapters.
  One per (server, tool) pair where structured rendering helps; the
  rest fall through to ``generic.adapt_generic``. Adapters convert a
  raw MCP response into a typed ``PayloadKind`` payload plus an
  ``observables_delta`` for the reasoning case state.

Modules instantiate these per-investigation (or per-worker) and inject
their own ``recorder`` callable for per-call audit logging into a
module-specific table.
"""
from __future__ import annotations

__all__: list[str] = []
