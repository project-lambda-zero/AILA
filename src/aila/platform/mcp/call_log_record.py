"""Consolidated platform MCP call-log table (RFC-04 phase 2).

One row per delegated MCP tool call, across every module. Every column comes
from :class:`aila.platform.contracts.mcp_call_log_base.McpCallLogRecordBase`;
this concrete adds a single ``module_scope`` column so the operator can slice
the platform audit trail by originating module (``"vr"`` / ``"malware"`` /
future). The pre-split per-module call-log tables retire in migration 136
which copies every row into ``mcp_call_log`` stamping the originating scope.

Live dispatch continues to go through the module-bound
``services.mcp_call_logger.record_call`` partial; the partial now points at
this record model and supplies its own ``module_scope`` so the writer stays
module-agnostic.
"""
from __future__ import annotations

from sqlmodel import Field

from aila.platform.contracts.mcp_call_log_base import McpCallLogRecordBase

__all__ = ["McpCallLogRecord"]


class McpCallLogRecord(McpCallLogRecordBase, table=True):
    """One MCP call record for the platform-wide audit trail.

    ``module_scope`` names the module that issued the call (``"vr"``,
    ``"malware"``, ...). Nullable so a platform-owned call path with no
    module attribution still records a row.
    """

    __tablename__ = "mcp_call_log"

    module_scope: str | None = Field(default=None, max_length=64, index=True)
