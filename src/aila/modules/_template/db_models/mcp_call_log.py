"""MCP call-log table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.mcp_call_log_base``;
the concrete below only sets ``__tablename__`` -- the base carries no
FK tablename ClassVars (``target_id`` / ``team_id`` are opaque string
references so a target row can be deleted while its call log stays
intact for the operator audit trail).

Scaffold intentionally stays at the base intersection: no
``investigation_id`` / ``branch_id`` / ``turn_number`` residue (the vr
concrete adds those from issue #39 / migration 082 as vr-only
observability join-keys). A new module that wants them declares them
here on the subclass.
"""
from __future__ import annotations

from aila.platform.contracts.mcp_call_log_base import McpCallLogRecordBase

__all__ = ["TemplateMcpCallLogRecord"]


class TemplateMcpCallLogRecord(McpCallLogRecordBase, table=True):
    """Scaffold: one MCP call record (operator audit trail)."""

    __tablename__ = "template_mcp_call_log"
