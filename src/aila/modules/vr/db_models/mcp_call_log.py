"""MCP call log table -- operator audit trail of every delegated call.

VR module's concrete record. Every column comes from the shared platform base;
see :mod:`aila.platform.contracts.mcp_call_log_base`. The #39 observability
join-keys (investigation_id / branch_id / turn_number) now live on the base
(RFC-04 Phase 1 unified the MCP call logger across modules).
"""
from __future__ import annotations

from aila.platform.contracts.mcp_call_log_base import McpCallLogRecordBase

__all__ = ["VRMcpCallLogRecord"]


class VRMcpCallLogRecord(McpCallLogRecordBase, table=True):
    """One MCP call record (operator audit trail)."""

    __tablename__ = "vr_mcp_call_log"
