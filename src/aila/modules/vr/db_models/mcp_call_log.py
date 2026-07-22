"""MCP call log table -- operator audit trail of every delegated call.

VR module's concrete record. Shared columns come from the platform base;
``investigation_id`` / ``branch_id`` / ``turn_number`` are vr-only
observability join-keys (issue #39 / migration 082) not yet present on the
malware side, so they stay here as module residue until they are hoisted.
"""
from __future__ import annotations

from sqlmodel import Field

from aila.platform.contracts.mcp_call_log_base import McpCallLogRecordBase

__all__ = ["VRMcpCallLogRecord"]


class VRMcpCallLogRecord(McpCallLogRecordBase, table=True):
    """One MCP call record (operator audit trail)."""

    __tablename__ = "vr_mcp_call_log"

    # #39 observability join keys (migration 082): vr-only residue.
    investigation_id: str | None = Field(default=None, max_length=36, index=True)
    branch_id: str | None = Field(default=None, max_length=36, index=True)
    turn_number: int | None = Field(default=None)
