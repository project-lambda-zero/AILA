"""MCP call log table -- operator audit trail of every delegated call.

One row is written per ``AuditMcpBridgeTool.forward()`` /
``IDABridgeTool.forward()`` invocation, capturing the action, latency,
outcome, and an excerpt of the error message when the call failed.

Bodies are NOT persisted (use worker logs for those). The point of this
table is operator visibility: ``what was just called, did it work, how
long did it take``.
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now

__all__ = ["VRMcpCallLogRecord"]


class VRMcpCallLogRecord(SQLModel, table=True):
    """One MCP call record."""

    __tablename__ = "vr_mcp_call_log"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    server_id: str = Field(max_length=64, index=True)
    base_url: str = Field(max_length=512)
    action: str = Field(max_length=128)
    status: str = Field(max_length=16)  # 'ready' | 'error' | 'pending'
    http_status: int | None = Field(default=None)
    latency_ms: int | None = Field(default=None)
    error_excerpt: str | None = Field(default=None, sa_column=Column(Text))
    target_id: str | None = Field(default=None, max_length=36, index=True)
    team_id: str | None = Field(default=None, max_length=36)
    # #39 observability join keys: correlate a tool call back to the
    # investigation, branch, and turn that requested it.
    investigation_id: str | None = Field(default=None, max_length=36, index=True)
    branch_id: str | None = Field(default=None, max_length=36, index=True)
    turn_number: int | None = Field(default=None)
    called_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
        index=True,
    )
