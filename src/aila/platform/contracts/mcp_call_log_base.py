"""MCP call-log record base shared by the investigation engine (RFC-01).

Zero-domain table: the vr and malware MCP call-log tables share the operator
audit-trail columns. One row per ``AuditMcpBridgeTool.forward()`` /
``IDABridgeTool.forward()`` invocation, capturing the action, latency,
outcome, and an excerpt of the error message when the call failed.

Bodies are NOT persisted (use worker logs for those). The point of this
table is operator visibility: ``what was just called, did it work, how
long did it take``.

A concrete module call-log collapses to::

    class MalwareMcpCallLogRecord(McpCallLogRecordBase, table=True):
        __tablename__ = "malware_mcp_call_log"

Note on the shared column set: migration 082 (issue #39) added
``investigation_id`` / ``branch_id`` / ``turn_number`` to ``vr_mcp_call_log``
ONLY, so those three observability join-keys are vr-only residue and are
intentionally OUT of this base. They stay on the vr concrete record until
the malware side also grows them, at which point they can be hoisted.

No FKs live on the base: the concrete columns declare only ``target_id`` /
``team_id`` as opaque string references, matching the operator audit-trail
posture (a target row may be deleted while its call log stays intact).
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Column, DateTime, Text
from sqlmodel import Field, SQLModel

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin

__all__ = ["McpCallLogRecordBase"]


class McpCallLogRecordBase(TableDerivedConstraintsMixin, SQLModel):
    """Shared columns for every module's MCP call-log table.

    A concrete subclass MUST set ``__tablename__`` and ``table=True``.
    """

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    server_id: str = Field(max_length=64, index=True)
    base_url: str = Field(max_length=512)
    action: str = Field(max_length=128)
    # 'ready' | 'error' | 'pending'
    status: str = Field(max_length=16)
    http_status: int | None = Field(default=None)
    latency_ms: int | None = Field(default=None)
    error_excerpt: str | None = Field(default=None, sa_column=Column(Text))
    target_id: str | None = Field(default=None, max_length=36, index=True)
    team_id: str | None = Field(default=None, max_length=36)
    called_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
        index=True,
    )
