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

Shared column set includes the observability join-keys ``investigation_id``
/ ``branch_id`` / ``turn_number`` (issue #39). They were vr-only until
RFC-04 Phase 1 unified the MCP call logger; both modules now carry them so a
call-log row joins back to the investigation, branch, and turn that made it.
Migration 082 added them to ``vr_mcp_call_log``; a later migration adds them
to ``malware_mcp_call_log``.

No FKs live on the base: the concrete columns declare only ``target_id`` /
``team_id`` as opaque string references, matching the operator audit-trail
posture (a target row may be deleted while its call log stays intact).
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Text
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
    error_excerpt: str | None = Field(default=None, sa_type=Text, sa_column_kwargs={"nullable": True})
    target_id: str | None = Field(default=None, max_length=36, index=True)
    team_id: str | None = Field(default=None, max_length=36)
    # RFC-11 provenance: which physical catalog row served this call.
    # ``None`` when the URL came from the ``env`` / ``config`` / ``default``
    # tiers of the resolver (the row-less pre-catalog paths). Indexed so
    # the operator dashboard joins call-log rows to catalog rows on this
    # key without a full scan.
    instance_id: str | None = Field(default=None, max_length=128, index=True)
    # #39 observability join-keys: correlate a call-log row to the
    # investigation / branch / turn that made it. Stamped from the ambient
    # correlation ContextVar by the MCP call logger.
    investigation_id: str | None = Field(default=None, max_length=36, index=True)
    branch_id: str | None = Field(default=None, max_length=36, index=True)
    turn_number: int | None = Field(default=None)
    called_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
        index=True,
    )
