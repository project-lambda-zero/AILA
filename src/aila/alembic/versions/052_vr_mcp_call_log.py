"""052 -- VR MCP call log.

Every forward() through audit_mcp_bridge or ida_bridge writes one row so
operators have a live audit trail of what the platform delegated to
which workstation, with latency, outcome, and an error excerpt when the
MCP call failed.

The table is intentionally narrow -- no full request/response bodies, no
free-form metadata. The point is operator visibility ("what was just
called, did it succeed, how long did it take"), not full IR. Detailed
payloads stay in worker logs.

Revision ID: 052_vr_mcp_call_log
Revises: 051_vr_target_ingestion
Create Date: 2026-05-18
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "052_vr_mcp_call_log"
down_revision: str | None = "051_vr_target_ingestion"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_mcp_call_log",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("server_id", sa.String(64), nullable=False),
        sa.Column("base_url", sa.String(512), nullable=False),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("error_excerpt", sa.Text(), nullable=True),
        sa.Column("target_id", sa.String(36), nullable=True),
        sa.Column("team_id", sa.String(36), nullable=True),
        sa.Column(
            "called_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_vr_mcp_call_log_called_at",
        "vr_mcp_call_log",
        ["called_at"],
    )
    op.create_index(
        "ix_vr_mcp_call_log_server_id",
        "vr_mcp_call_log",
        ["server_id"],
    )
    op.create_index(
        "ix_vr_mcp_call_log_target_id",
        "vr_mcp_call_log",
        ["target_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_vr_mcp_call_log_target_id", "vr_mcp_call_log")
    op.drop_index("ix_vr_mcp_call_log_server_id", "vr_mcp_call_log")
    op.drop_index("ix_vr_mcp_call_log_called_at", "vr_mcp_call_log")
    op.drop_table("vr_mcp_call_log")
