"""051 -- VR target auto-ingestion (v0.4.5).

Backend now ingests every target transparently. Operator never provides
or sees MCP-internal ids. Adds:

  analysis_state           -- pending / ingesting / ready / failed
  analysis_state_message   -- operator-visible progress / error string
  analysis_started_at      -- when the ingestion job kicked off
  analysis_completed_at    -- when it finished
  _mcp_handles_json        -- backend-only: audit_mcp index_id + ida binary_id
                              etc. Underscore prefix marks 'internal -- never
                              exposed in contracts or UI'.

No backward compatibility. Existing rows are reset to ``pending`` so the
new ingestion pipeline owns the lifecycle. Legacy descriptor fields
(audit_mcp_index_id, binary_id) are stripped -- they were never operator-
fillable.

Revision ID: 051_vr_target_ingestion
Revises: 050_vr_cve_records
Create Date: 2026-05-17
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "051_vr_target_ingestion"
down_revision: str | None = "050_vr_cve_records"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vr_targets",
        sa.Column(
            "analysis_state",
            sa.String(24),
            nullable=False,
            server_default="pending",
        ),
    )
    op.add_column(
        "vr_targets",
        sa.Column("analysis_state_message", sa.Text(), nullable=True),
    )
    op.add_column(
        "vr_targets",
        sa.Column(
            "analysis_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "vr_targets",
        sa.Column(
            "analysis_completed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "vr_targets",
        sa.Column(
            "_mcp_handles_json",
            sa.Text(),
            nullable=False,
            server_default="{}",
        ),
    )
    op.create_index(
        "ix_vr_targets_analysis_state",
        "vr_targets",
        ["analysis_state"],
    )

    # Strip legacy descriptor fields that were never operator-fillable.
    op.execute(
        """
        UPDATE vr_targets
        SET descriptor_json = (
            descriptor_json::jsonb
            - 'audit_mcp_index_id'
            - 'binary_id'
            - 'kernel_image_id'
        )::text;
        """,
    )

    # Drop the now-defunct enrichment_status column.
    # The new analysis_state covers the operator-facing lifecycle and
    # the old column duplicated half of it with worse names.
    op.drop_column("vr_targets", "enrichment_status")


def downgrade() -> None:
    op.add_column(
        "vr_targets",
        sa.Column(
            "enrichment_status",
            sa.String(24),
            nullable=False,
            server_default="unenriched",
        ),
    )
    op.drop_index("ix_vr_targets_analysis_state", table_name="vr_targets")
    op.drop_column("vr_targets", "_mcp_handles_json")
    op.drop_column("vr_targets", "analysis_completed_at")
    op.drop_column("vr_targets", "analysis_started_at")
    op.drop_column("vr_targets", "analysis_state_message")
    op.drop_column("vr_targets", "analysis_state")
