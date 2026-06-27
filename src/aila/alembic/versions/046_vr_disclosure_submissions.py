"""046 -- VR disclosure submissions (Disclosure Lifecycle plan).

Adds one new table ``vr_disclosure_submissions`` capturing the
per-(finding, track) submission lifecycle. Built-in tracks are
in-process (no track table); operator selects from the
``/vr/disclosure-tracks`` registry endpoint.

Revision ID: 046_vr_disclosure_submissions
Revises: 045_vr_patterns
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "046_vr_disclosure_submissions"
down_revision: str | None = "045_vr_patterns"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_disclosure_submissions",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column(
            "finding_id", sa.String(64),
            sa.ForeignKey("vr_findings.id"), nullable=False,
        ),
        sa.Column(
            "workspace_id", sa.String(64),
            sa.ForeignKey("vr_workspaces.id"), nullable=False,
        ),
        sa.Column("track_id", sa.String(64), nullable=False),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="drafted"),
        sa.Column("poc_tier", sa.String(24), nullable=False, server_default="no_poc"),
        sa.Column("severity_rating", sa.String(64), nullable=True),
        sa.Column("embargo_days_used", sa.Integer(), nullable=True),
        sa.Column("embargo_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("vendor_reference", sa.String(128), nullable=True),
        sa.Column("bounty_awarded_usd", sa.Float(), nullable=True),
        sa.Column("rendered_submission_body", sa.Text(), nullable=True),
        sa.Column(
            "rendered_submission_format", sa.String(16),
            nullable=False, server_default="markdown",
        ),
        sa.Column("last_rendered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "rendered_submission_metadata_json", sa.Text(),
            nullable=False, server_default="{}",
        ),
        sa.Column("notes", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "validation_errors_json", sa.Text(),
            nullable=False, server_default="[]",
        ),
        sa.Column(
            "created_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )
    op.create_index(
        "ix_vr_disclosure_submissions_team_id",
        "vr_disclosure_submissions", ["team_id"],
    )
    op.create_index(
        "ix_vr_disclosure_submissions_finding_id",
        "vr_disclosure_submissions", ["finding_id"],
    )
    op.create_index(
        "ix_vr_disclosure_submissions_workspace_id",
        "vr_disclosure_submissions", ["workspace_id"],
    )
    op.create_index(
        "ix_vr_disclosure_submissions_track_id",
        "vr_disclosure_submissions", ["track_id"],
    )
    op.create_index(
        "ix_vr_disclosure_submissions_kind",
        "vr_disclosure_submissions", ["kind"],
    )
    op.create_index(
        "ix_vr_disclosure_submissions_status",
        "vr_disclosure_submissions", ["status"],
    )
    op.create_index(
        "ix_vr_disclosure_submissions_embargo_until",
        "vr_disclosure_submissions", ["embargo_until"],
    )
    op.create_index(
        "ix_vr_disclosure_submissions_vendor_reference",
        "vr_disclosure_submissions", ["vendor_reference"],
    )


def downgrade() -> None:
    for ix in (
        "ix_vr_disclosure_submissions_vendor_reference",
        "ix_vr_disclosure_submissions_embargo_until",
        "ix_vr_disclosure_submissions_status",
        "ix_vr_disclosure_submissions_kind",
        "ix_vr_disclosure_submissions_track_id",
        "ix_vr_disclosure_submissions_workspace_id",
        "ix_vr_disclosure_submissions_finding_id",
        "ix_vr_disclosure_submissions_team_id",
    ):
        op.drop_index(ix, table_name="vr_disclosure_submissions")
    op.drop_table("vr_disclosure_submissions")
