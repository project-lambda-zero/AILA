"""040 -- create vulnerability research module tables.

Adds the two tables required by the vulnerability research (VR) module:
  - vr_projects        -- per-target research project with budget/obligation snapshot
  - vr_findings        -- confirmed vulnerabilities with triage, PoC, and disclosure state

Revision ID: 040_vr_tables
Revises: 039_forensics_directive_controls
Create Date: 2026-05-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "040_vr_tables"
down_revision: str | None = "039_forensics_directive_controls"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_projects",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("target_class", sa.String(32), nullable=False, server_default="native"),
        sa.Column("target_path", sa.Text(), nullable=True),
        sa.Column("binary_id", sa.String(128), nullable=True),
        sa.Column("patched_path", sa.Text(), nullable=True),
        sa.Column("patched_binary_id", sa.String(128), nullable=True),
        sa.Column("source_available", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("context_notes", sa.Text(), nullable=False, server_default=""),
        sa.Column("status", sa.String(32), nullable=False, server_default="created"),
        sa.Column("mitigations_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("budget_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("obligations_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vr_projects_team_id", "vr_projects", ["team_id"])
    op.create_index("ix_vr_projects_name", "vr_projects", ["name"])
    op.create_index("ix_vr_projects_cve_id", "vr_projects", ["cve_id"])
    op.create_index("ix_vr_projects_target_class", "vr_projects", ["target_class"])
    op.create_index("ix_vr_projects_status", "vr_projects", ["status"])

    op.create_table(
        "vr_findings",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column("crash_type", sa.String(64), nullable=True),
        sa.Column("crash_signature", sa.String(128), nullable=True),
        sa.Column("root_cause", sa.Text(), nullable=False, server_default=""),
        sa.Column("vulnerable_function", sa.String(255), nullable=True),
        sa.Column("poc_code", sa.Text(), nullable=True),
        sa.Column("poc_language", sa.String(32), nullable=True),
        sa.Column("poc_reliability", sa.String(16), nullable=True),
        sa.Column("asan_report", sa.Text(), nullable=True),
        sa.Column("cvss_vector", sa.String(128), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cwe_id", sa.String(16), nullable=True),
        sa.Column("advisory_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("disclosure_status", sa.String(32), nullable=False, server_default="undisclosed"),
        sa.Column("vendor_contact", sa.Text(), nullable=True),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("embargo_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("assigned_cve_id", sa.String(32), nullable=True),
        sa.Column("patch_version", sa.String(64), nullable=True),
        sa.Column("evidence_refs_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("obligations_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vr_findings_project_id", "vr_findings", ["project_id"])
    op.create_index("ix_vr_findings_team_id", "vr_findings", ["team_id"])
    op.create_index("ix_vr_findings_crash_type", "vr_findings", ["crash_type"])
    op.create_index("ix_vr_findings_disclosure_status", "vr_findings", ["disclosure_status"])


def downgrade() -> None:
    op.drop_index("ix_vr_findings_disclosure_status", table_name="vr_findings")
    op.drop_index("ix_vr_findings_crash_type", table_name="vr_findings")
    op.drop_index("ix_vr_findings_team_id", table_name="vr_findings")
    op.drop_index("ix_vr_findings_project_id", table_name="vr_findings")
    op.drop_table("vr_findings")

    op.drop_index("ix_vr_projects_status", table_name="vr_projects")
    op.drop_index("ix_vr_projects_target_class", table_name="vr_projects")
    op.drop_index("ix_vr_projects_cve_id", table_name="vr_projects")
    op.drop_index("ix_vr_projects_name", table_name="vr_projects")
    op.drop_index("ix_vr_projects_team_id", table_name="vr_projects")
    op.drop_table("vr_projects")
