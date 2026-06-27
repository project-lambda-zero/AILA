"""028 -- create forensics module tables.

Adds all tables required by the forensics investigation module:
  - forensics_projects
  - forensics_project_evidence
  - forensics_artifacts
  - forensics_leads
  - forensics_investigations
  - forensics_agent_steps
  - forensics_writeups
  - forensics_answer_candidates

Revision ID: 028_forensics_tables
Revises: 027_drop_user_group_records
Create Date: 2026-04-14
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "028_forensics_tables"
down_revision: str | None = "027_drop_user_group_records"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "forensics_projects",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), server_default=""),
        sa.Column("system_id", sa.Integer(), nullable=False),
        sa.Column("evidence_directory", sa.Text(), nullable=False),
        sa.Column("status", sa.String(50), server_default="created"),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensics_projects_name", "forensics_projects", ["name"])
    op.create_index("ix_forensics_projects_system_id", "forensics_projects", ["system_id"])
    op.create_index("ix_forensics_projects_status", "forensics_projects", ["status"])
    op.create_index("ix_forensics_projects_team_id", "forensics_projects", ["team_id"])

    op.create_table(
        "forensics_project_evidence",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("evidence_type", sa.String(50), server_default="unknown"),
        sa.Column("file_hash_sha256", sa.Text(), nullable=True),
        sa.Column("size_bytes", sa.BigInteger(), nullable=True),
        sa.Column("metadata_json", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensics_evidence_project_id", "forensics_project_evidence", ["project_id"])
    op.create_index("ix_forensics_evidence_type", "forensics_project_evidence", ["evidence_type"])

    op.create_table(
        "forensics_artifacts",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("artifact_family", sa.String(50), nullable=False),
        sa.Column("artifact_type", sa.String(100), nullable=False),
        sa.Column("source_tool", sa.String(100), server_default=""),
        sa.Column("source_evidence_id", sa.Text(), nullable=True),
        sa.Column("data_json", sa.Text(), server_default="{}"),
        sa.Column("lead_score", sa.Float(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensics_artifacts_project_id", "forensics_artifacts", ["project_id"])
    op.create_index("ix_forensics_artifacts_family", "forensics_artifacts", ["artifact_family"])
    op.create_index("ix_forensics_artifacts_type", "forensics_artifacts", ["artifact_type"])

    op.create_table(
        "forensics_leads",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("artifact_id", sa.Text(), nullable=False),
        sa.Column("score", sa.Float(), server_default="0.0"),
        sa.Column("reason", sa.Text(), server_default=""),
        sa.Column("artifact_family", sa.String(50), server_default=""),
        sa.Column("related_artifact_ids_json", sa.Text(), server_default="[]"),
        sa.Column("question_families_json", sa.Text(), server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensics_leads_project_id", "forensics_leads", ["project_id"])
    op.create_index("ix_forensics_leads_artifact_id", "forensics_leads", ["artifact_id"])

    op.create_table(
        "forensics_investigations",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("question", sa.Text(), nullable=False),
        sa.Column("status", sa.String(50), server_default="pending"),
        sa.Column("max_attempts", sa.Integer(), server_default="10"),
        sa.Column("attempts_used", sa.Integer(), server_default="0"),
        sa.Column("final_answer", sa.Text(), nullable=True),
        sa.Column("confidence", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensics_inv_project_id", "forensics_investigations", ["project_id"])
    op.create_index("ix_forensics_inv_status", "forensics_investigations", ["status"])

    op.create_table(
        "forensics_agent_steps",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("investigation_id", sa.Text(), nullable=False),
        sa.Column("step_number", sa.Integer(), server_default="0"),
        sa.Column("action", sa.String(50), server_default="reasoning"),
        sa.Column("script_content", sa.Text(), nullable=True),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("stdout", sa.Text(), nullable=True),
        sa.Column("stderr", sa.Text(), nullable=True),
        sa.Column("exit_code", sa.Integer(), nullable=True),
        sa.Column("reasoning", sa.Text(), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensics_steps_inv_id", "forensics_agent_steps", ["investigation_id"])

    op.create_table(
        "forensics_writeups",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("investigation_id", sa.Text(), nullable=True),
        sa.Column("title", sa.String(512), server_default=""),
        sa.Column("content_markdown", sa.Text(), server_default=""),
        sa.Column("methodology", sa.Text(), server_default=""),
        sa.Column("artifacts_referenced_json", sa.Text(), server_default="[]"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensics_writeups_project_id", "forensics_writeups", ["project_id"])
    op.create_index("ix_forensics_writeups_inv_id", "forensics_writeups", ["investigation_id"])

    op.create_table(
        "forensics_answer_candidates",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("project_id", sa.Text(), nullable=False),
        sa.Column("investigation_id", sa.Text(), nullable=True),
        sa.Column("question_text", sa.Text(), nullable=False),
        sa.Column("answer_text", sa.Text(), server_default=""),
        sa.Column("confidence", sa.String(50), server_default="caveated"),
        sa.Column("primary_artifact_id", sa.Text(), nullable=True),
        sa.Column("corroboration_json", sa.Text(), server_default="[]"),
        sa.Column("format_hint", sa.String(255), server_default=""),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_forensics_answers_project_id", "forensics_answer_candidates", ["project_id"])
    op.create_index("ix_forensics_answers_inv_id", "forensics_answer_candidates", ["investigation_id"])


def downgrade() -> None:
    op.drop_table("forensics_answer_candidates")
    op.drop_table("forensics_writeups")
    op.drop_table("forensics_agent_steps")
    op.drop_table("forensics_investigations")
    op.drop_table("forensics_leads")
    op.drop_table("forensics_artifacts")
    op.drop_table("forensics_project_evidence")
    op.drop_table("forensics_projects")
