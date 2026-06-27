"""042 -- VR v0.3 foundation: workspaces, targets, target tag index.

Per D-49: Workspace = thematic project (e.g. "Browser engines").
Per D-50: Investigation has a primary target; targets are first-class.
Per D-51: capability_profile_json populated by M3.T-2 through M3.T-4
          enrichment pipeline.
Per D-52: Multi-dimensional tag filtering via vr_target_tag_index.

Additive -- does not touch vr_projects or vr_findings yet. The follow-up
migration (043) will refactor vr_projects to reference vr_targets.target_id
and drop the redundant target columns from vr_projects (target_class,
target_path, binary_id, patched_path, patched_binary_id, input_source,
target_format, repo_url, vulnerable_ref, patched_ref, build_command,
build_artifact, upload_filename, upload_sha256, download_url,
source_available, mitigations_json). Per D-53 there is no v0.1 legacy
to preserve, so the eventual refactor is destructive.

Revision ID: 042_vr_workspaces_targets
Revises: 041_vr_target_formats
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "042_vr_workspaces_targets"
down_revision: str | None = "041_vr_target_formats"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "vr_workspaces",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(128), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column("theme", sa.String(64), nullable=False, server_default="custom"),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("team_id", "slug", name="uq_workspace_team_slug"),
    )
    op.create_index("ix_vr_workspaces_team_id", "vr_workspaces", ["team_id"])
    op.create_index("ix_vr_workspaces_name", "vr_workspaces", ["name"])
    op.create_index("ix_vr_workspaces_slug", "vr_workspaces", ["slug"])
    op.create_index("ix_vr_workspaces_status", "vr_workspaces", ["status"])

    op.create_table(
        "vr_targets",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "workspace_id",
            sa.String(64),
            sa.ForeignKey("vr_workspaces.id"),
            nullable=False,
        ),
        sa.Column("team_id", sa.Text(), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=False),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("descriptor_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("primary_language", sa.String(32), nullable=True),
        sa.Column("secondary_languages_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("capability_profile_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("tags_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("enrichment_status", sa.String(32), nullable=False, server_default="unenriched"),
        sa.Column("last_enriched_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_vr_targets_workspace_id", "vr_targets", ["workspace_id"])
    op.create_index("ix_vr_targets_team_id", "vr_targets", ["team_id"])
    op.create_index("ix_vr_targets_kind", "vr_targets", ["kind"])
    op.create_index("ix_vr_targets_status", "vr_targets", ["status"])
    op.create_index("ix_vr_targets_enrichment_status", "vr_targets", ["enrichment_status"])

    op.create_table(
        "vr_target_tag_index",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column(
            "target_id",
            sa.String(64),
            sa.ForeignKey("vr_targets.id"),
            nullable=False,
        ),
        sa.Column(
            "workspace_id",
            sa.String(64),
            sa.ForeignKey("vr_workspaces.id"),
            nullable=False,
        ),
        sa.Column("tag", sa.String(128), nullable=False),
        sa.Column("tag_source", sa.String(32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("target_id", "tag", "tag_source", name="uq_target_tag_source"),
    )
    op.create_index("ix_vr_target_tag_index_target_id", "vr_target_tag_index", ["target_id"])
    op.create_index("ix_vr_target_tag_index_workspace_id", "vr_target_tag_index", ["workspace_id"])
    op.create_index("ix_vr_target_tag_index_tag", "vr_target_tag_index", ["tag"])


def downgrade() -> None:
    op.drop_index("ix_vr_target_tag_index_tag", table_name="vr_target_tag_index")
    op.drop_index("ix_vr_target_tag_index_workspace_id", table_name="vr_target_tag_index")
    op.drop_index("ix_vr_target_tag_index_target_id", table_name="vr_target_tag_index")
    op.drop_table("vr_target_tag_index")

    op.drop_index("ix_vr_targets_enrichment_status", table_name="vr_targets")
    op.drop_index("ix_vr_targets_status", table_name="vr_targets")
    op.drop_index("ix_vr_targets_kind", table_name="vr_targets")
    op.drop_index("ix_vr_targets_team_id", table_name="vr_targets")
    op.drop_index("ix_vr_targets_workspace_id", table_name="vr_targets")
    op.drop_table("vr_targets")

    op.drop_index("ix_vr_workspaces_status", table_name="vr_workspaces")
    op.drop_index("ix_vr_workspaces_slug", table_name="vr_workspaces")
    op.drop_index("ix_vr_workspaces_name", table_name="vr_workspaces")
    op.drop_index("ix_vr_workspaces_team_id", table_name="vr_workspaces")
    op.drop_table("vr_workspaces")
