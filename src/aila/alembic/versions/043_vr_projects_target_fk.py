"""043 -- Refactor vr_projects to reference vr_targets; drop legacy target columns.

Per D-53 (no legacy v0.1 backward compat). Schema unification: target
identity moves from vr_projects to vr_targets. vr_projects keeps only
project-scoped fields (status, budget, obligations, context, machine
assignments).

vr_findings also gets a nullable target_id FK for v0.3 fuzz findings that
exist standalone without a project. v0.1 N-day findings continue to use
project_id as their primary scoping.

NOTE: Both vr_projects and vr_findings are empty at migration time
(verified 0 rows). Destructive column drops are safe.

Revision ID: 043_vr_projects_target_fk
Revises: 042_vr_workspaces_targets
Create Date: 2026-05-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "043_vr_projects_target_fk"
down_revision: str | None = "042_vr_workspaces_targets"
branch_labels = None
depends_on = None


_LEGACY_PROJECT_COLS: list[str] = [
    "target_class", "target_path", "binary_id", "patched_path", "patched_binary_id",
    "source_available", "input_source", "target_format", "repo_url",
    "vulnerable_ref", "patched_ref", "build_command", "build_artifact",
    "upload_filename", "upload_sha256", "download_url", "mitigations_json",
]


def upgrade() -> None:
    op.drop_index("ix_vr_projects_target_class", table_name="vr_projects")
    for col in _LEGACY_PROJECT_COLS:
        op.drop_column("vr_projects", col)

    op.add_column(
        "vr_projects",
        sa.Column(
            "target_id",
            sa.String(64),
            sa.ForeignKey("vr_targets.id"),
            nullable=False,
            server_default="",
        ),
    )
    op.alter_column("vr_projects", "target_id", server_default=None)
    op.create_index("ix_vr_projects_target_id", "vr_projects", ["target_id"])

    op.add_column(
        "vr_projects",
        sa.Column(
            "patched_target_id",
            sa.String(64),
            sa.ForeignKey("vr_targets.id"),
            nullable=True,
        ),
    )
    op.create_index("ix_vr_projects_patched_target_id", "vr_projects", ["patched_target_id"])

    op.add_column(
        "vr_findings",
        sa.Column(
            "target_id",
            sa.String(64),
            sa.ForeignKey("vr_targets.id"),
            nullable=True,
        ),
    )
    op.create_index("ix_vr_findings_target_id", "vr_findings", ["target_id"])


def downgrade() -> None:
    op.drop_index("ix_vr_findings_target_id", table_name="vr_findings")
    op.drop_column("vr_findings", "target_id")

    op.drop_index("ix_vr_projects_patched_target_id", table_name="vr_projects")
    op.drop_column("vr_projects", "patched_target_id")
    op.drop_index("ix_vr_projects_target_id", table_name="vr_projects")
    op.drop_column("vr_projects", "target_id")

    op.add_column("vr_projects", sa.Column("target_class", sa.String(32), nullable=False, server_default="native"))
    op.add_column("vr_projects", sa.Column("target_path", sa.Text(), nullable=True))
    op.add_column("vr_projects", sa.Column("binary_id", sa.String(128), nullable=True))
    op.add_column("vr_projects", sa.Column("patched_path", sa.Text(), nullable=True))
    op.add_column("vr_projects", sa.Column("patched_binary_id", sa.String(128), nullable=True))
    op.add_column("vr_projects", sa.Column("source_available", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("vr_projects", sa.Column("input_source", sa.String(32), nullable=False, server_default="upload"))
    op.add_column("vr_projects", sa.Column("target_format", sa.String(32), nullable=True))
    op.add_column("vr_projects", sa.Column("repo_url", sa.Text(), nullable=True))
    op.add_column("vr_projects", sa.Column("vulnerable_ref", sa.String(255), nullable=True))
    op.add_column("vr_projects", sa.Column("patched_ref", sa.String(255), nullable=True))
    op.add_column("vr_projects", sa.Column("build_command", sa.Text(), nullable=True))
    op.add_column("vr_projects", sa.Column("build_artifact", sa.String(512), nullable=True))
    op.add_column("vr_projects", sa.Column("upload_filename", sa.String(512), nullable=True))
    op.add_column("vr_projects", sa.Column("upload_sha256", sa.String(128), nullable=True))
    op.add_column("vr_projects", sa.Column("download_url", sa.Text(), nullable=True))
    op.add_column("vr_projects", sa.Column("mitigations_json", sa.Text(), nullable=False, server_default="{}"))
    op.create_index("ix_vr_projects_target_class", "vr_projects", ["target_class"])
