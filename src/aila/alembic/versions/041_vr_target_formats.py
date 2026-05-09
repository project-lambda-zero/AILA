"""041 — vulnerability research target ingestion formats and multi-machine layout.

Adds columns to ``vr_projects`` to support the redesigned target ingestion flow:

  * Multiple input sources: direct upload, git repository, HTTP URL.
  * Explicit target format hint (elf, pe_exe, apk, source_archive, ...).
  * Source-build metadata (vulnerable/patched refs, build command, artifact path).
  * Upload provenance (filename + SHA-256) used by the setup state handler when
    transferring the bytes to the analysis workstation.
  * Split of the single ``system_id`` into ``analysis_system_id`` (runs IDA) and
    ``poc_system_id`` (runs PoCs — may be a different machine, e.g. the host
    where the vulnerable build is installed).

Strictly additive — no columns are dropped or renamed. The pre-existing
``target_path`` column is retained but its meaning shifts: the setup handler
now writes the workstation-side path there after transferring the artefact,
instead of the user supplying a path directly.

Revision ID: 041_vr_target_formats
Revises: 040_vr_tables
Create Date: 2026-05-09
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "041_vr_target_formats"
down_revision: str | None = "040_vr_tables"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "vr_projects",
        sa.Column("input_source", sa.String(32), nullable=False, server_default="upload"),
    )
    op.add_column("vr_projects", sa.Column("target_format", sa.String(32), nullable=True))
    op.add_column("vr_projects", sa.Column("repo_url", sa.Text(), nullable=True))
    op.add_column("vr_projects", sa.Column("vulnerable_ref", sa.String(255), nullable=True))
    op.add_column("vr_projects", sa.Column("patched_ref", sa.String(255), nullable=True))
    op.add_column("vr_projects", sa.Column("build_command", sa.Text(), nullable=True))
    op.add_column("vr_projects", sa.Column("build_artifact", sa.String(512), nullable=True))
    op.add_column("vr_projects", sa.Column("upload_filename", sa.String(512), nullable=True))
    op.add_column("vr_projects", sa.Column("upload_sha256", sa.String(128), nullable=True))
    op.add_column("vr_projects", sa.Column("download_url", sa.Text(), nullable=True))
    op.add_column("vr_projects", sa.Column("analysis_system_id", sa.Integer(), nullable=True))
    op.add_column("vr_projects", sa.Column("poc_system_id", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("vr_projects", "poc_system_id")
    op.drop_column("vr_projects", "analysis_system_id")
    op.drop_column("vr_projects", "download_url")
    op.drop_column("vr_projects", "upload_sha256")
    op.drop_column("vr_projects", "upload_filename")
    op.drop_column("vr_projects", "build_artifact")
    op.drop_column("vr_projects", "build_command")
    op.drop_column("vr_projects", "patched_ref")
    op.drop_column("vr_projects", "vulnerable_ref")
    op.drop_column("vr_projects", "repo_url")
    op.drop_column("vr_projects", "target_format")
    op.drop_column("vr_projects", "input_source")
