"""084 -- rename workspace + target-tag-index unique constraints to the derived form (#26).

RFC-01 Phase 2 (domain tables). The workspace and target_tag_index concretes
now derive their unique-constraint names structurally from the concrete
``__tablename__`` via ``TabledUq``:

  uq_<module>_workspace_team_slug   -> uq_<module>_workspaces_team_slug
  uq_<module>_target_tag_source     -> uq_<module>_target_tag_index_target_tag_source

The other domain tables (investigation, message, pattern, project) carry no
named unique constraint, so they need no rename. Single-column foreign keys
keep the Postgres default ``<table>_<col>_fkey`` name and are untouched.

Guarded with ``IF EXISTS`` so a re-run, or a fresh database that already
carries the derived name, is a no-op.

Revision ID: 084_domain_uq_rename
Revises:     083_investigation_target_uq_rename
Create Date: 2026-07-21
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "084_domain_uq_rename"
down_revision: str | None = "083_investigation_target_uq_rename"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_vr_workspace_team_slug') THEN
                ALTER TABLE vr_workspaces
                    RENAME CONSTRAINT uq_vr_workspace_team_slug
                    TO uq_vr_workspaces_team_slug;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_malware_workspace_team_slug') THEN
                ALTER TABLE malware_workspaces
                    RENAME CONSTRAINT uq_malware_workspace_team_slug
                    TO uq_malware_workspaces_team_slug;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_vr_target_tag_source') THEN
                ALTER TABLE vr_target_tag_index
                    RENAME CONSTRAINT uq_vr_target_tag_source
                    TO uq_vr_target_tag_index_target_tag_source;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_malware_target_tag_source') THEN
                ALTER TABLE malware_target_tag_index
                    RENAME CONSTRAINT uq_malware_target_tag_source
                    TO uq_malware_target_tag_index_target_tag_source;
            END IF;
        END $$;
    """))


def downgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_vr_workspaces_team_slug') THEN
                ALTER TABLE vr_workspaces
                    RENAME CONSTRAINT uq_vr_workspaces_team_slug
                    TO uq_vr_workspace_team_slug;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_malware_workspaces_team_slug') THEN
                ALTER TABLE malware_workspaces
                    RENAME CONSTRAINT uq_malware_workspaces_team_slug
                    TO uq_malware_workspace_team_slug;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_vr_target_tag_index_target_tag_source') THEN
                ALTER TABLE vr_target_tag_index
                    RENAME CONSTRAINT uq_vr_target_tag_index_target_tag_source
                    TO uq_vr_target_tag_source;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_malware_target_tag_index_target_tag_source') THEN
                ALTER TABLE malware_target_tag_index
                    RENAME CONSTRAINT uq_malware_target_tag_index_target_tag_source
                    TO uq_malware_target_tag_source;
            END IF;
        END $$;
    """))
