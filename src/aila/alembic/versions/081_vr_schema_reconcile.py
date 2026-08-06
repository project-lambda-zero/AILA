"""081 -- reconcile VR module schema drift (model vs migration).

Two named UNIQUE constraints on VR module tables shared the same
un-prefixed name as their malware counterparts before malware was
prefixed in migration 068. Migration 068 renamed the malware-side
constraints; the VR-side constraints kept their generic names. This
migration prefixes both VR constraints so the model and the migrated
production database converge on the same names, matching the wider
per-module naming convention (CLAUDE.md Common Mistake #21).

Renames (guarded with ``IF EXISTS`` so a re-run on a database that
already carries the new names is a no-op):

  - ``vr_workspaces``: ``uq_workspace_team_slug`` -> ``uq_vr_workspace_team_slug``
  - ``vr_target_tag_index``: ``uq_target_tag_source`` -> ``uq_vr_target_tag_source``

No column or index shape changes are needed on the migration side: the
composite index built by migration 063 on
``vr_investigation_messages(investigation_id, auto_steering_key)``,
the partial index built by migration 058 on
``vr_investigations.is_favorite`` (``WHERE is_favorite = true``), and
the unbounded ``vr_findings.project_id TEXT`` column from migration
040 are already the production truth. The SQLModel models in
``src/aila/modules/vr/db_models/`` are being aligned to them in the
same commit so ``create_all`` (tests, fresh installs) matches
production.

Revision ID: 081_vr_schema_reconcile
Revises:     080_platform_schema_reconcile
Create Date: 2026-07-22
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "081_vr_schema_reconcile"
down_revision: str | None = "080_platform_schema_reconcile"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'uq_workspace_team_slug'
            ) THEN
                ALTER TABLE vr_workspaces
                    RENAME CONSTRAINT uq_workspace_team_slug
                    TO uq_vr_workspace_team_slug;
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'uq_target_tag_source'
            ) THEN
                ALTER TABLE vr_target_tag_index
                    RENAME CONSTRAINT uq_target_tag_source
                    TO uq_vr_target_tag_source;
            END IF;
        END $$;
    """))


def downgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'uq_vr_workspace_team_slug'
            ) THEN
                ALTER TABLE vr_workspaces
                    RENAME CONSTRAINT uq_vr_workspace_team_slug
                    TO uq_workspace_team_slug;
            END IF;
            IF EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'uq_vr_target_tag_source'
            ) THEN
                ALTER TABLE vr_target_tag_index
                    RENAME CONSTRAINT uq_vr_target_tag_source
                    TO uq_target_tag_source;
            END IF;
        END $$;
    """))
