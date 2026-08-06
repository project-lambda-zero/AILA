"""083 -- rename investigation_target unique constraints to the derived form (#26).

RFC-01 Phase 2 derives every constraint name structurally from the concrete
``__tablename__`` via ``TabledUq``. The investigation_target join tables carried
a hand-written name (``uq_<module>_investigation_target``) that does not match
the derived ``uq_<tablename>_investigation_target``. Rename both so the model
(``create_all`` on fresh installs / tests) and the migrated production database
converge on the same name.

Guarded with ``IF EXISTS`` so a re-run, or a fresh database that already carries
the derived name, is a no-op.

Revision ID: 083_investigation_target_uq_rename
Revises:     082_observability_join_keys
Create Date: 2026-07-21
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "083_investigation_target_uq_rename"
down_revision: str | None = "082_observability_join_keys"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_vr_investigation_target') THEN
                ALTER TABLE vr_investigation_targets
                    RENAME CONSTRAINT uq_vr_investigation_target
                    TO uq_vr_investigation_targets_investigation_target;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_malware_investigation_target') THEN
                ALTER TABLE malware_investigation_targets
                    RENAME CONSTRAINT uq_malware_investigation_target
                    TO uq_malware_investigation_targets_investigation_target;
            END IF;
        END $$;
    """))


def downgrade() -> None:
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_vr_investigation_targets_investigation_target') THEN
                ALTER TABLE vr_investigation_targets
                    RENAME CONSTRAINT uq_vr_investigation_targets_investigation_target
                    TO uq_vr_investigation_target;
            END IF;
            IF EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_malware_investigation_targets_investigation_target') THEN
                ALTER TABLE malware_investigation_targets
                    RENAME CONSTRAINT uq_malware_investigation_targets_investigation_target
                    TO uq_malware_investigation_target;
            END IF;
        END $$;
    """))
