"""096 -- lifecycle canary/shadow assignments (RFC-10 steps 1-2).

Backs the shadow + canary stages of the agent development lifecycle. A
shadow row registers a candidate version for comparison without production
traffic; a canary row routes a stable cohort fraction of new investigations
to a candidate; a drift or cost spike flips the active canary to a held
state. resolve_version_for_investigation reads the active canary and buckets
by a hash of the investigation id. Columns match
platform/lifecycle/assignments.py so create_all (tests, fresh installs)
matches the migrated schema. Guarded with IF NOT EXISTS.

Revision ID: 096_lifecycle_canary_assignments
Revises:     095_investigation_prompt_pins
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "096_lifecycle_canary_assignments"
down_revision: str | None = "095_investigation_prompt_pins"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS lifecycle_canary_assignments (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            kind VARCHAR(16) NOT NULL,
            version VARCHAR(32) NOT NULL,
            cohort_percent INTEGER,
            state VARCHAR(16) NOT NULL DEFAULT 'active',
            actor VARCHAR(128) NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            last_signal_json TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_lifecycle_canary_assignments_key "
        "ON lifecycle_canary_assignments (key);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS "
        "ix_lifecycle_canary_assignments_key_kind_state "
        "ON lifecycle_canary_assignments (key, kind, state);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS "
        "ix_lifecycle_canary_assignments_key_created_at "
        "ON lifecycle_canary_assignments (key, created_at);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS lifecycle_canary_assignments;"))
