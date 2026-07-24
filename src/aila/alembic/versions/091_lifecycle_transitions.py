"""091 -- agent lifecycle transition journal (RFC-10 step 1).

Creates ``lifecycle_transitions`` -- one row per agent-behavior
lifecycle stage transition (built -> evaluated -> production ->
rolled_back). Each row carries the prompt key + version, the from/to
stages, the actor + reason, and a ``metrics_snapshot_json`` blob holding
the eval verdict / report bundle (evaluate rows) or the restored target
version (rollback rows).

Columns match the SQLModel definition in platform/lifecycle/models.py so
``create_all`` (tests, fresh installs) matches the migrated schema. Index
names are prefixed ``ix_lifecycle_transitions_`` because Postgres index
names are database-scoped, not table-scoped. There is no FK to
``eval_runs`` -- the ``eval_run_id`` lives inside
``metrics_snapshot_json`` as an opaque string so an eval-row purge cannot
cascade-corrupt the lifecycle journal. Guarded with ``IF NOT EXISTS`` so
a re-run or a fresh database that already carries the table is a no-op.

Revision ID: 091_lifecycle_transitions
Revises:     090_eval_harness_tables
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "091_lifecycle_transitions"
down_revision: str | None = "090_eval_harness_tables"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS lifecycle_transitions (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            version VARCHAR(32) NOT NULL,
            from_stage VARCHAR(32) NOT NULL,
            to_stage VARCHAR(32) NOT NULL,
            actor VARCHAR(128) NOT NULL DEFAULT '',
            reason TEXT NOT NULL DEFAULT '',
            metrics_snapshot_json TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_lifecycle_transitions_key "
        "ON lifecycle_transitions (key);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_lifecycle_transitions_key_created_at "
        "ON lifecycle_transitions (key, created_at);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS "
        "ix_lifecycle_transitions_key_version_to_stage "
        "ON lifecycle_transitions (key, version, to_stage);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS lifecycle_transitions;"))
