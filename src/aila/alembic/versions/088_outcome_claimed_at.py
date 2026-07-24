"""088 -- add claimed_at to outcome tables (RFC-03 Phase 6b reclaim).

The dispatch claim flips dispatch_status to 'claimed'. Without a claim
timestamp a dispatcher that crashes after winning the claim strands the
row at 'claimed' forever (retry sees CLAIMED and skips). claimed_at lets
the next dispatch attempt tell a live claim from a stranded one and
reclaim the stranded row. Nullable: NULL until first claimed. The
SQLModel base OutcomeRecordBase is updated in the same commit so
create_all (tests, fresh installs) matches the migrated schema.

Guarded with IF NOT EXISTS so a re-run, or a fresh create_all database
that already carries the column, is a no-op.

Revision ID: 088_outcome_claimed_at
Revises:     087_prompt_version_store
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "088_outcome_claimed_at"
down_revision: str | None = "087_prompt_version_store"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None

_TABLES = ("vr_investigation_outcomes", "malware_investigation_outcomes")


def upgrade() -> None:
    for table in _TABLES:
        op.execute(sa.text(
            f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ"
        ))


def downgrade() -> None:
    for table in _TABLES:
        op.execute(sa.text(
            f"ALTER TABLE {table} DROP COLUMN IF EXISTS claimed_at"
        ))
