"""102 -- investigation_ledger: the shared blackboard (RFC-13, #68).

One append-only table per investigation. Every branch appends discoveries,
requests, decisions, notes, and objective entries; every branch reads.
Objectives are tagged entries (objective_key + owner_branch_id + status),
folded by a read view, so there is no separate objective table. The unique
(investigation_id, idempotency_key) constraint makes LedgerService.append
idempotent under ARQ retries; NULL keys stay distinct so non-idempotent
appends never collide. Columns match InvestigationLedgerRecord in
platform/services/ledger.py so create_all (tests, fresh installs) matches
the migrated schema. Additive and guarded with IF NOT EXISTS.

Revision ID: 102_investigation_ledger
Revises:     101_workflow_cursor_join_keys
Create Date: 2026-07-25
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "102_investigation_ledger"
down_revision: str | None = "101_workflow_cursor_join_keys"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "CREATE TABLE IF NOT EXISTS investigation_ledger ("
        " id SERIAL PRIMARY KEY,"
        " investigation_id VARCHAR(64) NOT NULL,"
        " author_branch_id VARCHAR(64) NOT NULL,"
        " kind VARCHAR(32) NOT NULL,"
        " payload_json TEXT NOT NULL,"
        " objective_key VARCHAR(128),"
        " owner_branch_id VARCHAR(64),"
        " status VARCHAR(32),"
        " supersedes_id INTEGER,"
        " idempotency_key VARCHAR(128),"
        " created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
        " CONSTRAINT uq_investigation_ledger_idem"
        " UNIQUE (investigation_id, idempotency_key)"
        ")"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_investigation_ledger_investigation_id "
        "ON investigation_ledger (investigation_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_investigation_ledger_objective_key "
        "ON investigation_ledger (objective_key)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_investigation_ledger_kind "
        "ON investigation_ledger (kind)"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS investigation_ledger"))
