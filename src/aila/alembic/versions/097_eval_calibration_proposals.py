"""097 -- eval calibration proposals (RFC-08 step 2).

Backs the CalibrationProposer: a per-outcome_kind confidence-threshold
adjustment aggregated from accept/reject review history, stored as a
versioned and reversible proposal (status active / superseded / reverted).
Proposals are advisory -- application goes through the eval gate and the
lifecycle, never auto-applied. Columns match platform/eval/calibration.py
so create_all (tests, fresh installs) matches the migrated schema. Guarded
with IF NOT EXISTS.

Revision ID: 097_eval_calibration_proposals
Revises:     096_lifecycle_canary_assignments
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "097_eval_calibration_proposals"
down_revision: str | None = "096_lifecycle_canary_assignments"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS eval_calibration_proposals (
            id VARCHAR NOT NULL PRIMARY KEY,
            outcome_kind VARCHAR(64) NOT NULL,
            before_threshold FLOAT NOT NULL,
            after_threshold FLOAT NOT NULL,
            approve_count INTEGER NOT NULL DEFAULT 0,
            reject_count INTEGER NOT NULL DEFAULT 0,
            mean_confidence_reject FLOAT NOT NULL DEFAULT 0,
            mean_confidence_approve FLOAT NOT NULL DEFAULT 0,
            reasoning TEXT NOT NULL DEFAULT '',
            evidence_json TEXT NOT NULL DEFAULT '{}',
            status VARCHAR(16) NOT NULL DEFAULT 'active',
            superseded_by VARCHAR(64),
            reverted_from VARCHAR(64),
            actor VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_calibration_proposals_outcome_kind "
        "ON eval_calibration_proposals (outcome_kind);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_calibration_proposals_kind_created_at "
        "ON eval_calibration_proposals (outcome_kind, created_at);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_calibration_proposals_status "
        "ON eval_calibration_proposals (status);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS eval_calibration_proposals;"))
