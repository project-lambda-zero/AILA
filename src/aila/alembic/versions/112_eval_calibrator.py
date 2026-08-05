"""112 -- eval calibrator versions + score samples (RFC-08 step 3 / Tier D).

Backs the post-hoc :class:`Calibrator`: a per-``task_type`` recalibration
of the raw confidence numeric ``extract_confidence`` produces at the
gate, fitted from accept/reject review history and promoted only behind
an ECE-improvement + review-quorum gate (contract C7).

Two tables:

* ``eval_calibrator_versions`` -- versioned journal of fitted
  calibrators. Each row snapshots the fitted params (isotonic bin
  edges or the single temperature scalar) plus the ECE before and
  after applying it to the fit set. ``status`` starts at
  ``'candidate'``; promotion flips it to ``'active'`` and supersedes
  the prior active row for the same ``task_type``.
* ``eval_calibration_samples`` -- an audit trail of the raw
  ``(raw_confidence, correct)`` samples the trainer built from the
  accept/reject history. Assembled post-hoc during
  :func:`CalibrationTrainer.fit_and_propose`, NEVER written on the
  gate hot path.

Both tables carry composite indices scoped to the read patterns:
``(task_type, status)`` on versions so ``load_active_calibrator``
resolves in one keyed scan, ``(task_type, created_at)`` on samples so
retraining reads the most recent slice per task type without a full
scan. Guarded with IF NOT EXISTS to keep the ``db-init`` create_all +
alembic stamp path idempotent.

Revision ID: 112_eval_calibrator
Revises:     111_forensics_patterns
Create Date: 2026-08-05
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "112_eval_calibrator"
down_revision: str | None = "111_forensics_patterns"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS eval_calibrator_versions (
            id VARCHAR NOT NULL PRIMARY KEY,
            task_type VARCHAR(64) NOT NULL,
            method VARCHAR(32) NOT NULL,
            params_json TEXT NOT NULL DEFAULT '{}',
            ece_before FLOAT NOT NULL DEFAULT 0,
            ece_after FLOAT NOT NULL DEFAULT 0,
            sample_count INTEGER NOT NULL DEFAULT 0,
            status VARCHAR(16) NOT NULL DEFAULT 'candidate',
            superseded_by VARCHAR(64),
            actor VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_calibrator_versions_task_type "
        "ON eval_calibrator_versions (task_type);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_calibrator_versions_task_status "
        "ON eval_calibrator_versions (task_type, status);"
    ))

    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS eval_calibration_samples (
            id VARCHAR NOT NULL PRIMARY KEY,
            task_type VARCHAR(64) NOT NULL,
            outcome_kind VARCHAR(64) NOT NULL DEFAULT '',
            model_id VARCHAR(128) NOT NULL DEFAULT '',
            raw_confidence FLOAT NOT NULL DEFAULT 0,
            correct BOOLEAN NOT NULL DEFAULT FALSE,
            outcome_id VARCHAR(64),
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_calibration_samples_task_type "
        "ON eval_calibration_samples (task_type);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_calibration_samples_task_created "
        "ON eval_calibration_samples (task_type, created_at);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS eval_calibration_samples;"))
    op.execute(sa.text("DROP TABLE IF EXISTS eval_calibrator_versions;"))
