"""143 -- VR benchmark-measurement result tables.

Adds ``vr_eval_suite_runs`` and ``vr_eval_task_results`` for the VR
capability-measurement harness (one row per measurement run over a public
benchmark suite, one row per benchmark task scored from its investigation).

Creation uses ``IF NOT EXISTS`` so a database where ``create_all`` already
ran on a fresh boot is left intact.

Revision ID: 143_vr_eval_suites
Revises: 142_explain_cache_records
Create Date: 2026-10-30
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "143_vr_eval_suites"
down_revision: str | None = "142_explain_cache_records"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS vr_eval_suite_runs (
            id TEXT PRIMARY KEY,
            suite VARCHAR(64) NOT NULL,
            status VARCHAR(16) NOT NULL DEFAULT 'pending',
            requested_by VARCHAR(128),
            team_id TEXT,
            total_count INTEGER NOT NULL DEFAULT 0,
            solved_count INTEGER NOT NULL DEFAULT 0,
            total_cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            finished_at TIMESTAMPTZ
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_eval_suite_runs_suite "
        "ON vr_eval_suite_runs (suite)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_eval_suite_runs_status "
        "ON vr_eval_suite_runs (status)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_eval_suite_runs_team_id "
        "ON vr_eval_suite_runs (team_id)"
    ))

    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS vr_eval_task_results (
            id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL REFERENCES vr_eval_suite_runs(id) ON DELETE CASCADE,
            task_id VARCHAR(128) NOT NULL,
            name TEXT NOT NULL DEFAULT '',
            category VARCHAR(64),
            investigation_id VARCHAR(64),
            status VARCHAR(16) NOT NULL DEFAULT 'pending',
            solved BOOLEAN NOT NULL DEFAULT false,
            cost_usd DOUBLE PRECISION NOT NULL DEFAULT 0,
            polarity VARCHAR(16),
            reference_answer TEXT NOT NULL DEFAULT '',
            started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            finished_at TIMESTAMPTZ,
            CONSTRAINT uq_vr_eval_task_result_run_task UNIQUE (run_id, task_id)
        )
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_eval_task_results_run_id "
        "ON vr_eval_task_results (run_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_eval_task_results_investigation_id "
        "ON vr_eval_task_results (investigation_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_vr_eval_task_results_status "
        "ON vr_eval_task_results (status)"
    ))
    op.execute(sa.text("""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aila_app') THEN
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON vr_eval_suite_runs TO aila_app';
                EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON vr_eval_task_results TO aila_app';
            END IF;
        END
        $$;
    """))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS vr_eval_task_results"))
    op.execute(sa.text("DROP TABLE IF EXISTS vr_eval_suite_runs"))
