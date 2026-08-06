"""099 -- retrieval eval record-replay tables (RFC-12 criterion 7).

Backs the retrieval-quality eval harness: a benchmark of recorded queries
with per-query ground-truth relevant ids, and a scored replay event with
the beats()-gate verdict. Mirrors the prompt-eval tables (090). Columns
match platform/eval/retrieval_models.py so create_all (tests, fresh
installs) matches the migrated schema. Names prefixed retrieval_eval_ to
stay unique in the database-scoped Postgres namespace. Guarded with IF NOT
EXISTS.

Revision ID: 099_retrieval_eval_tables
Revises:     098_mcp_call_log_instance_id
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "099_retrieval_eval_tables"
down_revision: str | None = "098_mcp_call_log_instance_id"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS retrieval_eval_benchmarks (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            name VARCHAR(256) NOT NULL,
            k INTEGER NOT NULL DEFAULT 10,
            cases_json TEXT NOT NULL,
            created_by VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_retrieval_eval_benchmarks_key "
        "ON retrieval_eval_benchmarks (key);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_retrieval_eval_benchmarks_key_created_at "
        "ON retrieval_eval_benchmarks (key, created_at);"
    ))
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS retrieval_eval_runs (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            benchmark_id VARCHAR(64) NOT NULL
                REFERENCES retrieval_eval_benchmarks(id),
            candidate_label VARCHAR(64) NOT NULL,
            baseline_label VARCHAR(64),
            report_json TEXT NOT NULL,
            verdict VARCHAR(16) NOT NULL,
            actor VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_retrieval_eval_runs_key "
        "ON retrieval_eval_runs (key);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_retrieval_eval_runs_key_created_at "
        "ON retrieval_eval_runs (key, created_at);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS retrieval_eval_runs;"))
    op.execute(sa.text("DROP TABLE IF EXISTS retrieval_eval_benchmarks;"))
