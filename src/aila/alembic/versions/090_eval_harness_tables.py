"""090 -- eval harness tables (RFC-08 step 1).

Creates the two tables backing the eval runner:

- ``eval_benchmarks`` -- a named benchmark of pre-scored ``CaseOutcome``
  cases (predicted_verdict / verified_verdict / confidence per case,
  per version) plus a ``key`` naming the prompt those cases score.
- ``eval_runs`` -- one scoring event: which candidate prompt version was
  scored against which benchmark, which production version served as
  the baseline (nullable for a first-ever eval), the serialized
  ``EvalReport`` bundle, and the 'pass' / 'fail' verdict.

Columns match the SQLModel definitions in platform/eval/models.py so
``create_all`` (tests, fresh installs) matches the migrated schema.
Constraint and index names are prefixed ``eval_`` because Postgres
constraint names are database-scoped, not table-scoped -- unprefixed
names would collide with other modules over time. Guarded with
``IF NOT EXISTS`` so a re-run, or a fresh database that already carries
the tables, is a no-op.

Revision ID: 090_eval_harness_tables
Revises:     089_seal_prompt_content_hash
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "090_eval_harness_tables"
down_revision: str | None = "089_seal_prompt_content_hash"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS eval_benchmarks (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            name VARCHAR(256) NOT NULL,
            cases_json TEXT NOT NULL,
            created_by VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_benchmarks_key "
        "ON eval_benchmarks (key);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_benchmarks_key_created_at "
        "ON eval_benchmarks (key, created_at);"
    ))
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS eval_runs (
            id VARCHAR NOT NULL PRIMARY KEY,
            key VARCHAR(256) NOT NULL,
            candidate_version VARCHAR(32) NOT NULL,
            baseline_version VARCHAR(32),
            benchmark_id VARCHAR(64) NOT NULL
                REFERENCES eval_benchmarks (id),
            report_json TEXT NOT NULL,
            verdict VARCHAR(16) NOT NULL,
            actor VARCHAR(128) NOT NULL DEFAULT '',
            created_at TIMESTAMPTZ NOT NULL DEFAULT now()
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_runs_key "
        "ON eval_runs (key);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_eval_runs_key_created_at "
        "ON eval_runs (key, created_at);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS eval_runs;"))
    op.execute(sa.text("DROP TABLE IF EXISTS eval_benchmarks;"))
