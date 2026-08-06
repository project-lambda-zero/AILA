"""117 -- lifecycle_shadow_reports (RFC-10 shadow-runner G2).

Adds ``lifecycle_shadow_reports``, the aggregate report row produced by
:func:`aila.platform.lifecycle.shadow.run_shadow` when an operator runs
the off-path replay comparison for a shadowed candidate. One row
captures ``sample_attempted`` / ``sample_succeeded``, the mean
faithfulness + determinism across successful replays, a regression
counter (samples whose faithfulness fell below the configured floor),
and a JSON blob carrying the per-sample summary + attempt trail. The
runner ALSO journals one SHADOW-to-SHADOW ``lifecycle_transitions``
row that references the report id, so the transition timeline surfaces
"a shadow run happened here" inline with the rest of the stage moves;
no schema change is needed for that -- the journal accepts any
``metrics_snapshot_json`` shape.

Indexes:
    * (key, version, created_at) -- primary read pattern is "the newest
      report for a (key, version) pair", which this index answers with
      an index-only descending scan and LIMIT 1.
    * created_at -- audit ordering for operator dashboards that list
      recent shadow runs across every key.

Table-existence guard: on a fresh install ``create_all`` in tests +
``make db-init`` builds the table from
:class:`ShadowReportRecord`; the migration is a no-op on that path. On
an existing DB the table cannot pre-exist because this is its first
introduction; the guard keeps ``upgrade`` idempotent regardless.

Revision ID: 117_lifecycle_shadow_reports
Revises:     116_prompt_bundle_columns
Create Date: 2026-08-06
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "117_lifecycle_shadow_reports"
down_revision: str | None = "116_prompt_bundle_columns"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def _has_shadow_reports_table() -> bool:
    bind = op.get_bind()
    return "lifecycle_shadow_reports" in sa.inspect(bind).get_table_names()


def upgrade() -> None:
    if _has_shadow_reports_table():
        # Fresh install: create_all built lifecycle_shadow_reports from
        # the SQLModel before the stamp reaches this revision; nothing
        # to do here.
        return
    op.create_table(
        "lifecycle_shadow_reports",
        sa.Column("id", sa.String(length=64), primary_key=True, nullable=False),
        sa.Column("key", sa.String(length=256), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False),
        sa.Column("assignment_id", sa.String(length=64), nullable=True),
        sa.Column("sample_attempted", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("sample_succeeded", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("mean_faithfulness", sa.Float(), nullable=False, server_default=sa.text("0")),
        sa.Column("mean_determinism", sa.Float(), nullable=False, server_default=sa.text("0")),
        sa.Column("regressions", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("diff_summary_json", sa.Text(), nullable=False, server_default="{}"),
        sa.Column("actor", sa.String(length=128), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index(
        "ix_lifecycle_shadow_reports_key",
        "lifecycle_shadow_reports",
        ["key"],
    )
    op.create_index(
        "ix_lifecycle_shadow_reports_key_version_created",
        "lifecycle_shadow_reports",
        ["key", "version", "created_at"],
    )
    op.create_index(
        "ix_lifecycle_shadow_reports_created_at",
        "lifecycle_shadow_reports",
        ["created_at"],
    )


def downgrade() -> None:
    if not _has_shadow_reports_table():
        return
    op.drop_index(
        "ix_lifecycle_shadow_reports_created_at",
        table_name="lifecycle_shadow_reports",
    )
    op.drop_index(
        "ix_lifecycle_shadow_reports_key_version_created",
        table_name="lifecycle_shadow_reports",
    )
    op.drop_index(
        "ix_lifecycle_shadow_reports_key",
        table_name="lifecycle_shadow_reports",
    )
    op.drop_table("lifecycle_shadow_reports")
