"""126 -- drop dead ``taskrecord.result_path`` column (#144).

``TaskRecord.result_path`` (INFRA-06) was carried on ``taskrecord`` so
tasks could store a filesystem path to a per-run output artefact. No
task function in ``src/aila/`` ever returned ``{"result_path": ...}``
from its outcome dict, so the sole reader
(:mod:`aila.platform.tasks.hooks`) never wrote a value. Every consumer
(``GET /tasks/{id}``, ``GET /scans/{run_id}``, the frontend Tasks
detail panel) surfaced a permanent NULL. Module-owned result tables
(``vr_findings``, ``scan_findings``, forensics report tables, ...) are
the real result surface -- the retired ``result_path`` pattern only
survived as dead schema shape.

This migration drops the column via ``ALTER TABLE ... DROP COLUMN IF
EXISTS`` so a schema already missing the column (partial test
bootstrap, an environment restored without the column) becomes a
no-op. Table-existence is guarded via ``sa.inspect`` so an environment
without ``taskrecord`` (no platform ever booted here) becomes a no-op
too. Mirrors the guard pattern established by migration 115.

The Python model (``TaskRecord``), the API schemas (``TaskResponse``,
``ScanStatusResponse``), the ARQ hook that read the column, and the
frontend interfaces / detail panel are removed in the same commit;
after this migration runs, no code path references
``taskrecord.result_path`` any more.

Revision ID: 126_drop_result_path
Revises:     125_perf_indexes
Create Date: 2026-08-14
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "126_drop_result_path"
down_revision: str | None = "125_perf_indexes"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "taskrecord"


def _table_present() -> bool:
    """True when ``taskrecord`` exists in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS result_path"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(
        f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS result_path TEXT"
    ))
