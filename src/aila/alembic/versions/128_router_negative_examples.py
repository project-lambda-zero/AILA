"""128 -- ``router_negative_example`` (issue #161 write-only slice).

Adds the corpus table that :func:`aila.platform.agents.auto_steering
.maybe_post_auto_steering` writes to whenever a steering fires. Each
row captures one ground-truth routing failure signal (this
task_shape / tool needed operator-style intervention on this rule)
so a downstream re-tuner can consume the accrued corpus as hard
negatives. No consumer / router re-tune ships in this slice; the
table exists so the corpus starts accruing behind the write-only
path -- per the RFC recommendation, "start by logging the rows so
the corpus accrues before the tuner is built".

Columns:

* ``id`` -- UUID primary key.
* ``task_shape`` -- structural key of the failing call. Currently
  populated with ``"{server_id}.{tool_name}"`` because the tool
  executor site does not yet carry a distilled task-shape identifier;
  the tuner can group / project as it prefers.
* ``model`` -- routed model id (NULL when the auto-steering site
  does not yet plumb it through; kept nullable so the write-only
  path never fails to persist a signal for the missing field).
* ``tool`` -- ``"{server_id}.{tool_name}"``; nullable for future
  non-tool steering fires (dispatch-stall escalation, fuzz-feedback).
* ``rule_fired`` -- stable identifier of the auto-steering rule
  (``read_lines_past_eof``, ``read_function_indexer_fault``,
  ``read_lines_file_not_found``, ``kwarg_rejected``, ...).
* ``investigation_id`` -- FK-shaped VARCHAR (no explicit FK; the
  investigation may be pruned before the router re-tune runs, and
  we want the negative to survive as a historical signal).
* ``created_at`` -- server-side default so writers do not have to
  synchronise clocks with the DB.

Two indexes cover the expected re-tune query surface:

* ``ix_router_negative_example_created_at`` -- window scans (last
  N days of failures) for the periodic tuner.
* ``ix_router_negative_example_shape_rule`` -- grouped counts by
  ``(task_shape, rule_fired)`` for aggregate reports.

Every named constraint / index is module-prefixed (``router_negative
_example_...``) because Postgres constraint names are schema-global.

Revision ID: 128_router_negative_examples
Revises:     127_managed_system_passphrase_secret
Create Date: 2026-08-16
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "128_router_negative_examples"
down_revision: str | None = "127_managed_system_passphrase_secret"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "router_negative_example"
_IX_CREATED_AT: str = "ix_router_negative_example_created_at"
_IX_SHAPE_RULE: str = "ix_router_negative_example_shape_rule"


def _table_present() -> bool:
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if _table_present():
        # Fresh test bootstrap that created the table via metadata.create_all
        # (e.g. the test_db fixture) -- stamp-only, no-op the DDL. Mirrors
        # the pattern in 115 / 124 / 126.
        return
    op.execute(sa.text(
        f"""
CREATE TABLE {_TABLE} (
    id                VARCHAR(36)  NOT NULL,
    task_shape        VARCHAR(128) NOT NULL,
    model             VARCHAR(128),
    tool              VARCHAR(128),
    rule_fired        VARCHAR(64)  NOT NULL,
    investigation_id  VARCHAR(36),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_router_negative_example PRIMARY KEY (id)
)
"""
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_IX_CREATED_AT} "
        f"ON {_TABLE} (created_at)"
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_IX_SHAPE_RULE} "
        f"ON {_TABLE} (task_shape, rule_fired)"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_IX_SHAPE_RULE}"))
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_IX_CREATED_AT}"))
    op.execute(sa.text(f"DROP TABLE IF EXISTS {_TABLE}"))
