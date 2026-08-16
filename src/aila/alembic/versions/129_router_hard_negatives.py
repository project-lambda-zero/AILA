"""129 -- ``router_hard_negative`` (issue #161 consumer aggregate).

Adds the aggregated hard-negative table the
``platform.routing_negative_retune`` automation action writes to
(:mod:`aila.platform.routing.negative_feedback`). Each row is one
``(task_shape, model, tool)`` bucket accumulated from
``router_negative_example`` rows accrued above the
``platform.routing_negative_hwm`` config high-water mark.

The corpus table ``router_negative_example`` (migration 128) is
append-only per-fire and grows unboundedly with steering activity.
The nightly retune action drains new rows into this aggregate,
incrementing ``hit_count`` on the matching ``(task_shape, model,
tool)`` bucket and advancing the HWM. The aggregate is what a
:func:`aila.platform.routing.negative_feedback
.augment_history_provider_with_hard_negatives` wrapper folds into
:class:`aila.platform.eval.routing_learner.RoutingLearner` as synthetic
REJECT :class:`RoutingSample` rows (opt-in via the
``platform.routing_negative_feedback_enabled`` flag; default OFF so
enabling / disabling the schedule alone changes no live behaviour).

Columns:

* ``id`` -- UUID primary key.
* ``task_shape`` -- structural key of the failing call; sourced from
  ``router_negative_example.task_shape`` (currently the tool key
  ``"{server_id}.{tool_name}"``).
* ``model`` -- routed model id; ``''`` sentinel when the source row
  had NULL (the write path in ``auto_steering`` does not yet plumb
  the routed model through). NOT NULL with a default sentinel so the
  unique key below can dedupe without a partial-index dance.
* ``tool`` -- ``"{server_id}.{tool_name}"``. Same ``''`` sentinel
  rule as ``model`` when the source row was NULL.
* ``hit_count`` -- BIGINT running count of source rows that folded
  into this bucket. Increments on every retune tick that observes a
  matching source row. Bounded reads at fold time via ``min(hit_count,
  cap)`` so a runaway bucket cannot explode the sample stream.
* ``first_seen_at`` -- creation timestamp of the aggregate row.
* ``last_seen_at`` -- newest ``router_negative_example.created_at``
  seen for this bucket; monotonically advances.

One unique constraint (``task_shape, model, tool``) plus one
supporting index (``last_seen_at``) so the retune action's UPSERT
is O(1) per bucket and a window-scan on the aggregate is bounded.

Every named constraint / index is module-prefixed
(``router_hard_negative_``) because Postgres constraint names are
schema-global (CLAUDE.md common mistake 21).

Revision ID: 129_router_hard_negatives
Revises:     128_router_negative_examples
Create Date: 2026-08-16
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "129_router_hard_negatives"
down_revision: str | None = "128_router_negative_examples"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "router_hard_negative"
_UQ_SHAPE_MODEL_TOOL: str = "uq_router_hard_negative_shape_model_tool"
_IX_LAST_SEEN: str = "ix_router_hard_negative_last_seen_at"


def _table_present() -> bool:
    inspector = sa.inspect(op.get_bind())
    return _TABLE in set(inspector.get_table_names())


def upgrade() -> None:
    if _table_present():
        # Fresh test bootstrap that created the table via metadata.create_all
        # (e.g. the test_db fixture) -- stamp-only, no-op the DDL. Mirrors
        # the pattern in 115 / 124 / 126 / 128.
        return
    op.execute(sa.text(
        f"""
CREATE TABLE {_TABLE} (
    id             VARCHAR(36)  NOT NULL,
    task_shape     VARCHAR(128) NOT NULL,
    model          VARCHAR(128) NOT NULL DEFAULT '',
    tool           VARCHAR(128) NOT NULL DEFAULT '',
    hit_count      BIGINT       NOT NULL DEFAULT 0,
    first_seen_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    CONSTRAINT pk_router_hard_negative PRIMARY KEY (id),
    CONSTRAINT {_UQ_SHAPE_MODEL_TOOL} UNIQUE (task_shape, model, tool)
)
"""
    ))
    op.execute(sa.text(
        f"CREATE INDEX IF NOT EXISTS {_IX_LAST_SEEN} "
        f"ON {_TABLE} (last_seen_at)"
    ))


def downgrade() -> None:
    if not _table_present():
        return
    op.execute(sa.text(f"DROP INDEX IF EXISTS {_IX_LAST_SEEN}"))
    op.execute(sa.text(f"DROP TABLE IF EXISTS {_TABLE}"))
