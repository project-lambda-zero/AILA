"""144 -- drop the never-written vr_cve_feed_state table.

``vr_cve_feed_state`` (migration 050) was reserved as a per-source checkpoint
for an automated NVD / GHSA feed poller that was never built. No code path ever
wrote a row to it: CVE records enter only through the VR ingest endpoint, which
writes ``vr_cve_records`` directly. The ORM model is removed (issue #209), so
this migration drops the table so an existing database matches the model set.
A brand-new database builds its schema from the current models and never
creates the table, so the upgrade checks for the table first and is a no-op
there.

The drop follows the guard documented in migration 104: it refuses to run
while the table holds rows, so hand-inserted data is never discarded silently.
Delete or archive any such rows first, then re-run the upgrade.

Revision ID: 144_drop_vr_cve_feed_state
Revises: 143_vr_eval_suites
Create Date: 2026-10-30
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "144_drop_vr_cve_feed_state"
down_revision: str | None = "143_vr_eval_suites"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    bind = op.get_bind()
    if bind.execute(sa.text("SELECT to_regclass('vr_cve_feed_state')")).scalar() is None:
        return
    rows = bind.execute(sa.text("SELECT count(*) FROM vr_cve_feed_state")).scalar_one()
    if rows:
        raise RuntimeError(
            f"vr_cve_feed_state holds {rows} row(s); refusing to DROP. No "
            "AILA code writes this table, so the rows were inserted by "
            "hand. Archive or delete them (DELETE FROM vr_cve_feed_state) "
            "and re-run the upgrade.",
        )
    op.drop_table("vr_cve_feed_state")


def downgrade() -> None:
    op.create_table(
        "vr_cve_feed_state",
        sa.Column("source", sa.String(16), primary_key=True),
        sa.Column("last_polled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_cursor", sa.String(256), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "consecutive_errors", sa.Integer(),
            nullable=False, server_default="0",
        ),
        sa.Column("records_ingested", sa.Integer(), nullable=False, server_default="0"),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True),
            nullable=False, server_default=sa.func.now(),
        ),
    )
