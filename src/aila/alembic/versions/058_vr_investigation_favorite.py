"""058 — add is_favorite flag to vr_investigations.

Workspace-wide boolean (not per-user) — matches the existing flat
column model on vr_investigations. Default false so existing rows
backfill cleanly without a sentinel migration.

Indexed because the list endpoint adds a ``favorites=true`` filter
that benefits from a partial index when only a few rows are starred.

Revision: 058_vr_investigation_favorite
Revises:  057_vr_finding_project_nullable
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "058_vr_investigation_favorite"
down_revision: str | None = "057_vr_finding_project_nullable"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.add_column(
        "vr_investigations",
        sa.Column(
            "is_favorite",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    # Partial index — most investigations won't be starred, so a partial
    # index on (is_favorite=true) keeps the favorites query O(starred-count).
    op.create_index(
        "ix_vr_investigations_is_favorite_true",
        "vr_investigations",
        ["is_favorite"],
        postgresql_where=sa.text("is_favorite = true"),
    )


def downgrade() -> None:
    op.drop_index(
        "ix_vr_investigations_is_favorite_true",
        table_name="vr_investigations",
    )
    op.drop_column("vr_investigations", "is_favorite")
