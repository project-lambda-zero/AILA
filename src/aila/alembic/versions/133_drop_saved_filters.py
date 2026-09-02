"""133 -- drop the saved_filters feature tables (feature removed).

The admin "saved filters" personalization feature was removed end to end:
its router, schemas, and ORM model no longer exist. This migration drops the
``saved_filter_records`` table and its two indexes so an existing database
matches the model set. A brand-new database builds its schema from the
current models (which no longer include the record) and never creates the
table, so the drops are guarded with IF EXISTS and become a no-op there.

Revision ID: 133_drop_saved_filters
Revises: 132_message_superseded_at
Create Date: 2026-08-25
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "133_drop_saved_filters"
down_revision: str | None = "132_message_superseded_at"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("DROP INDEX IF EXISTS ix_saved_filter_records_entity_type")
    op.execute("DROP INDEX IF EXISTS ix_saved_filter_records_user_id")
    op.execute('DROP TABLE IF EXISTS "saved_filter_records" CASCADE')


def downgrade() -> None:
    op.create_table(
        "saved_filter_records",
        sa.Column("id", sa.Text, primary_key=True),
        sa.Column("user_id", sa.Text, nullable=False),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("entity_type", sa.Text, nullable=False),
        sa.Column("filter_json", sa.Text, nullable=False, server_default="{}"),
        sa.Column("is_pinned", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("shared_with_team", sa.Boolean, nullable=False, server_default="false"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
    )
    op.create_index("ix_saved_filter_records_user_id", "saved_filter_records", ["user_id"])
    op.create_index("ix_saved_filter_records_entity_type", "saved_filter_records", ["entity_type"])
