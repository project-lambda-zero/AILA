"""Add ip_address and user_agent to refresh_token_records (#36 auth).

RefreshTokenRecord declares ip_address and user_agent, and
issue_user_refresh_token() writes both on every login/refresh. Migration 002
created the table without these columns and no later migration added them, so
on an alembic-migrated database the INSERT references columns that do not exist
and every login fails with a 500. Databases built via create_all (fresh
installs, tests) already carry the columns from the model; this migration
backfills alembic-migrated databases. Both columns are nullable TEXT so existing
rows carry NULL.

Revision ID: 079_refresh_token_client_meta
Revises: 078_notification_created_index
Create Date: 2026-07-21
"""
from __future__ import annotations

from alembic import op

revision: str = "079_refresh_token_client_meta"
down_revision: str | None = "078_notification_created_index"
branch_labels = None
depends_on = None

_TABLE = "refresh_token_records"


def upgrade() -> None:
    op.execute(f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS ip_address TEXT")
    op.execute(f"ALTER TABLE {_TABLE} ADD COLUMN IF NOT EXISTS user_agent TEXT")


def downgrade() -> None:
    op.execute(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS user_agent")
    op.execute(f"ALTER TABLE {_TABLE} DROP COLUMN IF EXISTS ip_address")
