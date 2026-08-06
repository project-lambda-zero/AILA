"""Add default_team_id to oidc_provider_records (issue #36).

OIDC auto-provisioned users were created with no team, which under TEAM-06
means god-tier access to every team's data. This column lets an admin bind an
OIDC provider to a default team so auto-provisioned users are scoped on first
login. NULL preserves the prior behavior (god-tier), now explicit and logged.

The model side carries the column so a freshly created schema (tests, new
installs) already has it; this migration backfills existing databases.

Revision ID: 076_oidc_default_team
Revises: 075_hot_column_indexes
"""
from __future__ import annotations

from alembic import op

revision: str = "076_oidc_default_team"
down_revision: str | None = "075_hot_column_indexes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE oidc_provider_records ADD COLUMN IF NOT EXISTS default_team_id TEXT"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE oidc_provider_records DROP COLUMN IF EXISTS default_team_id"
    )
