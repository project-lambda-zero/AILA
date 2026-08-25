"""134 -- relax vr_fuzz_campaign_proposals.investigation_id / outcome_id
to NULLABLE so producer-generated proposals (authored from function
ranking, not from an investigation outcome) can persist without a
synthetic investigation/outcome row.

Existing rows already carry non-null values; the migration only widens
the constraint. The downgrade re-tightens both columns to NOT NULL,
which will fail on any producer-only rows -- expected, since a
downgrade past this point implies removing the producer entirely.

Revision ID: 134_fuzz_proposal_nullable_ctx
Revises: 133_drop_saved_filters
Create Date: 2026-08-25
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "134_fuzz_proposal_nullable_ctx"
down_revision: str | None = "133_drop_saved_filters"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "vr_fuzz_campaign_proposals",
        "investigation_id",
        existing_type=sa.String(),
        nullable=True,
    )
    op.alter_column(
        "vr_fuzz_campaign_proposals",
        "outcome_id",
        existing_type=sa.String(),
        nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "vr_fuzz_campaign_proposals",
        "investigation_id",
        existing_type=sa.String(),
        nullable=False,
    )
    op.alter_column(
        "vr_fuzz_campaign_proposals",
        "outcome_id",
        existing_type=sa.String(),
        nullable=False,
    )
