"""Phase 143 findings enrichment -- add is_kev + current_workflow_state to LatestFindingRecord.

Revision ID: 005_plan_143_findings_kev_workflow
Revises: 004_plan_d_network_tables
Create Date: 2026-04-10

Adds:
- is_kev BOOLEAN NOT NULL DEFAULT FALSE -- CISA KEV catalog flag (FIND-04)
- current_workflow_state TEXT NOT NULL DEFAULT 'new' -- triage workflow state (FIND-08)

Workflow states: new | investigating | mitigated | verified | closed
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "005_plan_143_findings_kev_workflow"
down_revision: Union[str, None] = "004_plan_d_network_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_VALID_WORKFLOW_STATES = "('new', 'investigating', 'mitigated', 'verified', 'closed')"


def upgrade() -> None:
    # Add is_kev: CISA KEV catalog flag
    op.add_column(
        "latest_finding_records",
        sa.Column("is_kev", sa.Boolean, nullable=False, server_default="false"),
    )

    # Add current_workflow_state: triage lifecycle state
    op.add_column(
        "latest_finding_records",
        sa.Column(
            "current_workflow_state",
            sa.Text,
            nullable=False,
            server_default="new",
        ),
    )

    # CHECK constraint on workflow state values
    op.create_check_constraint(
        "ck_lfr_workflow_state",
        "latest_finding_records",
        f"current_workflow_state IN {_VALID_WORKFLOW_STATES}",
    )

    # Indexes for filter performance
    op.create_index("ix_lfr_is_kev", "latest_finding_records", ["is_kev"])
    op.create_index(
        "ix_lfr_workflow_state",
        "latest_finding_records",
        ["current_workflow_state"],
    )


def downgrade() -> None:
    op.drop_index("ix_lfr_workflow_state", table_name="latest_finding_records")
    op.drop_index("ix_lfr_is_kev", table_name="latest_finding_records")
    op.drop_constraint(
        "ck_lfr_workflow_state",
        "latest_finding_records",
        type_="check",
    )
    op.drop_column("latest_finding_records", "current_workflow_state")
    op.drop_column("latest_finding_records", "is_kev")
