"""add condition_expr_json column to question and section records

Phase 151 TOOL-05: Adds condition_expr_json nullable Text column to both
sbd_nfr_question_record and sbd_nfr_section_record tables.

This column stores JSON-encoded multi-condition expressions for AND/OR gating.
When set, takes precedence over the legacy single depends_on_question_id +
expected_when pair. Existing rows are unaffected (null = use legacy path).

Revision ID: 008_add_condition_expr_json
Revises: 007_add_sbd_report_hash
Create Date: 2026-04-10
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "008_add_condition_expr_json"
down_revision: Union[str, None] = "007_add_sbd_report_hash"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sbd_nfr_question_record",
        sa.Column("condition_expr_json", sa.Text(), nullable=True),
    )
    op.add_column(
        "sbd_nfr_section_record",
        sa.Column("condition_expr_json", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sbd_nfr_question_record", "condition_expr_json")
    op.drop_column("sbd_nfr_section_record", "condition_expr_json")
