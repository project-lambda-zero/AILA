"""add sbd report hash columns

Phase 147 EXEC-04: SHA-256 integrity hash for SbD report PDF artifacts.

Adds two nullable columns to sbd_nfr_session_record:
  - report_hash_sha256: hex digest of the first-generated PDF bytes.
  - report_hash_generated_at: timestamp when the hash was first computed.

Both columns are nullable. Existing rows have null values (status="not_generated"
on the hash endpoint). No data backfill is performed.

Revision ID: 007_add_sbd_report_hash
Revises: 006_plan_143_finding_feedback
Create Date: 2026-04-09
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "007_add_sbd_report_hash"
down_revision: Union[str, None] = "006_plan_143_finding_feedback"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "sbd_nfr_session_record",
        sa.Column("report_hash_sha256", sa.Text(), nullable=True),
    )
    op.add_column(
        "sbd_nfr_session_record",
        sa.Column("report_hash_generated_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("sbd_nfr_session_record", "report_hash_generated_at")
    op.drop_column("sbd_nfr_session_record", "report_hash_sha256")
