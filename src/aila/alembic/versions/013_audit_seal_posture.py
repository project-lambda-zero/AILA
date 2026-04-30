"""Add posture_mode column to auditsealrecord (DPM-04).

Records the active data posture mode (transparent/standard/paranoid) at
the time each LLM call seal was computed.  Included in the HMAC payload
for tamper protection.

Revision ID: 013_audit_seal_posture
Revises: 012_automation_schedule
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "013_audit_seal_posture"
down_revision: Union[str, None] = "012_automation_schedule"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "auditsealrecord",
        sa.Column("posture_mode", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("auditsealrecord", "posture_mode")
