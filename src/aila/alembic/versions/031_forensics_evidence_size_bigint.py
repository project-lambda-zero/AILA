"""Widen forensics_project_evidence.size_bytes from INTEGER to BIGINT.

Disk images, memory dumps, and E01 files routinely exceed int32's 2.1GB
ceiling (a 100GB image = 107_374_182_400 bytes). The intake workflow was
crashing at commit with asyncpg DataError: "value out of int32 range".
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "031_evidence_size_bigint"
down_revision = "030_inv_task_id"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "forensics_project_evidence",
        "size_bytes",
        existing_type=sa.Integer(),
        type_=sa.BigInteger(),
        existing_nullable=True,
    )


def downgrade() -> None:
    op.alter_column(
        "forensics_project_evidence",
        "size_bytes",
        existing_type=sa.BigInteger(),
        type_=sa.Integer(),
        existing_nullable=True,
    )
