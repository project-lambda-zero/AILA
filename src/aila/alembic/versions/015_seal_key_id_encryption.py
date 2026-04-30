"""Add key_id and encrypted content columns to auditsealrecord (LLM-SEC-02/03).

Supports HMAC key rotation tracking via key_id and AES-256-GCM content
encryption via prompt_content_encrypted / response_content_encrypted.
Existing plaintext records are not migrated -- encrypt-on-write only.

Revision ID: 015_seal_key_id_encryption
Revises: 014_verification_record
Create Date: 2026-04-11
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "015_seal_key_id_encryption"
down_revision: Union[str, None] = "014_verification_record"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "auditsealrecord",
        sa.Column("key_id", sa.Text(), nullable=True),
    )
    op.add_column(
        "auditsealrecord",
        sa.Column("prompt_content_encrypted", sa.Text(), nullable=True),
    )
    op.add_column(
        "auditsealrecord",
        sa.Column("response_content_encrypted", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("auditsealrecord", "response_content_encrypted")
    op.drop_column("auditsealrecord", "prompt_content_encrypted")
    op.drop_column("auditsealrecord", "key_id")
