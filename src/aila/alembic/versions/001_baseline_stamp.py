"""Baseline stamp — marks existing schema as Alembic-managed.

This migration has empty upgrade() and downgrade() bodies.  It exists solely
to establish a head revision that `alembic stamp head` can point to.
Running `alembic stamp head` on an existing database marks all current tables
as managed by Alembic without emitting any DDL.

Revision ID: 001_baseline
Revises: None
Create Date: 2026-04-06
"""
from typing import Sequence, Union

# revision identifiers, used by Alembic.
revision: str = "001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
