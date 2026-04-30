"""021 — team_records + team_member_records (Phase 177).

Materialises teams as first-class records. Prior phases (167) tracked
``team_id`` on every team-scoped record as a free-form string without a
parent teams table. Phase 177 introduces:

    team_records           -- {id (uuid text PK), name (unique), description,
                              created_at, updated_at, deleted_at}
    team_member_records    -- {id, team_id (fk), user_id (fk), role,
                              created_at}

``team_id`` strings already stamped on existing records are preserved —
the migration does not backfill relationships. Admin UI creates teams
going forward and reassigns users as needed.

Revision ID: 021_team_records
Revises: 020_firewall_oidc_ext
Create Date: 2026-04-12
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "021_team_records"
down_revision: Union[str, None] = "020_firewall_oidc_ext"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "team_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("name", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False, server_default=""),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_team_records_name",
        "team_records",
        ["name"],
        unique=True,
    )
    op.create_index(
        "ix_team_records_deleted_at",
        "team_records",
        ["deleted_at"],
    )

    op.create_table(
        "team_member_records",
        sa.Column("id", sa.Text(), primary_key=True),
        sa.Column("team_id", sa.Text(), nullable=False),
        sa.Column("user_id", sa.Text(), nullable=False),
        sa.Column(
            "role",
            sa.Text(),
            nullable=False,
            server_default="operator",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint(
            "team_id",
            "user_id",
            name="uq_team_member_records_team_user",
        ),
    )
    op.create_index(
        "ix_team_member_records_team_id",
        "team_member_records",
        ["team_id"],
    )
    op.create_index(
        "ix_team_member_records_user_id",
        "team_member_records",
        ["user_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_team_member_records_user_id", table_name="team_member_records"
    )
    op.drop_index(
        "ix_team_member_records_team_id", table_name="team_member_records"
    )
    op.drop_table("team_member_records")

    op.drop_index("ix_team_records_deleted_at", table_name="team_records")
    op.drop_index("ix_team_records_name", table_name="team_records")
    op.drop_table("team_records")
