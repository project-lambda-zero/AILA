"""system_metadata_records -- per-system neofetch/gateway/external-ip snapshot.

Revision ID: 018_system_metadata
Revises: 017_llm_cost_record
Create Date: 2026-04-12

Adds a 1:1 metadata table for each ManagedSystemRecord, populated by the
network discovery job on each scan. Stores:

    gateway_ip, gateway_interface  -- from `ip route show default`
    external_ip                    -- from `curl ifconfig.me`
    os_name / os_pretty_name       -- from /etc/os-release
    kernel                         -- from `uname -r`
    cpu_cores                      -- from `nproc`
    memory_mb                      -- from `free -m`
    disk_gb                        -- from `df -BG /`
    uptime_seconds                 -- from `uptime -s`

The uniqueness constraint on system_id enforces the 1:1 mapping. The
is_stale flag follows the same discovery pattern used by the existing
network tables (D-10).
"""
from __future__ import annotations

from typing import Union

import sqlalchemy as sa
from alembic import op

revision: str = "018_system_metadata"
down_revision: Union[str, None] = "017_llm_cost_record"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "system_metadata_records",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("system_id", sa.Integer(), nullable=False),
        sa.Column("gateway_ip", sa.Text(), nullable=True),
        sa.Column("gateway_interface", sa.Text(), nullable=True),
        sa.Column("external_ip", sa.Text(), nullable=True),
        sa.Column("os_name", sa.Text(), nullable=True),
        sa.Column("os_pretty_name", sa.Text(), nullable=True),
        sa.Column("kernel", sa.Text(), nullable=True),
        sa.Column("cpu_cores", sa.Integer(), nullable=True),
        sa.Column("memory_mb", sa.Integer(), nullable=True),
        sa.Column("disk_gb", sa.Integer(), nullable=True),
        sa.Column("uptime_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "last_collected",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "is_stale",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.UniqueConstraint(
            "system_id", name="uq_system_metadata_record_system_id"
        ),
    )
    op.create_index(
        "ix_system_metadata_records_system_id",
        "system_metadata_records",
        ["system_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_system_metadata_records_system_id",
        table_name="system_metadata_records",
    )
    op.drop_table("system_metadata_records")
