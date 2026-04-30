"""Plan D network discovery tables — system ports, services, and connections.

Revision ID: 004_plan_d_network_tables
Revises: 003_plan_c_endpoint_tables
Create Date: 2026-04-09

Creates:
- system_port_records: open TCP/UDP listening ports per system (RADAR-01/D-03)
- system_service_records: running systemd services per system (RADAR-03/D-03)
- system_connection_records: active TCP connections between registered systems (D-04)

Each table supports overwrite-per-scan (D-09) and stale marking (D-10) via
is_stale and last_collected columns.
"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "004_plan_d_network_tables"
down_revision: Union[str, None] = "003_plan_c_endpoint_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # system_port_records: open TCP/UDP listening ports per system (RADAR-01/D-03)
    op.create_table(
        "system_port_records",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("system_id", sa.Integer, nullable=False),
        sa.Column("port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.Text, nullable=False, server_default="tcp"),
        sa.Column("local_address", sa.Text, nullable=False, server_default=""),
        sa.Column("process_name", sa.Text, nullable=True),
        sa.Column("pid", sa.Integer, nullable=True),
        sa.Column(
            "last_collected",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("is_stale", sa.Boolean, nullable=False, server_default="false"),
    )
    op.create_index("ix_spr_system_id", "system_port_records", ["system_id"])

    # system_service_records: running systemd services per system (RADAR-03/D-03)
    op.create_table(
        "system_service_records",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("system_id", sa.Integer, nullable=False),
        sa.Column("service_name", sa.Text, nullable=False),
        sa.Column("service_type", sa.Text, nullable=False, server_default="systemd"),
        sa.Column("state", sa.Text, nullable=False, server_default="running"),
        sa.Column("sub_state", sa.Text, nullable=False, server_default=""),
        sa.Column(
            "last_collected",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("is_stale", sa.Boolean, nullable=False, server_default="false"),
    )
    op.create_index("ix_ssr_system_id", "system_service_records", ["system_id"])
    op.create_index("ix_ssr_service_name", "system_service_records", ["service_name"])

    # system_connection_records: active TCP connections between registered systems (D-04)
    op.create_table(
        "system_connection_records",
        sa.Column("id", sa.Integer, primary_key=True, autoincrement=True),
        sa.Column("source_system_id", sa.Integer, nullable=False),
        sa.Column("dest_system_id", sa.Integer, nullable=False),
        sa.Column("dest_ip", sa.Text, nullable=False, server_default=""),
        sa.Column("dest_port", sa.Integer, nullable=False),
        sa.Column("protocol", sa.Text, nullable=False, server_default="tcp"),
        sa.Column("state", sa.Text, nullable=False, server_default="ESTABLISHED"),
        sa.Column(
            "last_collected",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("NOW()"),
        ),
        sa.Column("is_stale", sa.Boolean, nullable=False, server_default="false"),
    )
    op.create_index("ix_scr_source_id", "system_connection_records", ["source_system_id"])
    op.create_index("ix_scr_dest_id", "system_connection_records", ["dest_system_id"])


def downgrade() -> None:
    op.drop_table("system_connection_records")
    op.drop_table("system_service_records")
    op.drop_table("system_port_records")
