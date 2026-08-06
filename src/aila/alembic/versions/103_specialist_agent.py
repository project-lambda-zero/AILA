"""103 -- specialist_agent: user-extensible optional specialist registry.

The investigation panel is a fixed 3-role spine plus optional specialist
agents a core branch can request from the oracle. A specialist is data: a
row carries a capability (matching a dispatch phase), an optional prompt
family, and a description. Users add specialists through the CRUD API
without a code change; every module inherits the mechanism. Columns match
SpecialistAgentRecord in platform/services/specialist_registry.py so
create_all (tests, fresh installs) matches the migrated schema. Additive
and guarded with IF NOT EXISTS.

Revision ID: 103_specialist_agent
Revises:     102_investigation_ledger
Create Date: 2026-07-26
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "103_specialist_agent"
down_revision: str | None = "102_investigation_ledger"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text(
        "CREATE TABLE IF NOT EXISTS specialist_agent ("
        " id VARCHAR(64) PRIMARY KEY,"
        " module_id VARCHAR(64) NOT NULL,"
        " name VARCHAR(64) NOT NULL,"
        " capability VARCHAR(64) NOT NULL,"
        " strategy_family VARCHAR(128),"
        " description TEXT,"
        " enabled BOOLEAN NOT NULL DEFAULT true,"
        " team_id VARCHAR(64),"
        " created_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
        " updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),"
        " CONSTRAINT uq_specialist_agent_module_name"
        " UNIQUE (module_id, name)"
        ")"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_specialist_agent_module_id "
        "ON specialist_agent (module_id)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_specialist_agent_capability "
        "ON specialist_agent (capability)"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_specialist_agent_team_id "
        "ON specialist_agent (team_id)"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS specialist_agent"))
