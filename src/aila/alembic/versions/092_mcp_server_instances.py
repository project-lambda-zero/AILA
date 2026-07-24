"""092 -- MCP server instance catalog (RFC-11 step 1).

Creates ``mcp_server_instances`` -- an operator-editable catalog of MCP
server registrations. ``McpRegistryServiceBase`` MAY consult it as a
default that beats the code-embedded ``default_url`` but stays below the
``env`` and ``config`` overrides. When no row exists for a given
``(module_scope, name)`` the URL resolution is byte-identical to the
pre-catalog behaviour, so this table does not touch live dispatch.

Columns match the SQLModel definition in platform/mcp/instance_catalog.py
so ``create_all`` (tests, fresh installs) matches the migrated schema.
The unique constraint and index names are prefixed for the
database-scoped Postgres namespace. Guarded with ``IF NOT EXISTS``.

No seed rows: the catalog starts empty and resolution falls back to the
per-module static ``MCP_SERVERS`` tuples, so live investigations are
unaffected. Operators add instances via ``POST /platform/mcp/instances``.

Revision ID: 092_mcp_server_instances
Revises:     091_lifecycle_transitions
Create Date: 2026-07-24
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "092_mcp_server_instances"
down_revision: str | None = "091_lifecycle_transitions"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    op.execute(sa.text("""
        CREATE TABLE IF NOT EXISTS mcp_server_instances (
            id VARCHAR NOT NULL PRIMARY KEY,
            name TEXT NOT NULL,
            transport TEXT NOT NULL DEFAULT 'http',
            endpoint TEXT NOT NULL,
            capability_tags TEXT NOT NULL DEFAULT '[]',
            enabled BOOLEAN NOT NULL DEFAULT true,
            module_scope TEXT,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at TIMESTAMPTZ,
            CONSTRAINT uq_mcp_server_instances_scope_name
                UNIQUE (module_scope, name)
        );
    """))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_mcp_server_instances_name "
        "ON mcp_server_instances (name);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_mcp_server_instances_enabled "
        "ON mcp_server_instances (enabled);"
    ))
    op.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_mcp_server_instances_module_scope "
        "ON mcp_server_instances (module_scope);"
    ))


def downgrade() -> None:
    op.execute(sa.text("DROP TABLE IF EXISTS mcp_server_instances;"))
