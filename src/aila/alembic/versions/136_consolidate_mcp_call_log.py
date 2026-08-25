"""136 -- consolidate ``vr_mcp_call_log`` + ``malware_mcp_call_log`` into
one platform ``mcp_call_log`` table stamped with ``module_scope``.

RFC-04 phase 2 finish line: the per-module call-log tables were byte-
identical apart from their table names + a stray ``module_scope``-shaped
prefix in the record class names. This migration:

* Creates the consolidated ``mcp_call_log`` table with the full
  :class:`McpCallLogRecordBase` column set plus a nullable ``module_scope``
  column indexed for the operator dashboard slice.
* Copies every row out of ``vr_mcp_call_log`` (stamping ``module_scope='vr'``)
  and ``malware_mcp_call_log`` (stamping ``module_scope='malware'``).
* Drops both source tables + their indexes.

Both reads + drops are guarded via ``inspect(...).has_table(...)`` so a
re-run, or a deployment that predates one of the source tables, is a
no-op for the missing side.

The migration deliberately hard-codes the column list rather than importing
the SQLModel base so a future change to
:class:`aila.platform.contracts.mcp_call_log_base.McpCallLogRecordBase` never
retroactively edits this frozen schema step.

Revision ID: 136_consolidate_mcp_call_log
Revises:     135_vr_investigation_outcome_axes
Create Date: 2026-08-25
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "136_consolidate_mcp_call_log"
down_revision: str | None = "135_vr_investigation_outcome_axes"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_NEW_TABLE: str = "mcp_call_log"
_VR_TABLE: str = "vr_mcp_call_log"
_MW_TABLE: str = "malware_mcp_call_log"


def _has_table(name: str) -> bool:
    return sa.inspect(op.get_bind()).has_table(name)


def _copy_from(source: str, module_scope: str) -> None:
    """Copy every source row into the consolidated table, stamping scope."""
    op.execute(sa.text(
        f"INSERT INTO {_NEW_TABLE} ("
        "id, server_id, base_url, action, status, http_status, latency_ms, "
        "error_excerpt, target_id, team_id, instance_id, "
        "investigation_id, branch_id, turn_number, called_at, module_scope"
        ") SELECT "
        "id, server_id, base_url, action, status, http_status, latency_ms, "
        "error_excerpt, target_id, team_id, instance_id, "
        f"investigation_id, branch_id, turn_number, called_at, '{module_scope}'"
        f" FROM {source}"
    ))


def _create_consolidated() -> None:
    op.create_table(
        _NEW_TABLE,
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("server_id", sa.String(length=64), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("error_excerpt", sa.Text(), nullable=True),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("team_id", sa.String(length=36), nullable=True),
        sa.Column("instance_id", sa.String(length=128), nullable=True),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column("turn_number", sa.Integer(), nullable=True),
        sa.Column(
            "called_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("module_scope", sa.String(length=64), nullable=True),
    )
    op.create_index(
        "ix_mcp_call_log_server_id", _NEW_TABLE, ["server_id"],
    )
    op.create_index(
        "ix_mcp_call_log_target_id", _NEW_TABLE, ["target_id"],
    )
    op.create_index(
        "ix_mcp_call_log_instance_id", _NEW_TABLE, ["instance_id"],
    )
    op.create_index(
        "ix_mcp_call_log_investigation_id", _NEW_TABLE, ["investigation_id"],
    )
    op.create_index(
        "ix_mcp_call_log_branch_id", _NEW_TABLE, ["branch_id"],
    )
    op.create_index(
        "ix_mcp_call_log_called_at", _NEW_TABLE, ["called_at"],
    )
    op.create_index(
        "ix_mcp_call_log_module_scope", _NEW_TABLE, ["module_scope"],
    )


def _drop_source(source: str) -> None:
    # Best-effort per-index drop guarded by IF EXISTS so a deployment
    # missing one of the pre-consolidation indexes still passes.
    for ix in (
        f"ix_{source}_target_id",
        f"ix_{source}_server_id",
        f"ix_{source}_called_at",
        f"ix_{source}_instance_id",
        f"ix_{source}_investigation_id",
        f"ix_{source}_branch_id",
    ):
        op.execute(sa.text(f"DROP INDEX IF EXISTS {ix}"))
    op.drop_table(source)


def upgrade() -> None:
    _create_consolidated()
    if _has_table(_VR_TABLE):
        _copy_from(_VR_TABLE, "vr")
        _drop_source(_VR_TABLE)
    if _has_table(_MW_TABLE):
        _copy_from(_MW_TABLE, "malware")
        _drop_source(_MW_TABLE)


def _recreate_vr_table() -> None:
    op.create_table(
        _VR_TABLE,
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("server_id", sa.String(length=64), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("error_excerpt", sa.Text(), nullable=True),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("team_id", sa.String(length=36), nullable=True),
        sa.Column("instance_id", sa.String(length=128), nullable=True),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column("turn_number", sa.Integer(), nullable=True),
        sa.Column(
            "called_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(f"ix_{_VR_TABLE}_server_id", _VR_TABLE, ["server_id"])
    op.create_index(f"ix_{_VR_TABLE}_target_id", _VR_TABLE, ["target_id"])
    op.create_index(f"ix_{_VR_TABLE}_called_at", _VR_TABLE, ["called_at"])
    op.create_index(f"ix_{_VR_TABLE}_instance_id", _VR_TABLE, ["instance_id"])
    op.create_index(
        f"ix_{_VR_TABLE}_investigation_id", _VR_TABLE, ["investigation_id"],
    )
    op.create_index(f"ix_{_VR_TABLE}_branch_id", _VR_TABLE, ["branch_id"])


def _recreate_mw_table() -> None:
    op.create_table(
        _MW_TABLE,
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("server_id", sa.String(length=64), nullable=False),
        sa.Column("base_url", sa.String(length=512), nullable=False),
        sa.Column("action", sa.String(length=128), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("http_status", sa.Integer(), nullable=True),
        sa.Column("latency_ms", sa.Integer(), nullable=True),
        sa.Column("error_excerpt", sa.Text(), nullable=True),
        sa.Column("target_id", sa.String(length=36), nullable=True),
        sa.Column("team_id", sa.String(length=36), nullable=True),
        sa.Column("instance_id", sa.String(length=128), nullable=True),
        sa.Column("investigation_id", sa.String(length=36), nullable=True),
        sa.Column("branch_id", sa.String(length=36), nullable=True),
        sa.Column("turn_number", sa.Integer(), nullable=True),
        sa.Column(
            "called_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index(f"ix_{_MW_TABLE}_server_id", _MW_TABLE, ["server_id"])
    op.create_index(f"ix_{_MW_TABLE}_target_id", _MW_TABLE, ["target_id"])
    op.create_index(f"ix_{_MW_TABLE}_called_at", _MW_TABLE, ["called_at"])
    op.create_index(f"ix_{_MW_TABLE}_instance_id", _MW_TABLE, ["instance_id"])
    op.create_index(
        f"ix_{_MW_TABLE}_investigation_id", _MW_TABLE, ["investigation_id"],
    )
    op.create_index(f"ix_{_MW_TABLE}_branch_id", _MW_TABLE, ["branch_id"])


def _copy_back(target: str, module_scope: str) -> None:
    op.execute(sa.text(
        f"INSERT INTO {target} ("
        "id, server_id, base_url, action, status, http_status, latency_ms, "
        "error_excerpt, target_id, team_id, instance_id, "
        "investigation_id, branch_id, turn_number, called_at"
        ") SELECT "
        "id, server_id, base_url, action, status, http_status, latency_ms, "
        "error_excerpt, target_id, team_id, instance_id, "
        "investigation_id, branch_id, turn_number, called_at"
        f" FROM {_NEW_TABLE} WHERE module_scope = '{module_scope}'"
    ))


def downgrade() -> None:
    _recreate_vr_table()
    _recreate_mw_table()
    _copy_back(_VR_TABLE, "vr")
    _copy_back(_MW_TABLE, "malware")
    for ix in (
        "ix_mcp_call_log_module_scope",
        "ix_mcp_call_log_called_at",
        "ix_mcp_call_log_branch_id",
        "ix_mcp_call_log_investigation_id",
        "ix_mcp_call_log_instance_id",
        "ix_mcp_call_log_target_id",
        "ix_mcp_call_log_server_id",
    ):
        op.execute(sa.text(f"DROP INDEX IF EXISTS {ix}"))
    op.drop_table(_NEW_TABLE)
