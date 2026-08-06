"""118 -- RFC-11 zero-trust catalog gate for MCP server instances.

Layers the RFC-11 zero-trust gate over the operator-editable
``mcp_server_instances`` catalog created in 092:

* Five new columns on ``mcp_server_instances``:
    ``team_id`` (TEXT, indexed) -- per-team ownership; ``NULL`` = platform-wide.
    ``approval_state`` (TEXT, NOT NULL, server_default ``'pending'``) --
      one of ``pending`` / ``approved`` / ``revoked``. Live dispatch
      (Wave 2) filters ``approved_only=True`` so only ``approved`` rows
      are visible to the resolve path.
    ``approved_hash`` (TEXT, nullable) -- sha256 of the tool-schema
      projection pinned at approval time. Drift detection compares this
      against the last observed ``schema_hash``.
    ``schema_hash`` (TEXT, nullable) -- last observed sha256 of the
      live tool schema. Updated by the drift-check path
      (``GET /platform/mcp/instances/{id}/tools``) and by every
      approve call.
    ``server_card_json`` (TEXT, nullable) -- the ``.well-known/mcp.json``
      MCP Server Card fetched at approval time. Optional; the approve
      handler swallows the fetch failure and stores ``NULL``.

* One new table ``mcp_approval_change_log`` -- append-only audit of
  every ``approve`` / ``revoke`` transition (from state, to state,
  approver, schema hash pinned, reason on revoke).

GRANDFATHER RULE: every pre-existing row in ``mcp_server_instances``
is stamped ``approval_state='approved'`` by this migration so live
dispatch stays byte-identical to the pre-gate behaviour. Only rows
inserted AFTER 118 lands (via ``POST /platform/mcp/instances``) default
to ``pending``.

Existence-guarded per the pattern established by 113: every column
add and index / table create checks the bind's live schema first, so
a fresh test DB (``create_all`` already installed the columns) or a
partially-migrated DB does not crash the upgrade.

Revision ID: 118_mcp_trust_gate
Revises: 117_lifecycle_shadow_reports
Create Date: 2026-08-06
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "118_mcp_trust_gate"
down_revision: str | None = "117_lifecycle_shadow_reports"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_INSTANCE_TABLE: str = "mcp_server_instances"
_AUDIT_TABLE: str = "mcp_approval_change_log"

# (column_name, sa.Column factory kwargs handled inline in upgrade()).
_NEW_COLUMNS: tuple[str, ...] = (
    "team_id",
    "approval_state",
    "approved_hash",
    "schema_hash",
    "server_card_json",
)


def _existing_columns(table: str) -> set[str]:
    """Return the current column names for ``table`` on the bound DB.

    Empty set when the table does not exist so callers can skip both
    the add-column loop and the follow-up UPDATE (fresh test DB where
    ``create_all`` has not yet touched the catalog schema).
    """
    inspector = sa.inspect(op.get_bind())
    if table not in set(inspector.get_table_names()):
        return set()
    return {col["name"] for col in inspector.get_columns(table)}


def upgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    if _INSTANCE_TABLE in tables:
        present = _existing_columns(_INSTANCE_TABLE)

        if "team_id" not in present:
            op.add_column(
                _INSTANCE_TABLE,
                sa.Column("team_id", sa.Text(), nullable=True),
            )
            op.create_index(
                f"ix_{_INSTANCE_TABLE}_team_id",
                _INSTANCE_TABLE,
                ["team_id"],
            )

        if "approval_state" not in present:
            op.add_column(
                _INSTANCE_TABLE,
                sa.Column(
                    "approval_state",
                    sa.Text(),
                    nullable=False,
                    server_default="pending",
                ),
            )

        if "approved_hash" not in present:
            op.add_column(
                _INSTANCE_TABLE,
                sa.Column("approved_hash", sa.Text(), nullable=True),
            )

        if "schema_hash" not in present:
            op.add_column(
                _INSTANCE_TABLE,
                sa.Column("schema_hash", sa.Text(), nullable=True),
            )

        if "server_card_json" not in present:
            op.add_column(
                _INSTANCE_TABLE,
                sa.Column("server_card_json", sa.Text(), nullable=True),
            )

        # Grandfather any pre-existing operator-seeded rows to APPROVED so
        # live dispatch stays byte-identical after this migration lands.
        # Rows added via the API AFTER 118 default to 'pending' because
        # the model server_default and the ORM assign 'pending' up front,
        # so this UPDATE only touches rows whose approval_state column
        # was created by the ADD COLUMN above (all set to 'pending' by
        # the server_default).
        op.execute(sa.text(
            f"UPDATE {_INSTANCE_TABLE} "
            "SET approval_state='approved' "
            "WHERE approval_state='pending'",
        ))

    if _AUDIT_TABLE not in tables:
        op.create_table(
            _AUDIT_TABLE,
            sa.Column("id", sa.String(), primary_key=True, nullable=False),
            sa.Column("instance_id", sa.Text(), nullable=False, index=True),
            sa.Column("from_state", sa.Text(), nullable=False),
            sa.Column("to_state", sa.Text(), nullable=False),
            sa.Column("approver", sa.Text(), nullable=False),
            sa.Column("schema_hash", sa.Text(), nullable=True),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
        )
        op.create_index(
            f"ix_{_AUDIT_TABLE}_instance_created",
            _AUDIT_TABLE,
            ["instance_id", "created_at"],
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    tables = set(inspector.get_table_names())

    if _AUDIT_TABLE in tables:
        op.drop_index(
            f"ix_{_AUDIT_TABLE}_instance_created",
            table_name=_AUDIT_TABLE,
        )
        op.drop_table(_AUDIT_TABLE)

    if _INSTANCE_TABLE in tables:
        present = _existing_columns(_INSTANCE_TABLE)
        if "team_id" in present:
            op.drop_index(
                f"ix_{_INSTANCE_TABLE}_team_id",
                table_name=_INSTANCE_TABLE,
            )
        for col in _NEW_COLUMNS:
            if col in present:
                op.drop_column(_INSTANCE_TABLE, col)
