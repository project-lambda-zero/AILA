"""106 -- workflowrunrecord route_json/short_memory_json/summary_json TEXT -> JSONB (#45).

Completes the #45 remaining leg by promoting the three JSON-in-Text columns
on ``workflowrunrecord`` to true ``JSONB``. Once the columns are JSONB,
SQLAlchemy owns dict<->jsonb serialization uniformly across the async
(asyncpg) and sync (psycopg) drivers, eliminating the raw-driver divergence
that migration 104 explicitly deferred (see its module docstring).

The upgrade converts existing rows in place using the ``aila_is_valid_json``
helper installed by migration 104:

    ALTER TABLE workflowrunrecord
        ALTER COLUMN route_json TYPE jsonb
        USING (
            CASE WHEN aila_is_valid_json(route_json)
                 THEN route_json::jsonb
                 ELSE '{}'::jsonb
            END
        )

A row that survived the (NOT VALID) CHECK from migration 104 with a
malformed payload is coerced to ``'{}'::jsonb`` rather than aborting the
whole migration. The CHECK constraints themselves are dropped in this
migration because a JSONB column is always valid JSON by construction --
the CHECK becomes tautological once the column type flips. The
``aila_is_valid_json`` helper stays installed (kept for any operator query
or future migration that revisits legacy text-json data); dropping it here
would break migration 104's downgrade path.

Downgrade converts the columns back to ``text`` via ``USING <col>::text``
which re-materialises the JSONB back into a canonical text representation,
then re-adds the NOT VALID CHECK constraints so state at "105 after
downgrade from 106" matches state at "105 before upgrade to 106". The
helper is re-installed with ``CREATE OR REPLACE FUNCTION`` (idempotent)
so a downgrade from a fresh bootstrap stamped at head -- where migration
104's upgrade never actually ran -- still lands cleanly.

Revision ID: 106_workflowrun_json_to_jsonb
Revises:     105_automation_run_history
Create Date: 2026-07-27
"""
from __future__ import annotations

from alembic import op

revision: str = "106_workflowrun_json_to_jsonb"
down_revision: str | None = "105_automation_run_history"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "workflowrunrecord"
_JSON_COLUMNS: tuple[str, ...] = (
    "route_json",
    "short_memory_json",
    "summary_json",
)


def _constraint_name(column: str) -> str:
    # Mirrors migration 104's naming so we can drop / re-add the exact rows.
    return f"ck_wfr_{column}_valid_json"


def upgrade() -> None:
    # 1) Drop migration 104's NOT VALID CHECK constraints first. A JSONB
    #    column is always valid JSON, so keeping the CHECK would be
    #    tautological (and it references the pre-cast text column, so it
    #    would trip during the type-flip planning).
    for column in _JSON_COLUMNS:
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"DROP CONSTRAINT IF EXISTS {_constraint_name(column)}"
        )

    # 2) Flip each column to JSONB. Malformed rows (that survived under
    #    the NOT VALID CHECK) are rescued to '{}'::jsonb via the helper
    #    installed in migration 104. Set NOT NULL + a JSONB '{}' default
    #    so fresh rows behave identically to the SQLModel-declared shape.
    #
    #    DROP DEFAULT before the type flip: the pre-JSONB default is the
    #    text literal ``'{}'``, and PostgreSQL refuses to auto-cast it into
    #    a JSONB expression during ALTER COLUMN TYPE (raises
    #    ``DatatypeMismatch: default for column ... cannot be cast
    #    automatically to type jsonb``). Re-attach a JSONB-typed default
    #    after the flip.
    for column in _JSON_COLUMNS:
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ALTER COLUMN {column} DROP DEFAULT"
        )
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ALTER COLUMN {column} TYPE jsonb "
            f"USING (CASE WHEN {column} IS NULL THEN '{{}}'::jsonb "
            f"WHEN aila_is_valid_json({column}) "
            f"THEN {column}::jsonb "
            f"ELSE '{{}}'::jsonb END)"
        )
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ALTER COLUMN {column} SET DEFAULT '{{}}'::jsonb"
        )
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ALTER COLUMN {column} SET NOT NULL"
        )


def downgrade() -> None:
    # Reverse the flip: cast JSONB back to text (canonical JSON text form),
    # restore the string '{}' default, then re-add migration 104's
    # NOT VALID CHECK constraints so the downgrade stack is symmetric with
    # the upgrade path.
    #
    # The helper is re-installed with CREATE OR REPLACE FUNCTION -- migration
    # 104's upgrade defines it identically. Idempotently re-creating it here
    # keeps the downgrade functional even when the DB was bootstrapped via
    # create_all + stamp-at-head (which never actually ran 104), avoiding a
    # missing-function abort on the CHECK constraint re-add.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION aila_is_valid_json(t text)
        RETURNS boolean
        LANGUAGE plpgsql
        IMMUTABLE
        AS $$
        BEGIN
            IF t IS NULL THEN
                RETURN TRUE;
            END IF;
            PERFORM t::jsonb;
            RETURN TRUE;
        EXCEPTION WHEN others THEN
            RETURN FALSE;
        END;
        $$
        """
    )

    for column in _JSON_COLUMNS:
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ALTER COLUMN {column} DROP DEFAULT"
        )
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ALTER COLUMN {column} TYPE text "
            f"USING {column}::text"
        )
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ALTER COLUMN {column} SET DEFAULT '{{}}'"
        )
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ADD CONSTRAINT {_constraint_name(column)} "
            f"CHECK (aila_is_valid_json({column})) NOT VALID"
        )
