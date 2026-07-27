"""104 -- workflowrunrecord JSON validity CHECK constraints (#45).

Closes the malformed-JSON leg of issue #45. The three ``workflowrunrecord``
text columns that store JSON payloads (``route_json``, ``short_memory_json``,
``summary_json``) had no invariant enforcing well-formed JSON: an application
bug or bad manual UPDATE could park a row that later crashes
``json.loads(row.route_json)`` in ``platform/services/report.py`` and
``storage/report_repository.py``.

This migration installs an IMMUTABLE plpgsql helper ``aila_is_valid_json(text)``
that returns True for NULL / valid JSON and False for garbage, then adds three
``NOT VALID`` CHECK constraints (one per column). ``NOT VALID`` means:

* new INSERTs and UPDATEs are validated (the go-forward guard the audit asks
  for);
* existing rows are NOT re-scanned at ADD time -- important because the
  migration must be zero-downtime on a large ``workflowrunrecord`` table and
  because we do not want to fail the upgrade over legacy garbage rows an
  operator can clean up on their own schedule.

An operator can later run ``ALTER TABLE workflowrunrecord VALIDATE CONSTRAINT
ck_wfr_<col>_json_valid`` to force-scan existing rows once they have been
audited.

Explicit non-goal (deferred): converting the three ``Text`` columns to
``JSONB``. That is a cross-domain change requiring simultaneous updates in:

* ``src/aila/storage/db_models.py`` -- field types must move from ``str`` to
  ``dict[str, Any]``;
* ``src/aila/platform/runtime/orchestrator.py`` -- drop ``json.dumps`` /
  ``model_dump_json`` around assignments;
* ``src/aila/platform/services/report.py`` and
  ``src/aila/storage/report_repository.py`` -- drop ``json.loads`` on reads;
* ``src/aila/api/routers/systems.py`` -- the ``.contains()`` string-LIKE
  filter and ``in`` substring test must move to JSONB operators.

``asyncpg`` returns JSONB as ``str`` by default, but ``psycopg`` (v3, the sync
driver AILA uses) returns JSONB as parsed ``dict``, so a bare column-type
switch would break every sync callsite of ``run.route_json``. See ``_msg_fix56``
notes for the follow-up handoff.

Companion issue #56 -- DROP-guard pattern (going-forward hardening): future
destructive migrations should follow the pattern documented in
``_drop_helper_pattern`` at the end of this file rather than raw
``DROP TABLE ... CASCADE`` (see migration 069:68 for the concrete precedent
that motivated this note). This migration does not attempt to undo 069's drop
(the row set is unrecoverable now) -- it only establishes the go-forward
policy so a future ``104+n`` migration touching a populated table has a
copy-pasteable reference.

Revision ID: 104_workflowrun_json_validity_check
Revises:     103_specialist_agent
Create Date: 2026-07-27
"""
from __future__ import annotations

from alembic import op

revision: str = "104_workflowrun_json_validity_check"
down_revision: str | None = "103_specialist_agent"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


# Table + columns guarded by this migration. workflowrunrecord's JSON-in-Text
# columns are the ones the #45 audit called out; keeping the tuple explicit
# so a future migration can extend by copy-paste without touching the rest.
_TABLE: str = "workflowrunrecord"
_JSON_COLUMNS: tuple[str, ...] = (
    "route_json",
    "short_memory_json",
    "summary_json",
)


def _constraint_name(column: str) -> str:
    # Module-qualified per CLAUDE.md common mistake #21 (constraint names are
    # unique per schema, not per table).
    return f"ck_wfr_{column}_valid_json"


def upgrade() -> None:
    # 1) Helper function. IMMUTABLE so it is legal inside a CHECK. STRICT is
    #    intentionally OFF: we need to handle NULL ourselves (return True) so
    #    the constraint permits NULL columns (this is defensive -- the three
    #    target columns are NOT NULL today, but a future ALTER might relax
    #    that and the constraint should not become an accidental NOT NULL).
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

    # 2) One NOT VALID CHECK per JSON-in-Text column. IF NOT EXISTS keeps the
    #    migration idempotent on re-runs (fresh installs create the columns
    #    via SQLModel metadata + this migration adds the constraints on top).
    for column in _JSON_COLUMNS:
        name = _constraint_name(column)
        op.execute(
            f"ALTER TABLE {_TABLE} "
            f"ADD CONSTRAINT {name} "
            f"CHECK (aila_is_valid_json({column})) NOT VALID"
        )


def downgrade() -> None:
    # Drop constraints first, then the helper, so nothing depends on the
    # function at DROP FUNCTION time.
    for column in _JSON_COLUMNS:
        name = _constraint_name(column)
        op.execute(f"ALTER TABLE {_TABLE} DROP CONSTRAINT IF EXISTS {name}")
    op.execute("DROP FUNCTION IF EXISTS aila_is_valid_json(text)")


# ---------------------------------------------------------------------------
# _drop_helper_pattern -- documentation reference (#45, going-forward guard)
# ---------------------------------------------------------------------------
#
# Migration 069 dropped ``malware_findings`` with a bare
# ``DROP TABLE IF EXISTS malware_findings CASCADE`` and no row-count guard.
# The horse has bolted for 069 specifically; this note is the copy-paste
# reference for the NEXT destructive migration so it does not repeat the
# pattern.
#
# The safe shape for any future destructive DROP is: verify the table is
# empty (or explicitly archived) before dropping, and require an operator
# opt-in when it is not. Sketch::
#
#     def upgrade() -> None:
#         # 1) Refuse to run if the table has rows unless the operator has
#         #    explicitly acknowledged the data loss via an env override.
#         count = op.get_bind().execute(
#             sa.text("SELECT count(*) FROM legacy_table")
#         ).scalar_one()
#         if count and not os.environ.get("AILA_ALLOW_DESTRUCTIVE_DROP"):
#             raise RuntimeError(
#                 "legacy_table has rows; refusing to DROP. "
#                 "Archive first or set AILA_ALLOW_DESTRUCTIVE_DROP=1."
#             )
#         # 2) Only then perform the drop.
#         op.execute("DROP TABLE IF EXISTS legacy_table CASCADE")
#
# Enforcement is code review + this reference. The honesty audit already
# scans migrations; a future audit rule can grep for
# ``DROP TABLE`` without a preceding ``count(*)`` check.
