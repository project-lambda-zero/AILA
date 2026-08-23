"""131 -- drop the sbd_nfr module tables (module removed).

The Security by Design NFR (sbd_nfr) module was removed from the codebase.
Its Python package and frontend are deleted, so its ORM models no longer
exist. This migration drops the twelve tables the module owned so an existing
database matches the model set. A brand-new database builds its schema from
the current models (which no longer include sbd_nfr) and never creates these
tables, so the drops are guarded with IF EXISTS and become a no-op there.

Irreversible: the model definitions that described these tables are deleted,
so the schema cannot be faithfully reconstructed. ``downgrade()`` raises.

Revision ID: 131_drop_sbd_nfr
Revises: 130_auto_patch
Create Date: 2026-08-24
"""
from __future__ import annotations

from alembic import op

revision: str = "131_drop_sbd_nfr"
down_revision: str | None = "130_auto_patch"
branch_labels = None
depends_on = None

# Every table the sbd_nfr module owned. No foreign-key constraints link them,
# so drop order is irrelevant; CASCADE removes any dependent indexes or views.
_SBD_NFR_TABLES: tuple[str, ...] = (
    "sbd_nfr_activity_record",
    "sbd_nfr_answer_record",
    "sbd_nfr_question_option_record",
    "sbd_nfr_question_record",
    "sbd_nfr_question_subtask_map",
    "sbd_nfr_resolution_result_record",
    "sbd_nfr_schema_version_record",
    "sbd_nfr_section_record",
    "sbd_nfr_session_record",
    "sbd_nfr_session_system_record",
    "sbd_nfr_subgroup_record",
    "sbd_nfr_subtask_component_record",
)


def upgrade() -> None:
    for table in _SBD_NFR_TABLES:
        op.execute(f'DROP TABLE IF EXISTS "{table}" CASCADE')


def downgrade() -> None:
    raise NotImplementedError(
        "131 is irreversible: the sbd_nfr module and its ORM models were "
        "removed, so the dropped tables cannot be faithfully recreated.",
    )
