"""113 -- RFC-08 memory-poisoning trust tier + provenance envelope.

Adds two columns to every module's pattern table
(``vr_patterns``, ``malware_patterns``, ``forensics_patterns``,
``template_patterns``):

* ``trust_tier`` (varchar(16), NOT NULL, server_default ``'unreviewed'``,
  indexed) -- one of ``verified`` / ``unreviewed`` / ``negative``. Stamped
  by the sole write path that produced the row: a signed
  :class:`QuorumOutcome` routed through :class:`ExperienceWriter` writes
  ``verified`` (approved) / ``negative`` (rejected); sanctioned DRAFT
  proposers (``pattern_extractor`` / ``pattern_proposer``) write
  ``unreviewed``. Pre-existing rows migrate to ``unreviewed`` so a
  historic auto-extracted pattern stays inert (equivalent to a fresh
  draft) rather than promoted-by-accident.
* ``provenance_json`` (text, nullable, server_default ``'{}'``) --
  audit envelope carrying ``source`` + originating outcome /
  investigation ids so a poisoned catalog can be traced back to the
  pipeline that wrote it.

Retrieval reads both: NEGATIVE rows never enter the actionable result
list, and their applicability overlap lowers a positive's score as a
prior (see :meth:`PatternStoreBase.applicable` +
:func:`_applicability_overlaps`). RFC-08 explicitly forbids
hard-blocking on a NEGATIVE -- always a prior, never a gate.

Revision ID: 113_pattern_trust_provenance
Revises: 112_eval_calibrator
Create Date: 2026-08-05
"""
from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision: str = "113_pattern_trust_provenance"
down_revision: str | None = "112_eval_calibrator"
branch_labels = None
depends_on = None


# Every deployed module's pattern table gets the same two columns + the
# same trust_tier index. Kept as a tuple so ``upgrade`` / ``downgrade``
# iterate once each and can never fall out of sync -- adding a fifth
# module later is one line here, not four in each function.
#
# ``template_patterns`` belongs to the ``_template`` copy-me scaffold,
# which is never registered as a live module, so no migration creates its
# table and it is absent from the live DB (it exists only in a test DB
# built via ``create_all``). Each column op is therefore guarded on the
# table actually existing in the bound database -- the scaffold table is
# skipped live and picked up automatically anywhere it does exist.
_PATTERN_TABLES: tuple[str, ...] = (
    "vr_patterns",
    "malware_patterns",
    "forensics_patterns",
    "template_patterns",
)


def _existing_tables() -> set[str]:
    """Return the subset of _PATTERN_TABLES present in the bound DB."""
    inspector = sa.inspect(op.get_bind())
    present = set(inspector.get_table_names())
    return {t for t in _PATTERN_TABLES if t in present}


def upgrade() -> None:
    for table in sorted(_existing_tables()):
        op.add_column(
            table,
            sa.Column(
                "trust_tier",
                sa.String(16),
                nullable=False,
                server_default="unreviewed",
            ),
        )
        op.add_column(
            table,
            sa.Column(
                "provenance_json",
                sa.Text(),
                nullable=True,
                server_default="{}",
            ),
        )
        op.create_index(
            f"ix_{table}_trust_tier",
            table,
            ["trust_tier"],
        )


def downgrade() -> None:
    for table in sorted(_existing_tables()):
        op.drop_index(f"ix_{table}_trust_tier", table_name=table)
        op.drop_column(table, "provenance_json")
        op.drop_column(table, "trust_tier")
