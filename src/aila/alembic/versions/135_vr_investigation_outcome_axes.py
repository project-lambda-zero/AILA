"""135 -- add ``vr_investigations.primary_outcome_polarity`` and
``verifier_verdict`` denormalized filter columns + backfill from the
primary outcome.

The investigations-list endpoint needs to filter by outcome polarity
(finding / no_finding / inconclusive) and by verifier verdict without
loading + JSON-parsing each row's primary outcome payload per request.
Both values are pure functions of the primary outcome's ``outcome_kind``
and ``payload_json`` (see ``modules/vr/services/outcome_polarity``);
the write hooks in the vuln-researcher outcome upsert, the reset path
in the router, and the claim verifier's post-persist hook keep the
denormalized columns in sync going forward. This migration seeds the
columns for every existing row so the new filters return correct
results immediately.

Backfill logic is inlined (not imported from app code) so the migration
stays self-contained + frozen. Existing rows without a primary outcome
stay NULL. Backfill is deterministic and idempotent per row.

Revision ID: 135_vr_investigation_outcome_axes
Revises:     134_fuzz_proposal_nullable_ctx
Create Date: 2026-08-25
"""
from __future__ import annotations

import json

import sqlalchemy as sa

from alembic import op

revision: str = "135_vr_investigation_outcome_axes"
down_revision: str | None = "134_fuzz_proposal_nullable_ctx"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


_TABLE: str = "vr_investigations"
_OUTCOME_TABLE: str = "vr_investigation_outcomes"

_COL_POLARITY: str = "primary_outcome_polarity"
_COL_VERDICT: str = "verifier_verdict"

_IX_POLARITY: str = "ix_vr_investigations_primary_outcome_polarity"
_IX_VERDICT: str = "ix_vr_investigations_verifier_verdict"


def _inspector() -> sa.engine.reflection.Inspector:
    return sa.inspect(op.get_bind())


def _has_table(name: str) -> bool:
    return name in set(_inspector().get_table_names())


def _has_column(table: str, column: str) -> bool:
    if not _has_table(table):
        return False
    cols = {c["name"] for c in _inspector().get_columns(table)}
    return column in cols


def _has_index(table: str, index_name: str) -> bool:
    if not _has_table(table):
        return False
    names = {ix["name"] for ix in _inspector().get_indexes(table)}
    return index_name in names


def _derive_polarity(outcome_kind: str, payload: dict) -> str | None:
    """Frozen copy of ``derive_outcome_polarity`` -- see
    ``modules/vr/services/outcome_polarity``. Kept inline so the
    migration never imports app code (Alembic + shifting model
    definitions do not mix).
    """
    if not outcome_kind:
        return None
    verifier_report = payload.get("verifier_report")
    if isinstance(verifier_report, dict):
        v = verifier_report.get("verdict")
        if v == "confirmed":
            return "finding"
        if v == "refuted":
            return "no_finding"
    if outcome_kind == "direct_finding":
        return "finding"
    if outcome_kind == "audit_memo" and payload.get("verdict") == "no_finding":
        return "no_finding"
    return "inconclusive"


def _derive_verdict(payload: dict) -> str | None:
    """Frozen copy of ``derive_verifier_verdict``."""
    report = payload.get("verifier_report")
    if isinstance(report, dict):
        v = report.get("verdict")
        if isinstance(v, str) and v:
            return v
    return None


def upgrade() -> None:
    if not _has_table(_TABLE):
        return

    if not _has_column(_TABLE, _COL_POLARITY):
        op.add_column(
            _TABLE,
            sa.Column(_COL_POLARITY, sa.String(length=16), nullable=True),
        )
    if not _has_column(_TABLE, _COL_VERDICT):
        op.add_column(
            _TABLE,
            sa.Column(_COL_VERDICT, sa.String(length=32), nullable=True),
        )
    if not _has_index(_TABLE, _IX_POLARITY):
        op.create_index(_IX_POLARITY, _TABLE, [_COL_POLARITY])
    if not _has_index(_TABLE, _IX_VERDICT):
        op.create_index(_IX_VERDICT, _TABLE, [_COL_VERDICT])

    if not _has_table(_OUTCOME_TABLE):
        return

    bind = op.get_bind()
    rows = bind.execute(sa.text(
        f"SELECT i.id AS inv_id, o.outcome_kind AS outcome_kind, "
        f"o.payload_json AS payload_json "
        f"FROM {_TABLE} i "
        f"JOIN {_OUTCOME_TABLE} o ON o.id = i.primary_outcome_id "
        f"WHERE i.primary_outcome_id IS NOT NULL"
    )).fetchall()

    update_stmt = sa.text(
        f"UPDATE {_TABLE} SET {_COL_POLARITY} = :polarity, "
        f"{_COL_VERDICT} = :verdict WHERE id = :inv_id"
    )
    for row in rows:
        raw = row.payload_json or "{}"
        try:
            payload = json.loads(raw)
        except (ValueError, TypeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        polarity = _derive_polarity(row.outcome_kind or "", payload)
        verdict = _derive_verdict(payload)
        bind.execute(
            update_stmt,
            {"polarity": polarity, "verdict": verdict, "inv_id": row.inv_id},
        )


def downgrade() -> None:
    if not _has_table(_TABLE):
        return
    if _has_index(_TABLE, _IX_VERDICT):
        op.drop_index(_IX_VERDICT, table_name=_TABLE)
    if _has_index(_TABLE, _IX_POLARITY):
        op.drop_index(_IX_POLARITY, table_name=_TABLE)
    if _has_column(_TABLE, _COL_VERDICT):
        op.drop_column(_TABLE, _COL_VERDICT)
    if _has_column(_TABLE, _COL_POLARITY):
        op.drop_column(_TABLE, _COL_POLARITY)
