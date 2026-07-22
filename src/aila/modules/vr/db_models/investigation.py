"""Investigation table definition (M3.R-1).

Per D-50: one primary target per investigation + N secondary target
references (stored as JSON list).

Per D-43 GA-24: cost tracking has three streams (LLM tokens + MCP calls
+ fuzz infra). Each stream is summed into ``cost_actual_usd``.

Linked artifacts (campaign_ids, finding_ids) are stored as JSON lists
rather than denormalized through join tables -- querying 'all findings
from this investigation' is a low-volume operator action that doesn't
need indexed access.

The shared columns live on the platform base (RFC-01); this module sets
the concrete table + target FK target name and appends the partial
``is_favorite`` Index preserved from migration 058. VR carries no
investigation residue columns.
"""
from __future__ import annotations

from typing import ClassVar

from sqlalchemy import Index, text

from aila.platform.contracts.investigation_base import InvestigationRecordBase

__all__ = ["VRInvestigationRecord"]


class VRInvestigationRecord(InvestigationRecordBase, table=True):
    """One operator-initiated reasoning session (D-43, D-50)."""

    __tablename__ = "vr_investigations"
    __target_tablename__: ClassVar[str] = "vr_targets"

    # Migration 058 built a PARTIAL index on is_favorite (WHERE
    # is_favorite = true) rather than a full-table index. Declare it
    # here so create_all (tests, fresh installs) matches the migrated
    # production shape.
    __table_args__ = (
        *InvestigationRecordBase.__table_args__,
        Index(
            "ix_vr_investigations_is_favorite_true",
            "is_favorite",
            postgresql_where=text("is_favorite = true"),
        ),
    )
