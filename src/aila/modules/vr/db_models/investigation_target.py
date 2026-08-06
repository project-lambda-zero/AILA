"""vr_investigation_targets join table -- vr concrete (v0.4 multi-target).

All columns come from the shared platform base; see
:mod:`aila.platform.contracts.investigation_target_base`. The unique
``(investigation_id, target_id)`` guard and the foreign keys are derived by
the base against this table's names.
"""
from __future__ import annotations

from aila.platform.contracts.investigation_target_base import (
    InvestigationTargetRecordBase,
)

__all__ = ["VRInvestigationTargetRecord"]


class VRInvestigationTargetRecord(InvestigationTargetRecordBase, table=True):
    """One (investigation, target, role) attachment."""

    __tablename__ = "vr_investigation_targets"
    __investigation_tablename__ = "vr_investigations"
    __target_tablename__ = "vr_targets"
