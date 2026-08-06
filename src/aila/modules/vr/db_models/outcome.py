"""Investigation outcome table -- vr concrete (D-43).

All columns come from the shared platform base; see
:mod:`aila.platform.contracts.outcome_base`.
"""
from __future__ import annotations

from aila.platform.contracts.outcome_base import OutcomeRecordBase

__all__ = ["VRInvestigationOutcomeRecord"]


class VRInvestigationOutcomeRecord(OutcomeRecordBase, table=True):
    """One typed outcome emitted by an investigation branch (D-43)."""

    __tablename__ = "vr_investigation_outcomes"
    __investigation_tablename__ = "vr_investigations"
    __branch_tablename__ = "vr_investigation_branches"
