"""Panel investigation outcome -- forensics concrete (#18).

All columns come from the shared platform base; see
:mod:`aila.platform.contracts.outcome_base`. A panel role submits a
draft outcome (state='draft'); siblings vote via the outcome-review
table; :func:`aila.platform.services.outcome_review.evaluate_quorum`
flips ``state`` to 'approved' or 'rejected' when the tally reaches the
module veto/quorum threshold.
"""
from __future__ import annotations

from aila.platform.contracts.outcome_base import OutcomeRecordBase

__all__ = ["ForensicsInvestigationOutcomeRecord"]


class ForensicsInvestigationOutcomeRecord(OutcomeRecordBase, table=True):
    """One typed outcome emitted by a forensics panel branch (#18)."""

    __tablename__ = "forensics_investigation_outcomes"
    __investigation_tablename__ = "forensics_investigations"
    __branch_tablename__ = "forensics_investigation_branches"
