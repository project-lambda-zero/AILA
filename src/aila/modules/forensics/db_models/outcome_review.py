"""Sibling-review of a draft panel outcome -- forensics concrete (#18).

All columns come from the shared platform base; see
:mod:`aila.platform.contracts.outcome_review_base`. The unique
``(outcome_id, reviewer_branch_id)`` guard keeps a single reviewing
branch to one vote per outcome and the ON DELETE CASCADE foreign keys
are derived by the base against this table's names.
"""
from __future__ import annotations

from aila.platform.contracts.outcome_review_base import OutcomeReviewRecordBase

__all__ = ["ForensicsInvestigationOutcomeReviewRecord"]


class ForensicsInvestigationOutcomeReviewRecord(OutcomeReviewRecordBase, table=True):
    """One sibling vote on a draft forensics panel outcome (#18)."""

    __tablename__ = "forensics_outcome_reviews"
    __outcome_tablename__ = "forensics_investigation_outcomes"
    __branch_tablename__ = "forensics_investigation_branches"
