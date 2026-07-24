"""Outcome-review table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.outcome_review_base``;
the concrete below sets ``__tablename__``, ``__outcome_tablename__``,
and ``__branch_tablename__``. The ``UNIQUE(outcome_id,
reviewer_branch_id)`` guard and the ON DELETE CASCADE foreign keys are
derived by the base against these tablename ClassVars.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.outcome_review_base import OutcomeReviewRecordBase

__all__ = ["TemplateInvestigationOutcomeReviewRecord"]


class TemplateInvestigationOutcomeReviewRecord(OutcomeReviewRecordBase, table=True):
    """Scaffold: one sibling vote on a draft outcome."""

    __tablename__ = "template_investigation_outcome_reviews"
    __outcome_tablename__: ClassVar[str] = "template_investigation_outcomes"
    __branch_tablename__: ClassVar[str] = "template_investigation_branches"
