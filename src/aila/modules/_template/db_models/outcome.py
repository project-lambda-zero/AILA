"""Investigation-outcome table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.outcome_base``; the
concrete below sets ``__tablename__``, ``__investigation_tablename__``,
and ``__branch_tablename__``.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.outcome_base import OutcomeRecordBase

__all__ = ["TemplateInvestigationOutcomeRecord"]


class TemplateInvestigationOutcomeRecord(OutcomeRecordBase, table=True):
    """Scaffold: one typed outcome emitted by an investigation branch."""

    __tablename__ = "template_investigation_outcomes"
    __investigation_tablename__: ClassVar[str] = "template_investigations"
    __branch_tablename__: ClassVar[str] = "template_investigation_branches"
