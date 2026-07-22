"""Investigation table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.investigation_base``;
the concrete below sets ``__tablename__`` + ``__target_tablename__``.
The parent-investigation FK is self-referential and derived by the base
against this class's own ``__tablename__`` -- no ClassVar needed for it.

Demonstrates the module-specific Index override: ``is_favorite`` is a
plain column on the base (index shape differs per module), so the
subclass appends its flavor to ``__table_args__``. The malware full-
column form is used here (vr uses a partial index instead); pick
whichever matches your query pattern.
"""
from __future__ import annotations

from typing import ClassVar

from sqlalchemy import Index

from aila.platform.contracts.investigation_base import InvestigationRecordBase

__all__ = ["TemplateInvestigationRecord"]


class TemplateInvestigationRecord(InvestigationRecordBase, table=True):
    """Scaffold: one operator-initiated reasoning session."""

    __tablename__ = "template_investigations"
    __target_tablename__: ClassVar[str] = "template_targets"

    # Splice ahead of the base's foreign-key markers so
    # ``__init_subclass__`` still resolves them at class-creation time.
    __table_args__ = (
        *InvestigationRecordBase.__table_args__,
        Index("ix_template_investigations_is_favorite", "is_favorite"),
    )
