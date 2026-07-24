"""Investigation-target join table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on
``aila.platform.contracts.investigation_target_base``; the concrete
below sets ``__tablename__``, ``__investigation_tablename__``, and
``__target_tablename__``. The ``UNIQUE(investigation_id, target_id)``
guard and both foreign keys are derived by the base against these
tablename ClassVars.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.investigation_target_base import (
    InvestigationTargetRecordBase,
)

__all__ = ["TemplateInvestigationTargetRecord"]


class TemplateInvestigationTargetRecord(InvestigationTargetRecordBase, table=True):
    """Scaffold: one (investigation, target, role) attachment."""

    __tablename__ = "template_investigation_targets"
    __investigation_tablename__: ClassVar[str] = "template_investigations"
    __target_tablename__: ClassVar[str] = "template_targets"
