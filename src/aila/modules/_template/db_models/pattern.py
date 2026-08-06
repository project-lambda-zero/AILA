"""Pattern catalog table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.pattern_base``; the
concrete below sets ``__tablename__``, ``__workspace_tablename__``, and
``__investigation_tablename__``. The FK constraints are derived by
``TableDerivedConstraintsMixin`` from those ClassVars at class-creation
time.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.pattern_base import PatternRecordBase

__all__ = ["TemplatePatternRecord"]


class TemplatePatternRecord(PatternRecordBase, table=True):
    """Scaffold: catalog entry for one reusable pattern."""

    __tablename__ = "template_patterns"
    __workspace_tablename__: ClassVar[str] = "template_workspaces"
    __investigation_tablename__: ClassVar[str] = "template_investigations"
