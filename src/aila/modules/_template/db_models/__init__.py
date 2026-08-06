"""Template module database models -- barrel re-export.

Scaffold demonstrating the RFC-01 base-subclass pattern for a new
module. Copy this package alongside the rest of the ``_template``
skeleton and rename ``Template`` / ``template_`` to your module's
identifier. Nothing here registers in the live app or in production
migrations: the ``_template`` package is skipped by module discovery
because its name starts with an underscore.

All shared columns live on ``aila.platform.contracts.<x>_base``; each
concrete below only sets the concrete table name, the required FK
tablename ClassVars called out by its base docstring, and any
module-specific residue or Index the module wants to layer on top.
"""
from __future__ import annotations

from .branch import TemplateInvestigationBranchRecord
from .investigation import TemplateInvestigationRecord
from .investigation_target import TemplateInvestigationTargetRecord
from .mcp_call_log import TemplateMcpCallLogRecord
from .message import TemplateInvestigationMessageRecord
from .outcome import TemplateInvestigationOutcomeRecord
from .outcome_review import TemplateInvestigationOutcomeReviewRecord
from .pattern import TemplatePatternRecord
from .project import TemplateProjectRecord
from .target import TemplateTargetRecord, TemplateTargetTagIndexRecord
from .workspace import TemplateWorkspaceRecord

__all__ = [
    "TemplateInvestigationBranchRecord",
    "TemplateInvestigationMessageRecord",
    "TemplateInvestigationOutcomeRecord",
    "TemplateInvestigationOutcomeReviewRecord",
    "TemplateInvestigationRecord",
    "TemplateInvestigationTargetRecord",
    "TemplateMcpCallLogRecord",
    "TemplatePatternRecord",
    "TemplateProjectRecord",
    "TemplateTargetRecord",
    "TemplateTargetTagIndexRecord",
    "TemplateWorkspaceRecord",
]
