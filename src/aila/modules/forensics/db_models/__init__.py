"""Forensics module database models -- barrel re-export.

All table classes are imported here for external consumption.
Individual model definitions live in domain submodules.
"""
from __future__ import annotations

from .artifact import ArtifactRecord, LeadRecord
from .branch import ForensicsInvestigationBranchRecord
from .directive import AnalystDirectiveRecord
from .finding_suppression import FindingSuppressionRecord
from .investigation import AgentStepRecord, InvestigationRunRecord, WriteUpRecord
from .message import ForensicsInvestigationMessageRecord
from .outcome import ForensicsInvestigationOutcomeRecord
from .outcome_review import ForensicsInvestigationOutcomeReviewRecord
from .project import ForensicsProjectRecord, ProjectEvidenceRecord
from .question import AnswerCandidateRecord
from .solid_evidence import SolidEvidenceRecord
from .team_scope import (
    PROJECT_ID_COLUMN,
    PROJECT_SCOPED_CHILDREN,
    TEAM_ID_COLUMN,
    TEAM_SCOPED_PARENT,
    load_project_for_team,
    require_project_ownership,
)

__all__ = [
    "PROJECT_ID_COLUMN",
    "PROJECT_SCOPED_CHILDREN",
    "TEAM_ID_COLUMN",
    "TEAM_SCOPED_PARENT",
    "AgentStepRecord",
    "AnalystDirectiveRecord",
    "AnswerCandidateRecord",
    "ArtifactRecord",
    "FindingSuppressionRecord",
    "ForensicsInvestigationBranchRecord",
    "ForensicsInvestigationMessageRecord",
    "ForensicsInvestigationOutcomeRecord",
    "ForensicsInvestigationOutcomeReviewRecord",
    "ForensicsProjectRecord",
    "InvestigationRunRecord",
    "LeadRecord",
    "ProjectEvidenceRecord",
    "SolidEvidenceRecord",
    "WriteUpRecord",
    "load_project_for_team",
    "require_project_ownership",
]
