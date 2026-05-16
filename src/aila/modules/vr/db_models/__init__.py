"""Vulnerability research module database models — barrel re-export.

All table classes are imported here for external consumption.
Individual model definitions live in domain submodules.
"""
from __future__ import annotations

from .branch import VRInvestigationBranchRecord
from .disclosure import VRDisclosureSubmissionRecord
from .finding import VRFindingRecord
from .fuzz import VRFuzzCampaignRecord, VRFuzzCrashRecord
from .investigation import VRInvestigationRecord
from .message import VRInvestigationMessageRecord
from .outcome import VRInvestigationOutcomeRecord
from .pattern import VRPatternRecord
from .project import VRProjectRecord
from .target import VRTargetRecord, VRTargetTagIndexRecord
from .workspace import VRWorkspaceRecord

__all__ = [
    "VRDisclosureSubmissionRecord",
    "VRFindingRecord",
    "VRFuzzCampaignRecord",
    "VRFuzzCrashRecord",
    "VRInvestigationBranchRecord",
    "VRInvestigationMessageRecord",
    "VRInvestigationOutcomeRecord",
    "VRInvestigationRecord",
    "VRPatternRecord",
    "VRProjectRecord",
    "VRTargetRecord",
    "VRTargetTagIndexRecord",
    "VRWorkspaceRecord",
]
