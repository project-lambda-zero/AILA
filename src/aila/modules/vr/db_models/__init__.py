"""Vulnerability research module database models -- barrel re-export.

All table classes are imported here for external consumption.
Individual model definitions live in domain submodules.
"""
from __future__ import annotations

from .branch import VRInvestigationBranchRecord
from .cve import VRCVEFeedStateRecord, VRCVERecord
from .disclosure import VRDisclosureSubmissionRecord
from .finding import VRFindingRecord
from .fuzz import VRFuzzCampaignRecord, VRFuzzCrashRecord
from .fuzz_proposal import VRFuzzCampaignProposalRecord
from .investigation import VRInvestigationRecord
from .investigation_target import VRInvestigationTargetRecord
from .mcp_call_log import VRMcpCallLogRecord
from .message import VRInvestigationMessageRecord
from .outcome import VRInvestigationOutcomeRecord
from .outcome_review import VRInvestigationOutcomeReviewRecord
from .pattern import VRPatternRecord
from .project import VRProjectRecord
from .target import VRTargetRecord, VRTargetTagIndexRecord
from .telemetry import VRFuzzTelemetryRecord
from .workspace import VRWorkspaceRecord

__all__ = [
    "VRDisclosureSubmissionRecord",
    "VRCVEFeedStateRecord",
    "VRCVERecord",
    "VRFindingRecord",
    "VRFuzzCampaignRecord",
    "VRFuzzCrashRecord",
    "VRFuzzCampaignProposalRecord",
    "VRFuzzTelemetryRecord",
    "VRInvestigationBranchRecord",
    "VRInvestigationMessageRecord",
    "VRInvestigationOutcomeRecord",
    "VRInvestigationOutcomeReviewRecord",
    "VRMcpCallLogRecord",
    "VRInvestigationRecord",
    "VRInvestigationTargetRecord",
    "VRPatternRecord",
    "VRProjectRecord",
    "VRTargetRecord",
    "VRTargetTagIndexRecord",
    "VRWorkspaceRecord",
]
