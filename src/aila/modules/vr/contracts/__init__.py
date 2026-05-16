"""Public contract models for the vulnerability research module.

Barrel re-export only. Model definitions live in domain submodules.
"""
from __future__ import annotations

from .advisory import CVSSVector, CWEMapping, VRAdvisory
from .audit_memo import (
    AuditMemoCreate,
    AuditMemoScope,
    AuditMemoSummary,
)
from .branch import (
    BranchOperation,
    BranchStatus,
    PersonaVoice,
    VRBranchSummary,
)
from .enrichment import (
    EnrichmentError,
    EnrichmentResult,
    MitigationFlags,
    TargetCapabilityProfile,
)
from .finding import (
    CrashSignature,
    CrashType,
    DisclosureStatus,
    PoCResult,
    VRFinding,
)
from .investigation import (
    InvestigationKind,
    InvestigationPauseReason,
    InvestigationStatus,
    VRInvestigationCreate,
    VRInvestigationSummary,
)
from .message import (
    OperatorIntent,
    PayloadKind,
    SenderKind,
    VRMessageCreate,
    VRMessageSummary,
)
from .outcome import (
    OutcomeConfidence,
    OutcomeDispatchStatus,
    OutcomeKind,
    VROutcomeCreate,
    VROutcomeSummary,
)
from .project import (
    InputSource,
    TargetClass,
    TargetFormat,
    TargetIngestionSpec,
    VRProjectCreate,
    VRProjectStatus,
    VRProjectSummary,
)
from .target import (
    EnrichmentStatus,
    TargetKind,
    TargetStatus,
    TargetTag,
    TargetTagSource,
    VRTargetCreate,
    VRTargetSummary,
)
from .workspace import (
    VRWorkspaceCreate,
    VRWorkspaceSummary,
    WorkspaceStatus,
    WorkspaceTheme,
)

__all__ = [
    "AuditMemoCreate",
    "AuditMemoScope",
    "AuditMemoSummary",
    "BranchOperation",
    "BranchStatus",
    "CVSSVector",
    "CWEMapping",
    "CrashSignature",
    "CrashType",
    "DisclosureStatus",
    "EnrichmentError",
    "EnrichmentResult",
    "EnrichmentStatus",
    "InputSource",
    "InvestigationKind",
    "InvestigationPauseReason",
    "InvestigationStatus",
    "MitigationFlags",
    "OperatorIntent",
    "OutcomeConfidence",
    "OutcomeDispatchStatus",
    "OutcomeKind",
    "PayloadKind",
    "PersonaVoice",
    "PoCResult",
    "SenderKind",
    "TargetCapabilityProfile",
    "TargetClass",
    "TargetFormat",
    "TargetIngestionSpec",
    "TargetKind",
    "TargetStatus",
    "TargetTag",
    "TargetTagSource",
    "VRAdvisory",
    "VRBranchSummary",
    "VRFinding",
    "VRInvestigationCreate",
    "VRInvestigationSummary",
    "VRMessageCreate",
    "VRMessageSummary",
    "VROutcomeCreate",
    "VROutcomeSummary",
    "VRProjectCreate",
    "VRProjectStatus",
    "VRProjectSummary",
    "VRTargetCreate",
    "VRTargetSummary",
    "VRWorkspaceCreate",
    "VRWorkspaceSummary",
    "WorkspaceStatus",
    "WorkspaceTheme",
]
