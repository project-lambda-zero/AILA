"""Public contract models for the vulnerability research module.

Barrel re-export only. Model definitions live in domain submodules.
"""
from __future__ import annotations

from .advisory import CVSSVector, CWEMapping, VRAdvisory
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
from .project import (
    InputSource,
    TargetClass,
    TargetFormat,
    VRProjectCreate,
    VRProjectStatus,
    VRProjectSummary,
    VRTarget,
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
    "CVSSVector",
    "CWEMapping",
    "CrashSignature",
    "CrashType",
    "DisclosureStatus",
    "EnrichmentError",
    "EnrichmentResult",
    "EnrichmentStatus",
    "InputSource",
    "MitigationFlags",
    "PoCResult",
    "TargetCapabilityProfile",
    "TargetClass",
    "TargetFormat",
    "TargetKind",
    "TargetStatus",
    "TargetTag",
    "TargetTagSource",
    "VRAdvisory",
    "VRFinding",
    "VRProjectCreate",
    "VRProjectStatus",
    "VRProjectSummary",
    "VRTarget",
    "VRTargetCreate",
    "VRTargetSummary",
    "VRWorkspaceCreate",
    "VRWorkspaceSummary",
    "WorkspaceStatus",
    "WorkspaceTheme",
]
