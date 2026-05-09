"""Public contract models for the vulnerability research module.

Barrel re-export only. Model definitions live in domain submodules.
"""
from __future__ import annotations

from .advisory import CVSSVector, CWEMapping, VRAdvisory
from .finding import (
    CrashSignature,
    CrashType,
    DisclosureStatus,
    PoCResult,
    VRFinding,
)
from .project import (
    TargetClass,
    VRProjectCreate,
    VRProjectStatus,
    VRProjectSummary,
    VRTarget,
)

__all__ = [
    "CVSSVector",
    "CWEMapping",
    "CrashSignature",
    "CrashType",
    "DisclosureStatus",
    "PoCResult",
    "TargetClass",
    "VRAdvisory",
    "VRFinding",
    "VRProjectCreate",
    "VRProjectStatus",
    "VRProjectSummary",
    "VRTarget",
]
