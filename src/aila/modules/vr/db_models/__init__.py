"""Vulnerability research module database models — barrel re-export.

All table classes are imported here for external consumption.
Individual model definitions live in domain submodules.
"""
from __future__ import annotations

from .finding import VRFindingRecord
from .project import VRProjectRecord
from .target import VRTargetRecord, VRTargetTagIndexRecord
from .workspace import VRWorkspaceRecord

__all__ = [
    "VRFindingRecord",
    "VRProjectRecord",
    "VRTargetRecord",
    "VRTargetTagIndexRecord",
    "VRWorkspaceRecord",
]
