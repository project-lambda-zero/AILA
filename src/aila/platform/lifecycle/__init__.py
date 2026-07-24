"""Platform agent lifecycle control plane (RFC-10).

The controller composes the RFC-08 eval runner and the RFC-09 prompt
version store into a stage-guarded flow: evaluate a candidate, promote
a version that passed evaluation, or rollback to a prior production
version. Every observed stage move writes one row to the
``lifecycle_transitions`` journal owned by ``models.py``.
"""
from __future__ import annotations

from .controller import (
    PRODUCTION_ALIAS,
    AgentLifecycleController,
    StageTransitionError,
)
from .models import LifecycleStage, LifecycleTransitionRecord

__all__ = [
    "PRODUCTION_ALIAS",
    "AgentLifecycleController",
    "LifecycleStage",
    "LifecycleTransitionRecord",
    "StageTransitionError",
]
