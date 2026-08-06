"""Platform agent lifecycle control plane (RFC-10).

The controller composes the RFC-08 eval runner and the RFC-09 prompt
version store into a stage-guarded flow: evaluate a candidate, register
a shadow, canary a cohort, promote a version that passed evaluation +
approval, or rollback to a prior production version. Every observed
stage move writes one row to the ``lifecycle_transitions`` journal
owned by ``models.py``; shadow / canary routing state lives on the
``lifecycle_canary_assignments`` table owned by ``assignments.py``.
"""
from __future__ import annotations

from .assignments import (
    AssignmentKind,
    AssignmentState,
    LifecycleCanaryAssignment,
)
from .controller import (
    PRODUCTION_ALIAS,
    AgentLifecycleController,
    CanaryHoldSignal,
    CanarySignalOutcome,
    CohortRoute,
    StageTransitionError,
)
from .models import LifecycleStage, LifecycleTransitionRecord

__all__ = [
    "PRODUCTION_ALIAS",
    "AgentLifecycleController",
    "AssignmentKind",
    "AssignmentState",
    "CanaryHoldSignal",
    "CanarySignalOutcome",
    "CohortRoute",
    "LifecycleCanaryAssignment",
    "LifecycleStage",
    "LifecycleTransitionRecord",
    "StageTransitionError",
]
