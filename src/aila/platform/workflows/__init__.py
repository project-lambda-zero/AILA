"""Durable workflows engine for AILA.

Public API:
    - ``DurableStateMachine`` -- the engine entry point (``.execute(...)``)
    - ``StateSpec``, ``WorkflowDefinition``, ``State``, ``StateResult``
    - ``WorkflowServices`` Protocol
    - Error types: ``WorkflowConflictError``, ``ServiceBuildError``,
      ``UnknownNextStateError``
    - Reserved terminal state constants and ``default_backoff``

Phase 178 scope: engine + schema only. Phase 179 adds the
``@platform_task`` decorator that invokes ``DurableStateMachine.execute``
inside an ARQ job wrapper. Phase 180 ports the first module.
"""
from __future__ import annotations

from .backoff import default_backoff
from .engine import DurableStateMachine
from .errors import (
    ServiceBuildError,
    UnknownNextStateError,
    WorkflowConflictError,
    WorkflowSafeMessage,
    WorkflowStepLimitExceeded,
)
from .types import (
    MAX_STEPS_PER_JOB,
    RESERVED_CANCELLED,
    RESERVED_CRASHED,
    RESERVED_FAILED,
    RESERVED_SUCCEEDED,
    RESERVED_TERMINAL_STATES,
    State,
    StateResult,
    StateSpec,
    WorkflowDefinition,
    WorkflowServices,
)

__all__ = [
    "MAX_STEPS_PER_JOB",
    "RESERVED_CANCELLED",
    "RESERVED_CRASHED",
    "RESERVED_FAILED",
    "RESERVED_SUCCEEDED",
    "RESERVED_TERMINAL_STATES",
    "DurableStateMachine",
    "ServiceBuildError",
    "State",
    "StateResult",
    "StateSpec",
    "UnknownNextStateError",
    "WorkflowConflictError",
    "WorkflowDefinition",
    "WorkflowSafeMessage",
    "WorkflowServices",
    "WorkflowStepLimitExceeded",
    "default_backoff",
]
