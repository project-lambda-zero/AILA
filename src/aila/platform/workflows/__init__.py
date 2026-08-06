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
from .phase_graph import (
    DISPATCH_STATE,
    EMIT_STATE,
    SETUP_STATE,
    GateFn,
    LoopBuilder,
    PhaseGraphSpec,
    PhaseSpec,
    RouterFn,
    SetupBuilder,
    build_dispatch_workflow,
    build_phase_workflow,
    make_dispatch_router,
    make_gate_state,
    make_router_state,
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
    "DISPATCH_STATE",
    "EMIT_STATE",
    "MAX_STEPS_PER_JOB",
    "RESERVED_CANCELLED",
    "RESERVED_CRASHED",
    "RESERVED_FAILED",
    "RESERVED_SUCCEEDED",
    "RESERVED_TERMINAL_STATES",
    "SETUP_STATE",
    "DurableStateMachine",
    "GateFn",
    "LoopBuilder",
    "PhaseGraphSpec",
    "PhaseSpec",
    "RouterFn",
    "ServiceBuildError",
    "SetupBuilder",
    "State",
    "StateResult",
    "StateSpec",
    "UnknownNextStateError",
    "WorkflowConflictError",
    "WorkflowDefinition",
    "WorkflowSafeMessage",
    "WorkflowServices",
    "WorkflowStepLimitExceeded",
    "build_dispatch_workflow",
    "build_phase_workflow",
    "default_backoff",
    "make_dispatch_router",
    "make_gate_state",
    "make_router_state",
]
