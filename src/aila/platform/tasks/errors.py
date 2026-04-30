"""Task-template-level exceptions (Phase 179).

Kept deliberately small. Workflow-engine exceptions live in
``aila.platform.workflows.errors``; task-wrapper/lifecycle exceptions belong
here so modules that decorate a function with ``@platform_task`` import from
a single, stable namespace.
"""
from __future__ import annotations

__all__ = ["WorkflowMigratedError"]


class WorkflowMigratedError(RuntimeError):
    """Reserved for future migration fences; not currently raised by any
    production code path.
    """
