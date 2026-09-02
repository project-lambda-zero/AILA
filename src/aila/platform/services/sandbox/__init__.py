"""Platform sandbox service package (issue #147).

Re-exports the public contracts and the :class:`SandboxService` entry
point so callers can ``from aila.platform.services.sandbox import
SandboxService, SandboxSpec`` without knowing the internal layout.
"""
from __future__ import annotations

from .contracts import (
    SandboxBackend,
    SandboxExecutionError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
)
from .service import SandboxConfig, SandboxProbe, SandboxService

__all__ = [
    "SandboxBackend",
    "SandboxConfig",
    "SandboxExecutionError",
    "SandboxProbe",
    "SandboxResult",
    "SandboxService",
    "SandboxSpec",
    "SandboxUnavailableError",
]
