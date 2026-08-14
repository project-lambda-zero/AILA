"""Concrete sandbox backends for :class:`SandboxService`.

Each backend module exports one class that satisfies the
:class:`SandboxBackend` Protocol declared in ``..contracts``.
"""
from __future__ import annotations

from .base import (
    HostWorkspace,
    SandboxBackend,
    SandboxExecutionError,
    SandboxResult,
    SandboxSpec,
    SandboxUnavailableError,
    collect_outputs,
    host_workspace,
    probe_binary,
    stage_inputs,
)
from .firecracker import FirecrackerBackend, build_vm_config
from .nsjail import NsjailBackend, build_nsjail_argv

__all__ = [
    "FirecrackerBackend",
    "HostWorkspace",
    "NsjailBackend",
    "SandboxBackend",
    "SandboxExecutionError",
    "SandboxResult",
    "SandboxSpec",
    "SandboxUnavailableError",
    "build_nsjail_argv",
    "build_vm_config",
    "collect_outputs",
    "host_workspace",
    "probe_binary",
    "stage_inputs",
]
