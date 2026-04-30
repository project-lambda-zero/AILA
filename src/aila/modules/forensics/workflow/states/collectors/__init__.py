"""Per-lane artifact collectors.

Each lane module exposes a single ``collect_<lane>_artifacts()`` coroutine
that takes ``(ssh, integration, path, analyzer_os, emitter=None)`` and
returns a list of artifact dicts. Collectors are pure transformers — they
do not touch the DB, emit progress via the optional ``emitter``, and never
raise past their own boundary (one failed file never aborts the stage).
"""
from __future__ import annotations

from .binary_analysis import collect_binary_analysis_artifacts
from .disk import collect_disk_artifacts
from .log import collect_log_artifacts
from .memory import collect_memory_artifacts
from .network import collect_network_artifacts

__all__ = [
    "collect_binary_analysis_artifacts",
    "collect_disk_artifacts",
    "collect_log_artifacts",
    "collect_memory_artifacts",
    "collect_network_artifacts",
]
