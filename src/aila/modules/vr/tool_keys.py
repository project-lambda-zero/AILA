"""Stable string identifiers for VR (vulnerability research) module tools.

Tool keys are stable across restarts and must not change after registration.
All keys are prefixed with ``vr.`` to avoid collisions with other modules.
"""
from __future__ import annotations

TOOL_IDA_BRIDGE = "vr.ida_bridge"
TOOL_POC_RUNNER = "vr.poc_runner"
TOOL_PATCH_DIFFER = "vr.patch_differ"
TOOL_CRASH_TRIAGE = "vr.crash_triage"
TOOL_ADVISORY_BUILDER = "vr.advisory_builder"

ALL_TOOL_KEYS: tuple[str, ...] = (
    TOOL_IDA_BRIDGE,
    TOOL_POC_RUNNER,
    TOOL_PATCH_DIFFER,
    TOOL_CRASH_TRIAGE,
    TOOL_ADVISORY_BUILDER,
)

__all__ = [
    "TOOL_IDA_BRIDGE",
    "TOOL_POC_RUNNER",
    "TOOL_PATCH_DIFFER",
    "TOOL_CRASH_TRIAGE",
    "TOOL_ADVISORY_BUILDER",
    "ALL_TOOL_KEYS",
]
