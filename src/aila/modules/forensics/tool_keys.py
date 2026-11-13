"""Stable string identifiers for forensics module tools.

Tool keys are stable across restarts and must not change after registration.
All keys are prefixed with `forensics.` to avoid collisions.
"""
from __future__ import annotations

EVIDENCE_INTAKE = "forensics.evidence_intake"
ARTIFACT_QUERY = "forensics.artifact_query"
DISSECT_RUNNER = "forensics.dissect_runner"
VOLATILITY_RUNNER = "forensics.volatility_runner"
TSHARK_RUNNER = "forensics.tshark_runner"
STRINGS_RUNNER = "forensics.strings_runner"
SCRIPT_EXECUTOR = "forensics.script_executor"
GHIDRA_RUNNER = "forensics.ghidra_runner"
ZEEK_RUNNER = "forensics.zeek_runner"
YARA_RUNNER = "forensics.yara_runner"
REGISTRY_VIEWER = "forensics.registry_viewer"
CARVING_RUNNER = "forensics.carving_runner"
DD_RUNNER = "forensics.dd_runner"

_ALL_TOOL_KEYS: tuple[str, ...] = (
    EVIDENCE_INTAKE,
    ARTIFACT_QUERY,
    DISSECT_RUNNER,
    VOLATILITY_RUNNER,
    TSHARK_RUNNER,
    ZEEK_RUNNER,
    STRINGS_RUNNER,
    SCRIPT_EXECUTOR,
    GHIDRA_RUNNER,
    YARA_RUNNER,
    REGISTRY_VIEWER,
    CARVING_RUNNER,
    DD_RUNNER,
)


def all_tool_keys() -> list[str]:
    """Return all forensics tool keys in registration order."""
    return list(_ALL_TOOL_KEYS)

__all__ = [
    "EVIDENCE_INTAKE",
    "ARTIFACT_QUERY",
    "DISSECT_RUNNER",
    "VOLATILITY_RUNNER",
    "TSHARK_RUNNER",
    "STRINGS_RUNNER",
    "SCRIPT_EXECUTOR",
    "GHIDRA_RUNNER",
    "ZEEK_RUNNER",
    "YARA_RUNNER",
    "REGISTRY_VIEWER",
    "CARVING_RUNNER",
    "DD_RUNNER",
    "all_tool_keys",
]
