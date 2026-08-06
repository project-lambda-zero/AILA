"""Generic finding-triage lifecycle owned by the platform.

The finding workflow (new -> investigating -> mitigated -> verified ->
closed) is a cross-module triage lifecycle, not domain vocabulary: a
finding of any kind moves through the same states. The platform owns the
base transition map; modules extend it with their own states and
transitions through ModuleProtocol.workflow_definitions().
"""
from __future__ import annotations

__all__ = ["FINDING_STATE_TRANSITIONS", "FINDING_STATES"]

# Each state maps to the states it may legally transition to.
FINDING_STATE_TRANSITIONS: dict[str, list[str]] = {
    "new": ["investigating"],
    "investigating": ["new", "mitigated"],
    "mitigated": ["investigating", "verified"],
    "verified": ["closed"],
    "closed": [],
}

FINDING_STATES: list[str] = list(FINDING_STATE_TRANSITIONS)
