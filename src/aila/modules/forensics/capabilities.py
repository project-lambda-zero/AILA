"""Capability metadata for the forensics module.

`CAPABILITY_DESCRIPTION` and `CAPABILITY_EXAMPLES` are consumed by
`ForensicsModule.capability_profiles()` to construct the `ModuleCapabilityProfile`
registered with the platform router. The router's selection agent uses these
strings to decide whether the forensics module handles a given user request.
"""
from __future__ import annotations

CAPABILITY_DESCRIPTION = (
    "Investigate forensic evidence on remote Analyzer Machines over SSH. "
    "Classify evidence types (disk images, memory dumps, PCAPs, extracted dirs), "
    "extract and normalize artifacts (host identity, users, browser history, "
    "network sessions, processes, malware indicators), score leads, answer "
    "investigation questions via bounded free-flow agent, and generate "
    "professional security write-ups."
)

CAPABILITY_EXAMPLES = [
    "create a forensics project for the disk image on my analyzer machine",
    "analyze the evidence in /cases/project-001 on the forensics workstation",
    "what malware was found on the windows disk image",
    "find the C2 IP address from the memory dump",
    "generate a write-up of the investigation findings",
    "check if the analyzer machine has all required tools installed",
]

__all__ = ["CAPABILITY_DESCRIPTION", "CAPABILITY_EXAMPLES"]
