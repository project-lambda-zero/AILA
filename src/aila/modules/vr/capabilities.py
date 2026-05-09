"""Capability metadata for the VR (vulnerability research) module.

``CAPABILITY_DESCRIPTION`` and ``CAPABILITY_EXAMPLES`` are consumed by the
module's ``capability_profiles()`` to construct the ``ModuleCapabilityProfile``
registered with the platform router. The router's selection agent uses these
strings to decide whether the VR module handles a given user request.

``MODULE_TOOLS`` mirrors ``tool_keys.ALL_TOOL_KEYS`` for module manifest
consumers that expect the canonical attribute name.
"""
from __future__ import annotations

from aila.modules.vr.tool_keys import ALL_TOOL_KEYS

CAPABILITY_DESCRIPTION = (
    "Conduct offensive vulnerability research against compiled binaries, services, "
    "and reported CVEs. Reverse engineer native, kernel, hypervisor, and managed "
    "runtime targets via an IDA Pro bridge; diff vendor patches to localize the "
    "fix and infer the original bug; classify root cause as a concrete exploit "
    "primitive (stack/heap overflow, UAF, type confusion, OOB, ARW/AAR/AAW, "
    "info leak, RIP control, command injection, deserialization, SSTI, SQLi, "
    "SSRF, etc.); write reproducible N-day proof-of-concept exploits with "
    "documented reliability targets; triage crashes for exploitability; and "
    "generate professional security advisories that track disclosure status "
    "from undisclosed through reported, acknowledged, patch_pending, patched, "
    "and public."
)

CAPABILITY_EXAMPLES = [
    "write a reproducible PoC for CVE-2024-1234",
    "analyze the patch diff between these two binaries and tell me what bug was fixed",
    "check what mitigations this binary has (NX, ASLR, CFG, stack canaries)",
    "reverse engineer this function and identify the root cause primitive",
    "triage this crash dump and tell me if it is exploitable",
    "generate a security advisory for this finding with disclosure timeline",
    "develop an N-day exploit for this kernel vulnerability targeting the patched function",
    "diff the vulnerable and patched versions of this service to localize the fix",
]

MODULE_TOOLS = ALL_TOOL_KEYS

__all__ = [
    "CAPABILITY_DESCRIPTION",
    "CAPABILITY_EXAMPLES",
    "MODULE_TOOLS",
]
