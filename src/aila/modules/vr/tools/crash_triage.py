"""Crash report parsing and dedup signature computation (GA-2).

Parses ASAN/GDB output, classifies the crash type into the project-wide
``CrashType`` vocabulary, and computes a stable SHA256 dedup signature
from the top-5 normalized stack frames. Also exposes a coarse
exploitability heuristic for triage prioritization.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from aila.platform.tools._common import Tool

__all__ = ["CrashTriageTool"]


# ASAN sanitizer error names → CrashType enum values. Anything not listed
# falls through to "info_disclosure" so signatures remain stable.
_ASAN_TO_CRASH_TYPE: dict[str, str] = {
    **dict.fromkeys(
        ("stack-buffer-overflow", "stack-buffer-underflow", "stack-overflow",
         "dynamic-stack-buffer-overflow"), "overflow_stack"),
    **dict.fromkeys(("heap-buffer-overflow", "heap-buffer-underflow"), "overflow_heap"),
    **dict.fromkeys(
        ("heap-use-after-free", "use-after-poison",
         "stack-use-after-return", "stack-use-after-scope"), "uaf"),
    **dict.fromkeys(("double-free", "alloc-dealloc-mismatch"), "double_free"),
    **dict.fromkeys(("FPE", "SEGV"), "null_deref"),
    "global-buffer-overflow": "oob_write",
    "negative-size-param": "integer_overflow",
}

_ASAN_ERROR_RE = re.compile(r"AddressSanitizer:\s+(\S+)")
_ACCESS_RE = re.compile(r"\b(READ|WRITE) of size (\d+)")
_ADDR_RE = re.compile(r"on address (0x[0-9a-fA-F]+)")
_FRAME_RE = re.compile(r"#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)(?:\s+(\S+))?")
_LOCATED_RE = re.compile(
    r"is located (\d+) bytes (?:to the )?(\w+)(?: of)? (\d+)-byte region"
)
# Address pattern for normalization (strip ASLR base for non-PIE).
_HEX_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")


class CrashTriageTool(Tool):
    """Parse crash reports, classify, and compute dedup signatures."""

    name = "vr.crash_triage"
    description = (
        "Parse crash reports (ASAN, GDB), classify crash type, compute "
        "dedup signature. Actions: parse_asan (extract crash type, address, "
        "frames from ASAN output), compute_signature (SHA256 fingerprint "
        "from crash_type + top-5 normalized frames), classify_exploitability "
        "(heuristic verdict from crash type and write metadata)."
    )
    inputs = {
        "action": {
            "type": "string",
            "description": "parse_asan | compute_signature | classify_exploitability",
        },
    }
    output_type = "object"
    skip_forward_signature_validation = True

    def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        if action == "parse_asan":
            return self.parse_asan(kwargs.get("asan_output", ""))
        if action == "compute_signature":
            return self.compute_signature(
                crash_type=kwargs.get("crash_type", ""),
                frames=kwargs.get("frames", []) or [],
            )
        if action == "classify_exploitability":
            return self.classify_exploitability(
                crash_type=kwargs.get("crash_type", ""),
                write_size=kwargs.get("write_size"),
                controllable=kwargs.get("controllable"),
            )
        return {
            "status": "error",
            "error": (
                f"Unknown action: {action!r}. Expected parse_asan, "
                "compute_signature, or classify_exploitability."
            ),
        }

    def parse_asan(self, asan_output: str) -> dict:
        """Extract structured fields from an ASAN report."""
        if not isinstance(asan_output, str) or not asan_output.strip():
            return {"status": "error", "error": "asan_output must be non-empty."}

        sanitizer_kind = ""
        if (m := _ASAN_ERROR_RE.search(asan_output)):
            sanitizer_kind = m.group(1).strip().rstrip(":")
        crash_type = _ASAN_TO_CRASH_TYPE.get(sanitizer_kind, "info_disclosure")

        access_type: str | None = None
        access_size: int | None = None
        if (m := _ACCESS_RE.search(asan_output)):
            access_type, access_size = m.group(1).lower(), int(m.group(2))

        crash_address = m.group(1) if (m := _ADDR_RE.search(asan_output)) else None

        overflow_offset: int | None = None
        overflow_direction: str | None = None
        region_size: int | None = None
        if (m := _LOCATED_RE.search(asan_output)):
            overflow_offset = int(m.group(1))
            overflow_direction = m.group(2).lower()
            region_size = int(m.group(3))

        frames = [
            {"depth": int(fm.group(1)), "function": fm.group(2), "module": fm.group(3) or ""}
            for fm in _FRAME_RE.finditer(asan_output)
        ]
        return {
            "status": "ready",
            "sanitizer": "AddressSanitizer",
            "sanitizer_kind": sanitizer_kind,
            "crash_type": crash_type,
            "access_type": access_type,
            "access_size": access_size,
            "crash_address": crash_address,
            "overflow_offset": overflow_offset,
            "overflow_direction": overflow_direction,
            "region_size": region_size,
            "stack_frames": frames,
        }

    def compute_signature(self, crash_type: str, frames: list[Any]) -> dict:
        """Build a deterministic SHA256 dedup signature.

        Frames are normalized (raw hex addresses stripped) before hashing
        so that ASLR bases and load offsets do not split otherwise-identical
        crashes into separate buckets. Only the top 5 frames participate.
        """
        if not isinstance(crash_type, str) or not crash_type:
            return {"status": "error", "error": "crash_type must be non-empty."}
        if not isinstance(frames, list):
            return {"status": "error", "error": "frames must be a list."}

        normalized: list[str] = []
        for raw in frames:
            if isinstance(raw, dict):
                fn, mod = str(raw.get("function") or "").strip(), str(raw.get("module") or "").strip()
                token = f"{fn}@{mod}" if mod else fn
            else:
                token = str(raw).strip()
            token = _HEX_ADDR_RE.sub("0x?", token)
            if token:
                normalized.append(token)

        top5 = normalized[:5]
        canonical = crash_type + "|" + "|".join(top5)
        sig = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return {
            "status": "ready",
            "crash_type": crash_type,
            "frames": top5,
            "signature_hash": sig,
        }

    def classify_exploitability(
        self,
        crash_type: str,
        write_size: int | None = None,
        controllable: bool | None = None,
    ) -> dict:
        """Coarse exploitability triage verdict.

        This is a tier-0 heuristic, not an exploit proof. The proper
        chain (deep taint, gate proofs, PoC) lives in the agent workflow.
        """
        if not isinstance(crash_type, str) or not crash_type:
            return {"status": "error", "error": "crash_type must be non-empty."}

        verdict, rationale = "uncertain", "Unclassified primitive."
        if crash_type in {"overflow_heap", "overflow_stack", "oob_write", "aaw"}:
            if controllable:
                verdict, rationale = "likely_exploitable", "Controllable write into adjacent memory."
            elif write_size and write_size >= 8:
                verdict, rationale = "possibly_exploitable", f"Write of {write_size} bytes — corruption primitive present."
            else:
                verdict, rationale = "possibly_exploitable", "Write primitive without confirmed control."
        elif crash_type in {"uaf", "double_free", "type_confusion", "rip_control"}:
            verdict, rationale = "likely_exploitable", "Allocator/control-flow corruption primitive."
        elif crash_type == "null_deref":
            verdict, rationale = "unlikely", "NULL deref — typically DoS only."
        elif crash_type in {"leak_stack", "leak_heap", "leak_libc", "leak_pie", "info_disclosure", "oob_read", "aar"}:
            verdict, rationale = "info_disclosure", "Read primitive — disclosure without code-exec on its own."
        elif crash_type in {"cmd_injection", "ssti", "sqli", "deser_gadget"}:
            verdict, rationale = "likely_exploitable", "Logic-layer code execution primitive."

        return {
            "status": "ready",
            "verdict": verdict,
            "rationale": rationale,
        }
