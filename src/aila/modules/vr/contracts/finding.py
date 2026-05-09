"""Finding contract models for the vulnerability research module."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CrashSignature",
    "CrashType",
    "DisclosureStatus",
    "PoCResult",
    "VRFinding",
]


class CrashType(StrEnum):
    """Exploit primitive vocabulary (D-19)."""

    OVERFLOW_STACK = "overflow_stack"
    OVERFLOW_HEAP = "overflow_heap"
    UAF = "uaf"
    DOUBLE_FREE = "double_free"
    TYPE_CONFUSION = "type_confusion"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    NULL_DEREF = "null_deref"
    OOB_READ = "oob_read"
    OOB_WRITE = "oob_write"
    ARW = "arw"
    AAR = "aar"
    AAW = "aaw"
    RIP_CONTROL = "rip_control"
    LEAK_STACK = "leak_stack"
    LEAK_HEAP = "leak_heap"
    LEAK_LIBC = "leak_libc"
    LEAK_PIE = "leak_pie"
    INFO_DISCLOSURE = "info_disclosure"
    CMD_INJECTION = "cmd_injection"
    DESER_GADGET = "deser_gadget"
    SSTI = "ssti"
    SQLI = "sqli"
    SSRF = "ssrf"


class DisclosureStatus(StrEnum):
    """Coordinated disclosure lifecycle (D-04)."""

    UNDISCLOSED = "undisclosed"
    REPORTED = "reported"
    ACKNOWLEDGED = "acknowledged"
    PATCH_PENDING = "patch_pending"
    PATCHED = "patched"
    PUBLIC = "public"


class CrashSignature(BaseModel):
    """Normalized fingerprint used to deduplicate crashes."""

    model_config = ConfigDict(extra="forbid")

    crash_type: CrashType
    frames: list[str] = Field(
        default_factory=list,
        description="Top-5 stack frames after symbol/address normalization.",
    )
    signature_hash: str = Field(
        description="SHA256 of the canonicalized crash_type + frames.",
    )


class PoCResult(BaseModel):
    """Outcome of running a generated proof-of-concept."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(description="PoC script source.")
    language: str = Field(default="python", description="python or c")
    crashes_vulnerable: int = Field(
        default=0,
        ge=0,
        description="Crash count out of 5 runs against the vulnerable target.",
    )
    crashes_patched: int = Field(
        default=0,
        ge=0,
        description="Crash count out of 1 run against the patched target (must be 0).",
    )
    asan_report: str = Field(default="")
    exit_code: int | None = None


class VRFinding(BaseModel):
    """A single vulnerability finding owned by a VR project."""

    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    project_id: str
    crash_type: CrashType | None = None
    crash_signature: CrashSignature | None = None
    root_cause: str = ""
    vulnerable_function: str = ""
    poc: PoCResult | None = None
    advisory_id: str | None = None

    # Disclosure tracking (D-04)
    disclosure_status: DisclosureStatus = DisclosureStatus.UNDISCLOSED
    vendor_contact: str | None = None
    reported_at: str | None = None
    embargo_until: str | None = None
    assigned_cve_id: str | None = None
    patch_version: str | None = None
