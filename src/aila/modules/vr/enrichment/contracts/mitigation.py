"""Mitigation analysis contract models (M3.T-2).

Wraps the raw ``MitigationFlags`` (defined in
``contracts/enrichment.py``) with provenance metadata so a target's
mitigation analysis is auditable: when was it produced, by which
analyzer, against which binary hash, and what errors (if any) occurred.

The persisted shape on ``vr_targets.capability_profile_json.mitigations``
is just the ``MitigationFlags`` flat dict (for query-friendliness).
The ``MitigationReport`` is the full analyzer output that includes
provenance and is returned by the analyzer service to its callers.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.contracts.enrichment import MitigationFlags

__all__ = [
    "MitigationKind",
    "MitigationReport",
    "MitigationSource",
]


class MitigationKind(StrEnum):
    """Categorical grouping of mitigation flags for UI + reasoning prompts.

    Operator-facing summaries group flags by kind so reports read as
    'memory protection: nx+aslr+pie present, RELRO partial' instead of
    a flat list. The reasoning engine uses the same grouping to reason
    about defense-in-depth coverage.
    """

    MEMORY_PROTECTION = "memory_protection"
    STACK_INTEGRITY = "stack_integrity"
    CONTROL_FLOW_INTEGRITY = "control_flow_integrity"
    INSTRUMENTATION = "instrumentation"


class MitigationSource(StrEnum):
    """Which analyzer produced this mitigation report.

    Multiple sources may be combined (M3.T-4 orchestrator). The source
    enum is recorded so disagreements between sources can be flagged
    (e.g. IDA reports CFI=true but local ELF parser reports CFI=false).
    """

    IDA_CHECKSEC = "ida_checksec"
    AUDIT_MCP = "audit_mcp"
    LOCAL_PE_PARSER = "local_pe_parser"
    LOCAL_ELF_PARSER = "local_elf_parser"
    SANITIZER_DETECTOR = "sanitizer_detector"
    OPERATOR_OVERRIDE = "operator_override"


class MitigationReport(BaseModel):
    """Full output of one mitigation-analysis run.

    Persisted in vr_targets.capability_profile_json.mitigations the flags
    portion is flattened; the report metadata (source, analyzed_at, etc.)
    lives alongside as capability_profile.mitigation_provenance.
    """

    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=64)
    binary_id: str | None = Field(
        default=None,
        description="MCP-side binary_id when the analysis ran via an MCP server.",
    )
    binary_sha256: str | None = Field(
        default=None,
        description="SHA256 of the analyzed binary content, when available.",
    )
    source: MitigationSource
    analyzer_version: str = Field(
        default="0.3.0",
        description="Version tag for the analyzer code path — bump on parser changes.",
    )
    analyzed_at: datetime
    flags: MitigationFlags
    errors: list[str] = Field(
        default_factory=list,
        description="Non-fatal warnings from the analyzer (missing fields, unknown values).",
    )
