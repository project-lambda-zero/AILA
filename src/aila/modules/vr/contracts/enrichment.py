"""Target enrichment contracts.

Populated by M3.T-2 (mitigation analyzer), M3.T-3 (function ranker), and
M3.T-4 (capability profile builder). Serialized to JSON in
``vr_targets.capability_profile_json``.

The TargetCapabilityProfile schema matches the D-51 sketch and drives:
  - Investigation start: limits strategy/engine selection to applicable
  - Fuzzing campaign creation: filters engine dropdown
  - Pattern retrieval: filters by applicable_pattern_kinds
  - Disclosure orchestrator: suggests default tracks
  - Cost estimation: per-investigation budget defaults
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from .target import TargetKind

__all__ = [
    "EnrichmentError",
    "EnrichmentResult",
    "MitigationFlags",
    "TargetCapabilityProfile",
]


class MitigationFlags(BaseModel):
    """Per-binary mitigation flags (populated by M3.T-2).

    Each flag is tristate:
      - True:  mitigation detected as present
      - False: mitigation detected as absent
      - None:  not yet analyzed OR not applicable to this target kind
    """

    model_config = ConfigDict(extra="forbid")

    nx: bool | None = Field(default=None, description="NX/DEP bit set on executable segments.")
    aslr: bool | None = Field(default=None, description="Image base randomization (DYNAMICBASE on PE, PIE on ELF).")
    canary: bool | None = Field(default=None, description="Stack canary / GS cookie.")
    cet: bool | None = Field(default=None, description="Intel CET shadow stack / IBT.")
    cfi: bool | None = Field(default=None, description="Control-flow integrity (CFG on PE, LLVM CFI on ELF).")
    relro_partial: bool | None = Field(default=None, description="ELF partial RELRO.")
    relro_full: bool | None = Field(default=None, description="ELF full RELRO with BIND_NOW.")
    pie: bool | None = Field(default=None, description="Position-independent executable.")
    sanitizers: list[str] = Field(
        default_factory=list,
        description="Detected sanitizer builds: 'asan', 'msan', 'ubsan', 'tsan', 'lsan'.",
    )
    notes: str = Field(default="", description="Free-form analyzer notes (e.g. partial CFI, custom canary).")


class TargetCapabilityProfile(BaseModel):
    """Full D-51 capability profile populated by M3.T-4 orchestrator.

    Encodes which platform capabilities are applicable for this target.
    Drives UI filtering and engine-side selection across the v0.3 stack.
    """

    model_config = ConfigDict(extra="forbid")

    target_kind: TargetKind
    primary_language: str = ""
    secondary_languages: list[str] = Field(default_factory=list)

    applicable_mcp_servers: list[str] = Field(
        default_factory=list,
        description="MCP server IDs that can operate on this target (e.g. 'ida_headless', 'audit_mcp').",
    )
    applicable_fuzzing_engines: list[str] = Field(
        default_factory=list,
        description="Fuzzing engine IDs (e.g. 'fuzzilli_v8', 'v8_d8_sbx', 'afl++_qemu').",
    )
    applicable_strategies: list[str] = Field(
        default_factory=list,
        description="Fuzzing strategy IDs applicable to this target.",
    )
    applicable_pattern_kinds: list[str] = Field(
        default_factory=list,
        description="Pattern kinds from D-43 GA-41 that retrieve for this target.",
    )

    default_reasoning_strategy: str = Field(
        default="vulnerability_research.discovery_research",
        description="Default ReasoningStrategyFamily value to start investigations with.",
    )
    default_disclosure_tracks: list[str] = Field(
        default_factory=list,
        description="Suggested disclosure track IDs at finding promotion time.",
    )

    estimated_cost_per_investigation_usd: float = Field(
        default=30.0, ge=0.0,
        description="Heuristic baseline budget for an investigation against this target.",
    )

    mitigations: MitigationFlags = Field(default_factory=MitigationFlags)


class EnrichmentError(BaseModel):
    """One failure within an enrichment run."""

    model_config = ConfigDict(extra="forbid")

    step: str
    message: str


class EnrichmentResult(BaseModel):
    """Output of one enrichment run for a target (M3.T-4 orchestrator output)."""

    model_config = ConfigDict(extra="forbid")

    target_id: str
    version: int = Field(default=1, description="Re-enrichment counter.")
    capability_profile: TargetCapabilityProfile | None = None
    completed_at: str | None = None
    errors: list[EnrichmentError] = Field(default_factory=list)
