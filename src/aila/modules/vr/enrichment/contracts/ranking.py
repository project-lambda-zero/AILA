"""Function ranking contract -- unified schema for source + binary targets.

The ranker dispatches to audit-mcp (source targets) OR IDA Headless MCP
(binary targets) and normalizes both into ``FunctionRanking``. The
schema records WHICH MCP produced the ranking so downstream consumers
(operator UI, reasoning engine, fuzz campaign creator) can interpret
the entries correctly.

audit-mcp source path → entries derived from ``fuzzing_targets()`` +
``complexity_hotspots()`` + optional ``scan_and_correlate()``.

IDA binary path → entries derived from ``find_api_call_sites()``
aggregated per function + ``assess_exploitability()`` deep-verdict for
top-K candidates.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "FunctionRanking",
    "RankedFunction",
    "RankingSource",
]


class RankingSource(StrEnum):
    """Which MCP produced the ranking.

    Source path → AUDIT_MCP_FUZZING_TARGETS (or AUDIT_MCP_CORRELATED if
    scan_and_correlate was also used).
    Binary path → IDA_ASSESS_EXPLOITABILITY.
    """

    AUDIT_MCP_FUZZING_TARGETS = "audit_mcp_fuzzing_targets"
    AUDIT_MCP_CORRELATED = "audit_mcp_correlated"
    IDA_ASSESS_EXPLOITABILITY = "ida_assess_exploitability"


class RankedFunction(BaseModel):
    """One entry in the ranked function list.

    Fields are union-typed so the same shape covers source + binary.
    For source targets ``address`` is empty and ``file_path`` + ``line``
    are populated. For binary targets ``file_path`` is empty and
    ``address`` is the function VA.
    """

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=512)
    address: str = Field(default="", max_length=64, description="Binary VA (binary targets only).")
    file_path: str = Field(default="", max_length=1024, description="Source path (source targets only).")
    line: int | None = Field(default=None, description="Source line (source targets only).")
    score: float = Field(ge=0.0, le=1.0, description="Normalized 0-1 composite score from the source MCP.")
    rank: int = Field(ge=1, description="1-based position in the ranked list.")
    reasons: list[str] = Field(
        default_factory=list,
        description="Short human-readable explanations from the source MCP (e.g. 'tainted from recv', 'cyclomatic=37, blast_radius=120').",
    )


class FunctionRanking(BaseModel):
    """Per-target ranked function list, normalized across source + binary."""

    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=64)
    source: RankingSource
    produced_at: datetime
    total_candidates: int = Field(ge=0, description="Total functions considered before top-K cut.")
    top_k: list[RankedFunction] = Field(default_factory=list)
    notes: str = Field(default="", description="Free-form notes from the dispatcher (errors, fallbacks, partial results).")
