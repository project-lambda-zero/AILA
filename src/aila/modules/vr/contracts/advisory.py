"""Advisory contract models for the vulnerability research module."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CVSSVector",
    "CWEMapping",
    "VRAdvisory",
]


class CVSSVector(BaseModel):
    """CVSS v3.1 scoring envelope."""

    model_config = ConfigDict(extra="forbid")

    vector_string: str = Field(
        default="",
        description="Full CVSS:3.1 vector string (CVSS:3.1/AV:N/AC:L/...).",
    )
    base_score: float = Field(default=0.0, ge=0.0, le=10.0)
    severity: str = Field(
        default="",
        description="NONE, LOW, MEDIUM, HIGH, or CRITICAL.",
    )


class CWEMapping(BaseModel):
    """CWE classification for a finding."""

    model_config = ConfigDict(extra="forbid")

    cwe_id: str = Field(description="CWE identifier in CWE-NNNN form.")
    name: str = Field(default="", description="Human-readable CWE name.")
    description: str = Field(default="")


class VRAdvisory(BaseModel):
    """Publishable advisory derived from a VR finding."""

    model_config = ConfigDict(extra="forbid")

    id: str | None = None
    finding_id: str
    cve_id: str | None = None
    title: str = ""
    summary: str = ""
    technical_details: str = ""
    impact: str = ""
    affected_versions: list[str] = Field(default_factory=list)
    remediation: str = ""
    cvss: CVSSVector = Field(default_factory=CVSSVector)
    cwe: CWEMapping | None = None
    references: list[str] = Field(default_factory=list)
