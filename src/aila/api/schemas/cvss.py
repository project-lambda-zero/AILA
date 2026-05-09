"""CVSS v3.1 vector parsing and human-readable explanation helpers.

The endpoint `GET /vulnerability/cves/{cve_id}` returns a `cvss_breakdown`
field so the UI can render a "why this score" panel. This module is the
single source of truth for the static mapping between CVSS metric codes and
their human-readable labels + explanation sentences + weight tiers.

Kept out of the router so the dictionary is importable from tests and not
buried in route handler scope.
"""
from __future__ import annotations

from typing import Literal

from pydantic import Field

from aila.api.schemas.common import APIModel

__all__ = [
    "CVSS_METRIC_EXPLANATIONS",
    "CVSS_METRIC_ORDER",
    "CveIntelResponse",
    "CvssMetricExplanation",
    "parse_cvss_vector",
]


# Canonical display order for the 8 base CVSS v3.1 metrics.
CVSS_METRIC_ORDER: tuple[str, ...] = (
    "AV",  # Attack Vector
    "AC",  # Attack Complexity
    "PR",  # Privileges Required
    "UI",  # User Interaction
    "S",   # Scope
    "C",   # Confidentiality
    "I",   # Integrity
    "A",   # Availability
)


# Human label for each metric.
_METRIC_LABELS: dict[str, str] = {
    "AV": "Attack Vector",
    "AC": "Attack Complexity",
    "PR": "Privileges Required",
    "UI": "User Interaction",
    "S": "Scope",
    "C": "Confidentiality Impact",
    "I": "Integrity Impact",
    "A": "Availability Impact",
}


# (metric_code, value_code) -> (readable value, explanation, weight)
# weight is how strongly this component pushes the base score upward.
CVSS_METRIC_EXPLANATIONS: dict[tuple[str, str], tuple[str, str, str]] = {
    # Attack Vector
    ("AV", "N"): (
        "Network",
        "Exploitable remotely over the network — no local access needed.",
        "high",
    ),
    ("AV", "A"): (
        "Adjacent",
        "Exploit requires adjacency on the same logical network segment.",
        "medium",
    ),
    ("AV", "L"): (
        "Local",
        "Exploit requires local access (shell, console, or local user).",
        "low",
    ),
    ("AV", "P"): (
        "Physical",
        "Exploit requires physical access to the target device.",
        "low",
    ),
    # Attack Complexity
    ("AC", "L"): (
        "Low",
        "No special conditions required — the attack is reliably reproducible.",
        "high",
    ),
    ("AC", "H"): (
        "High",
        "Exploit depends on conditions outside the attacker's control.",
        "low",
    ),
    # Privileges Required
    ("PR", "N"): (
        "None",
        "Attacker needs no prior authentication on the target.",
        "high",
    ),
    ("PR", "L"): (
        "Low",
        "Attacker needs basic user-level privileges.",
        "medium",
    ),
    ("PR", "H"): (
        "High",
        "Attacker needs administrative privileges, limiting exposure.",
        "low",
    ),
    # User Interaction
    ("UI", "N"): (
        "None",
        "No victim action required — exploit is fully unassisted.",
        "high",
    ),
    ("UI", "R"): (
        "Required",
        "A user must be tricked into an action (e.g., click a link).",
        "low",
    ),
    # Scope
    ("S", "U"): (
        "Unchanged",
        "Impact stays within the vulnerable component's security scope.",
        "low",
    ),
    ("S", "C"): (
        "Changed",
        "Impact can cross security boundaries into other components.",
        "high",
    ),
    # Confidentiality
    ("C", "H"): (
        "High",
        "Total disclosure of sensitive data is possible.",
        "high",
    ),
    ("C", "L"): (
        "Low",
        "Limited disclosure — attacker sees some restricted data.",
        "medium",
    ),
    ("C", "N"): (
        "None",
        "No loss of confidentiality.",
        "low",
    ),
    # Integrity
    ("I", "H"): (
        "High",
        "Attacker can modify any data protected by the component.",
        "high",
    ),
    ("I", "L"): (
        "Low",
        "Attacker can modify some data but with limited control.",
        "medium",
    ),
    ("I", "N"): (
        "None",
        "No loss of integrity.",
        "low",
    ),
    # Availability
    ("A", "H"): (
        "High",
        "Attacker can fully deny service to legitimate users.",
        "high",
    ),
    ("A", "L"): (
        "Low",
        "Attacker can degrade performance or interrupt service intermittently.",
        "medium",
    ),
    ("A", "N"): (
        "None",
        "No loss of availability.",
        "low",
    ),
}


class CvssMetricExplanation(APIModel):
    """Parsed, human-readable component of a CVSS v3.1 vector string.

    One `CvssMetricExplanation` per base metric (AV, AC, PR, UI, S, C, I, A).
    `weight` marks how strongly this component drove the overall score up,
    so the UI can highlight the high-weight components as the "why".
    """

    metric: str = Field(..., description='Human metric label, e.g. "Attack Vector"')
    code: str = Field(..., description='Metric + value code, e.g. "AV:N"')
    value: str = Field(..., description='Human value label, e.g. "Network"')
    explanation: str = Field(..., description="Plain-English explanation of the value.")
    weight: Literal["high", "medium", "low"] = Field(
        ...,
        description="How strongly this component contributed to raising the base score.",
    )


def parse_cvss_vector(vector: str | None) -> list[CvssMetricExplanation]:
    """Parse a CVSS v3.1 vector string into per-metric explanations.

    Accepts strings of the form::

        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    Unknown/missing metrics are skipped silently so a partial vector still
    produces partial output. Returns components in the canonical
    `CVSS_METRIC_ORDER`.

    Args:
        vector: Raw CVSS vector string from NVD. May be ``None`` or empty.

    Returns:
        Ordered list of `CvssMetricExplanation` objects. Empty when the
        vector is absent or has no recognized base metrics.
    """
    if not vector:
        return []

    parts = [p for p in vector.strip().split("/") if ":" in p]
    # Build a map of metric_code -> value_code, skipping the "CVSS:3.1" prefix part.
    pairs: dict[str, str] = {}
    for part in parts:
        metric, _, value = part.partition(":")
        metric = metric.strip().upper()
        value = value.strip().upper()
        if metric == "CVSS":
            # "CVSS:3.1" version marker — skip.
            continue
        if metric in _METRIC_LABELS and metric not in pairs:
            pairs[metric] = value

    out: list[CvssMetricExplanation] = []
    for metric in CVSS_METRIC_ORDER:
        if metric not in pairs:
            continue
        value_code = pairs[metric]
        entry = CVSS_METRIC_EXPLANATIONS.get((metric, value_code))
        if entry is None:
            # Unknown value code for a known metric — skip rather than surface
            # malformed data to the UI.
            continue
        value_label, explanation, weight = entry
        out.append(
            CvssMetricExplanation(
                metric=_METRIC_LABELS[metric],
                code=f"{metric}:{value_code}",
                value=value_label,
                explanation=explanation,
                weight=weight,  # type: ignore[arg-type]
            )
        )
    return out


class CveIntelResponse(APIModel):
    """CVE intelligence payload for the detail page.

    Mirrors the `CVEKnowledge` contract verbatim (same field names, no
    remapping) and adds a single computed field `cvss_breakdown` containing
    the parsed CVSS vector components. Mirroring instead of subclassing
    because `CVEKnowledge` uses the default Pydantic config while
    `CveIntelResponse` inherits `APIModel` (extra=forbid) for API surface
    hygiene.

    `cvss_vector` carries the raw "CVSS:3.1/..." string when available so
    the UI can render the vector next to its breakdown.
    """

    cve_id: str
    description: str = ""
    base_severity: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    attack_vector: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev_listed: bool = False
    kev_date_added: str | None = None
    nvd_url: str
    published_at: str | None = None
    updated_at: str | None = None
    notes: list[str] = Field(default_factory=list)
    intel_source_mode: str | None = None
    intel_last_synced_at: str | None = None
    cvss_breakdown: list[CvssMetricExplanation] = Field(default_factory=list)

    @classmethod
    def from_knowledge(
        cls,
        knowledge: object,
        *,
        cvss_vector: str | None = None,
    ) -> CveIntelResponse:
        """Build the response envelope from a `CVEKnowledge` plus parsed vector.

        The explicit `cvss_vector` override takes precedence when provided —
        otherwise falls back to the vector stored on the knowledge record
        (populated by IntelService._fetch_from_nvd for live fetches).
        """
        effective_vector = cvss_vector if cvss_vector is not None else knowledge.cvss_vector
        breakdown = parse_cvss_vector(effective_vector)
        return cls(
            cve_id=knowledge.cve_id,
            description=knowledge.description,
            base_severity=knowledge.base_severity,
            cvss_score=knowledge.cvss_score,
            cvss_vector=effective_vector,
            attack_vector=knowledge.attack_vector,
            privileges_required=knowledge.privileges_required,
            user_interaction=knowledge.user_interaction,
            epss_score=knowledge.epss_score,
            epss_percentile=knowledge.epss_percentile,
            kev_listed=knowledge.kev_listed,
            kev_date_added=knowledge.kev_date_added,
            nvd_url=knowledge.nvd_url,
            published_at=knowledge.published_at,
            updated_at=knowledge.updated_at,
            notes=list(knowledge.notes),
            intel_source_mode=knowledge.intel_source_mode,
            intel_last_synced_at=knowledge.intel_last_synced_at,
            cvss_breakdown=breakdown,
        )
