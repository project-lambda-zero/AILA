"""Pydantic response models for sbd_nfr endpoints.

Replaces bare-dict returns so every @router endpoint has a named type.
Each model maps 1:1 to a response site in api_router.py.
"""

from __future__ import annotations

from typing import Any

from pydantic import Field

from aila.api.schemas.common import APIModel

__all__ = [
    "ResolutionTriggerResponse",
    "BulkAssignResponse",
    "BulkExportResponse",
    "TriageContextResponse",
]


class ResolutionTriggerResponse(APIModel):
    """Response for POST /sessions/{session_id}/resolve (D-02).

    Returned with HTTP 202 when resolution has been successfully re-queued.
    """

    status: str = Field(description="Always 'resolving' when enqueued successfully")
    session_id: str = Field(description="Identifier of the session being resolved")


class BulkAssignResponse(APIModel):
    """Response for POST /sessions/bulk-assign (D-61).

    Maps each session_id to its assignment outcome ('assigned' or an error string).
    """

    results: dict[str, str] = Field(
        description="Per-session outcome: 'assigned' on success, 'error: <detail>' on failure"
    )


class BulkExportResponse(APIModel):
    """Response for POST /sessions/bulk-export (D-61).

    Maps each session_id to its export payload or an error dict.
    Missing or inaccessible sessions carry an 'error' key instead of session data.
    """

    exports: dict[str, Any] = Field(
        description="Per-session export dict; inaccessible sessions carry {error: <detail>}"
    )


class TriageContextResponse(APIModel):
    """Pre-triage risk context for a system (TRIAGE-01, TRIAGE-02).

    Sourced from the most recently completed NFR session linked to the system.
    All fields are optional because historical sessions may predate any given field.
    """

    data_sensitivity: str | None = Field(
        default=None,
        description="Raw scope answer (e.g. 'pii', 'confidential')",
    )
    internet_exposure: str | None = Field(
        default=None,
        description="Raw scope answer (e.g. 'internet_facing', 'internal')",
    )
    business_impact_tier: str | None = Field(
        default=None,
        description="'critical' | 'high' | 'medium' | 'low' | 'unknown'",
    )
    risk_tier: str | None = Field(
        default=None,
        description="'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'",
    )
    severity_multiplier: float | None = Field(
        default=None,
        description="Float used to adjust finding CVSS scores (TRIAGE-03, TRIAGE-04)",
    )

    model_config = {"extra": "allow"}
