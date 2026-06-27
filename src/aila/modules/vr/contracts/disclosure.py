"""Disclosure submission contracts (Disclosure Lifecycle plan GA-31..GA-36).

v1 ships the schema + 4 built-in tracks + per-submission lifecycle. The
multi-track embargo coordination, vendor communications log, and ARQ
classifier all defer to v1.1.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "ArtifactTier",
    "DisclosureKind",
    "DisclosureSubmissionStatus",
    "DisclosureTrackInfo",
    "VRDisclosureSubmissionCreate",
    "VRDisclosureSubmissionPatch",
    "VRDisclosureSubmissionSummary",
]


class DisclosureKind(StrEnum):
    """Catalog of track families (GA-31).

    Track _ids_ live in the track registry -- this enum classifies them
    by kind so the UI can group / filter.
    """

    BOUNTY = "bounty"
    BROKER = "broker"
    COORDINATION = "coordination"
    VENDOR_DIRECT = "vendor_direct"
    CNA = "cna"
    PUBLIC = "public"
    ACADEMIC = "academic"


class DisclosureSubmissionStatus(StrEnum):
    """Per-track lifecycle states.

    Drafted     -- submission rendered, not yet sent
    Submitted   -- handed to vendor/program
    Acknowledged-- vendor confirmed receipt
    Triaging    -- vendor working it
    Accepted    -- vendor confirmed valid finding (bounty programs)
    Rejected    -- vendor declined (dup / out-of-scope / not-a-bug)
    Patched     -- fix shipped
    Published   -- public disclosure released (blog_post / advisory / CVE published)
    Closed      -- terminal (rewarded + paid; or rejection with no appeal; or withdrawn)
    Withdrawn   -- operator pulled submission
    """

    DRAFTED = "drafted"
    SUBMITTED = "submitted"
    ACKNOWLEDGED = "acknowledged"
    TRIAGING = "triaging"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    PATCHED = "patched"
    PUBLISHED = "published"
    CLOSED = "closed"
    WITHDRAWN = "withdrawn"


class ArtifactTier(StrEnum):
    """Three PoC tiers per GA-34.

    Tracks declare which tier they accept (chrome_vrp wants working_poc;
    blog_post wants sanitized_poc; cna_github_gsa accepts no_poc).
    """

    WORKING_POC = "working_poc"
    SANITIZED_POC = "sanitized_poc"
    NO_POC = "no_poc"


class DisclosureTrackInfo(BaseModel):
    """Read-only projection of a built-in DisclosureTrack."""

    model_config = ConfigDict(extra="forbid")

    track_id: str
    kind: DisclosureKind
    display_name: str
    program_url: str | None = None
    required_artifacts: list[str] = Field(default_factory=list)
    accepted_poc_tiers: list[ArtifactTier] = Field(default_factory=list)
    embargo_default_days: int | None = None
    severity_schema: str = "cvss"
    notes: str = ""


class VRDisclosureSubmissionCreate(BaseModel):
    """Input payload for POST /vr/disclosures.

    Operator chooses a track at creation time; the track determines the
    initial validation rules + template. Subsequent state transitions go
    through PATCH.

    The submission can be anchored on EITHER:
      * an existing finding (`finding_id`) -- the original path; the
        service binds the disclosure to that finding row, OR
      * an investigation (`investigation_id`) -- the operator-friendly
        path: the service resolves the investigation's
        ``linked_finding_ids``. Exactly one linked finding promotes to
        the disclosure; zero auto-creates a stub finding from the
        investigation's primary outcome; multiple raises an error
        asking the operator to specify ``finding_id`` directly.

    Exactly one of the two must be set; both-set / neither-set raise
    validation errors. This lets the new dropdown-driven UI submit an
    investigation id without forcing every caller to know the
    finding-derivation rules.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Existing finding id to bind to. Mutually exclusive with investigation_id.",
    )
    investigation_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=64,
        description=(
            "Investigation id whose linked finding (or stub finding "
            "created from its primary outcome) the disclosure attaches "
            "to. Mutually exclusive with finding_id."
        ),
    )
    track_id: str = Field(
        min_length=1,
        max_length=64,
        description="Track id from /vr/disclosure-tracks list.",
    )
    workspace_id: str = Field(min_length=1, max_length=64)
    poc_tier: ArtifactTier = ArtifactTier.NO_POC
    severity_rating: str | None = Field(
        default=None,
        max_length=64,
        description="Track-specific (e.g. 'critical' for chrome_vrp; '9.8 high' for CVSS).",
    )
    embargo_days_override: int | None = Field(
        default=None,
        ge=0,
        le=730,
        description=(
            "Override the track's default embargo. Operator confirmation "
            "needed on POST/PATCH to ANY value below the default."
        ),
    )
    notes: str = ""

    @model_validator(mode="after")
    def _exactly_one_anchor(self) -> VRDisclosureSubmissionCreate:
        # `extra='forbid'` already blocks unknown keys; this guard catches
        # the both-set / neither-set cases. The service layer would also
        # crash on a missing finding lookup but the error message would
        # be less actionable than this surface-level rejection.
        has_finding = bool(self.finding_id)
        has_investigation = bool(self.investigation_id)
        if has_finding == has_investigation:
            raise ValueError(
                "exactly one of finding_id or investigation_id must be set",
            )
        return self


class VRDisclosureSubmissionPatch(BaseModel):
    """Operator-driven state transitions + field updates."""

    model_config = ConfigDict(extra="forbid")

    status: DisclosureSubmissionStatus | None = None
    poc_tier: ArtifactTier | None = None
    severity_rating: str | None = Field(default=None, max_length=64)
    embargo_days_override: int | None = Field(default=None, ge=0, le=730)
    vendor_reference: str | None = Field(
        default=None,
        max_length=128,
        description="Vendor's tracking id once acknowledged (e.g. Chrome Issue Tracker number).",
    )
    bounty_awarded_usd: float | None = Field(default=None, ge=0)
    notes: str | None = None


class VRDisclosureSubmissionSummary(BaseModel):
    """Read projection of one submission."""

    model_config = ConfigDict(extra="forbid")

    id: str
    finding_id: str
    track_id: str
    workspace_id: str
    kind: DisclosureKind
    status: DisclosureSubmissionStatus
    poc_tier: ArtifactTier
    severity_rating: str | None = None
    embargo_until: datetime | None = None
    embargo_days_used: int | None = None
    vendor_reference: str | None = None
    bounty_awarded_usd: float | None = None
    rendered_submission_path: str | None = None
    notes: str = ""
    validation_errors: list[str] = Field(default_factory=list)
    track_info: DisclosureTrackInfo | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    sections: dict[str, str] = Field(
        default_factory=dict,
        description=(
            "Named sections of the advisory -- keys: summary, "
            "technical_details, reproduction, patches, references. "
            "Empty until the operator runs regenerate or edits in the "
            "structured editor (08_FRONTEND_UX.md §1.8)."
        ),
    )
    regenerated_from_finding_at: datetime | None = None


class RenderedSubmission(BaseModel):
    """Output of DisclosureService.render() -- what the operator sends."""

    model_config = ConfigDict(extra="forbid")

    submission_id: str
    track_id: str
    finding_id: str
    rendered_at: datetime
    body: str
    body_format: str = "markdown"
    metadata: dict[str, Any] = Field(default_factory=dict)
    validation_errors: list[str] = Field(default_factory=list)
