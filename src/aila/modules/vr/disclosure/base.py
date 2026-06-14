"""DisclosureTrack base class — what every track plugin implements.

Each track produces a rendered submission body (Markdown) from a
VRFinding plus the operator's choices (poc_tier, severity_rating,
embargo_days). Validation runs at render time: missing required
artifacts → validation_errors populated and the render still returns
the body so the operator can see what's missing.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.contracts.disclosure import (
    ArtifactTier,
    DisclosureKind,
    DisclosureTrackInfo,
)

__all__ = ["DisclosureTrack"]


class DisclosureTrack:
    """Base class for disclosure tracks (GA-31).

    Subclasses override class attributes + the ``render`` method.
    """

    track_id: str = ""
    kind: DisclosureKind = DisclosureKind.VENDOR_DIRECT
    display_name: str = ""
    program_url: str | None = None
    required_artifacts: tuple[str, ...] = ()
    accepted_poc_tiers: tuple[ArtifactTier, ...] = (
        ArtifactTier.NO_POC,
        ArtifactTier.SANITIZED_POC,
        ArtifactTier.WORKING_POC,
    )
    embargo_default_days: int | None = None
    severity_schema: str = "cvss"
    notes: str = ""

    @classmethod
    def info(cls) -> DisclosureTrackInfo:
        """Return the registry projection of this track."""
        return DisclosureTrackInfo(
            track_id=cls.track_id,
            kind=cls.kind,
            display_name=cls.display_name,
            program_url=cls.program_url,
            required_artifacts=list(cls.required_artifacts),
            accepted_poc_tiers=list(cls.accepted_poc_tiers),
            embargo_default_days=cls.embargo_default_days,
            severity_schema=cls.severity_schema,
            notes=cls.notes,
        )

    @classmethod
    def validate(
        cls,
        *,
        poc_tier: ArtifactTier,
        finding_payload: dict[str, Any],
    ) -> list[str]:
        """Return a list of validation errors. Empty list = ready to submit.

        Subclasses may add track-specific checks. The base implementation
        enforces the accepted-poc-tier rule + the required_artifacts list
        against keys present on the finding payload.
        """
        errors: list[str] = []
        if poc_tier not in cls.accepted_poc_tiers:
            errors.append(
                f"track {cls.track_id} does not accept poc_tier={poc_tier.value}; "
                f"accepted: {[t.value for t in cls.accepted_poc_tiers]}",
            )
        for artifact in cls.required_artifacts:
            if not finding_payload.get(artifact):
                errors.append(f"missing required artifact: {artifact}")
        return errors

    @classmethod
    def render(
        cls,
        *,
        finding_payload: dict[str, Any],
        poc_tier: ArtifactTier,
        severity_rating: str | None,
        embargo_days: int | None,
    ) -> str:
        """Render the submission body. Override per-track.

        Returns Markdown by default. Subclasses targeting non-Markdown
        APIs (form fields, JSON payloads) should still emit a
        human-readable Markdown rendering — the operator pastes/uploads
        the actual format separately when needed.
        """
        del finding_payload, poc_tier, severity_rating, embargo_days
        raise NotImplementedError("Subclass must implement render()")
