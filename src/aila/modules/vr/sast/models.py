"""Immutable catalog model for the vendored SAST skill workflow."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

__all__ = ["SastPhase", "SastSkill"]


class SastPhase(StrEnum):
    """The three stages defined by the upstream SAST orchestration."""

    ANALYSIS = "analysis"
    DETECTION = "detection"
    REPORT = "report"


@dataclass(frozen=True, slots=True)
class SastSkill:
    """One upstream ``SKILL.md`` and its stable audit identity."""

    id: str
    title: str
    phase: SastPhase
    body_sha256: str

    @property
    def resource_path(self) -> str:
        return f"skills/{self.id}/SKILL.md"
