"""CVE feed + memo invalidation contracts (v0.4 GA-51).

The CVE feed poller normalizes records from NVD JSON 2.0 + GitHub
Security Advisory feed into ``vr_cve_records``. Each new CVE
triggers a similarity scan over the workspace's audit memos: matches
get an `invalidation_event` so the operator sees "this memo may be
outdated — CVE-2026-XXXXX landed in the same area".
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CVEFeedSource",
    "CVERecordSummary",
    "MemoInvalidationEvent",
    "VRCVERecordCreate",
]


class CVEFeedSource(StrEnum):
    """Where this CVE record was ingested from."""

    NVD = "nvd"
    GHSA = "ghsa"
    MITRE = "mitre"
    MANUAL = "manual"


class VRCVERecordCreate(BaseModel):
    """Insert payload for one CVE record (operator manual + poller use same shape)."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(min_length=1, max_length=32, pattern=r"^CVE-\d{4}-\d{4,}$")
    source: CVEFeedSource = CVEFeedSource.MANUAL
    title: str = Field(default="", max_length=512)
    description: str = Field(default="")
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    raw_payload: dict[str, Any] = Field(default_factory=dict)


class CVERecordSummary(BaseModel):
    """Read projection."""

    model_config = ConfigDict(extra="forbid")

    id: str
    cve_id: str
    source: CVEFeedSource
    title: str
    description: str
    published_at: datetime | None = None
    last_modified_at: datetime | None = None
    cvss_score: float | None = None
    cwe_ids: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    invalidations_triggered: int = 0
    ingested_at: datetime | None = None


class MemoInvalidationEvent(BaseModel):
    """One memo flagged as potentially invalidated by a new CVE.

    The event is appended to the KnowledgeEntryRecord's metadata so the
    operator UI can show "this memo may be outdated — CVE-XXXX-YYYY
    landed in same area".
    """

    model_config = ConfigDict(extra="forbid")

    memo_entry_id: int
    cve_id: str
    similarity_score: float
    flagged_at: datetime
    namespace: str
