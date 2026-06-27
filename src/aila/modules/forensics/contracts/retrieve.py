"""File-retrieval contract for pulling artefacts out of a disk image."""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "FetchRawRequest",
    "RetrieveFileRequest",
    "RetrieveFileResult",
]


class FetchRawRequest(BaseModel):
    """Inbound payload: pull a file or directory off the analyzer filesystem.

    Used by projects of kind ``raw_directory``. The ``evidence_id``
    selects one of the ProjectEvidenceRecord rows written by intake;
    the service reads that file (or zips it when it's a directory)
    directly from the analyzer -- no dissect, no disk image.
    """

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1)


class RetrieveFileRequest(BaseModel):
    """Inbound payload: extract ``virtual_path`` from the evidence image.

    ``virtual_path`` is the in-image path the analyst copied from a
    pre-analysis artefact. Both POSIX- and Windows-style separators are
    accepted; the server normalises.

    ``evidence_id`` is optional -- when omitted, the project's sole disk
    image is used. If multiple disk images exist the request is rejected
    with 400 and the caller must pick one.
    """

    model_config = ConfigDict(extra="forbid")

    virtual_path: str = Field(min_length=1, max_length=4096)
    evidence_id: str | None = None


class RetrieveFileResult(BaseModel):
    """Metadata returned in response headers (body is the raw bytes)."""

    model_config = ConfigDict(extra="forbid")

    filename: str
    size_bytes: int
    sha256: str
