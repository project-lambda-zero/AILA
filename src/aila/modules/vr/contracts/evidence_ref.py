"""Discriminated union for VR finding evidence references (#48-3.6).

A ``VRFindingRecord.evidence_refs_json`` list carries two shapes today,
both produced inside the vr module:

- ``SourceCitationRef``: a plain identifier (message id, outcome id,
  section source) wrapped as ``{"kind": "source_citation", "ref": "<id>"}``.
  Written by ``agents/outcome_dispatcher.py`` from the LLM outcome
  payload's ``evidence_refs`` list. The historical on-disk shape is a
  bare string; the ``EvidenceRefList`` before-validator normalizes bare
  strings into this dict form so legacy rows still validate on read.
- ``PocDraftMetadataRef``: the structured PocDraft sidecar appended by
  ``workflow/task.py::run_vr_draft_poc`` after a successful PoC generation.
  Consumed by ``reporting/pdf_report.py`` to render the build/run commands
  and caveats alongside the PoC source.

Every ref writer routes through
``EvidenceRefList.model_validate(refs).model_dump_json()`` so a mis-typed
dict (unknown ``kind`` or an unexpected field) raises ``ValidationError``
at write time instead of silently degrading to a blank section during
report render.
"""
from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator

__all__ = [
    "EvidenceRef",
    "EvidenceRefList",
    "PocDraftMetadataRef",
    "SourceCitationRef",
]


class SourceCitationRef(BaseModel):
    """Reference to a message/outcome id that supports a finding claim.

    Emitted by the outcome dispatcher when it forwards the LLM payload's
    ``evidence_refs`` list (originally ``list[str]`` per the outcome
    payload contract). Bare strings on the input side are normalized to
    this shape by ``EvidenceRefList`` so both new writes and legacy rows
    validate uniformly.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["source_citation"] = "source_citation"
    ref: str


class PocDraftMetadataRef(BaseModel):
    """Sidecar metadata persisted alongside ``VRFindingRecord.poc_code``.

    Field set mirrors the ``PocDraft`` contract at
    ``modules/vr/reporting/poc_writer.py``. Every non-discriminator field
    defaults to a safe empty value so that a partial legacy row still
    validates; new writes always populate the full set because the writer
    reads from a fully-validated ``PocDraft`` instance.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["poc_draft_metadata"] = "poc_draft_metadata"
    drafted_at: str = ""
    title: str = ""
    build_command: str = ""
    run_command: str = ""
    target_setup: str = ""
    expected_outcome: str = ""
    can_run: bool = False
    missing_inputs: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(default_factory=list)
    safety_notes: str = ""


EvidenceRef = Annotated[
    SourceCitationRef | PocDraftMetadataRef,
    Field(discriminator="kind"),
]


class EvidenceRefList(RootModel[list[EvidenceRef]]):
    """List wrapper that validates every entry against the discriminated union.

    A bare string in the input list is normalized to
    ``SourceCitationRef(ref=<string>)`` so historical rows written before
    the discriminated union landed continue to validate. Anything that is
    neither a bare string nor a valid discriminated dict raises
    ``ValidationError`` at write time.
    """

    @model_validator(mode="before")
    @classmethod
    def _normalize_bare_strings(cls, value: object) -> object:
        if not isinstance(value, list):
            return value
        normalized: list[object] = []
        for item in value:
            if isinstance(item, str):
                normalized.append({"kind": "source_citation", "ref": item})
            else:
                normalized.append(item)
        return normalized
