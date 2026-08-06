"""Contract tests for the VR ``EvidenceRefList`` discriminated union (#48-3.6).

These tests exercise the pure Pydantic surface only. No DB, no LLM, no
network: every case boils down to ``model_validate`` / ``model_dump_json``
round-trips or a targeted ``ValidationError`` assertion.
"""
from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from aila.modules.vr.contracts.evidence_ref import (
    EvidenceRefList,
    PocDraftMetadataRef,
    SourceCitationRef,
)


class TestSourceCitationRef:
    def test_round_trip_via_list_wrapper(self) -> None:
        """Well-formed source_citation dict validates and round-trips."""
        original = [{"kind": "source_citation", "ref": "msg-123"}]
        wrapped = EvidenceRefList.model_validate(original)
        assert len(wrapped.root) == 1
        assert isinstance(wrapped.root[0], SourceCitationRef)
        assert wrapped.root[0].ref == "msg-123"

        restored = EvidenceRefList.model_validate_json(wrapped.model_dump_json())
        assert isinstance(restored.root[0], SourceCitationRef)
        assert restored.root[0].ref == "msg-123"

    def test_bare_string_normalizes_to_source_citation(self) -> None:
        """Legacy bare-string entries are normalized on read.

        Historical ``VRFindingRecord.evidence_refs_json`` rows written by
        the outcome dispatcher stored a bare ``list[str]``. The
        ``before`` validator wraps each string as a source_citation dict
        so the discriminated union still validates.
        """
        wrapped = EvidenceRefList.model_validate(["msg-1", "outcome-2"])
        assert [r.ref for r in wrapped.root] == ["msg-1", "outcome-2"]
        dumped = json.loads(wrapped.model_dump_json())
        assert dumped == [
            {"kind": "source_citation", "ref": "msg-1"},
            {"kind": "source_citation", "ref": "outcome-2"},
        ]

    def test_extra_field_forbidden(self) -> None:
        """``extra='forbid'`` catches an unknown key on source_citation."""
        with pytest.raises(ValidationError):
            EvidenceRefList.model_validate(
                [{"kind": "source_citation", "ref": "msg-1", "note": "x"}],
            )

    def test_missing_ref_field(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceRefList.model_validate([{"kind": "source_citation"}])


class TestPocDraftMetadataRef:
    def _sample(self) -> dict[str, object]:
        return {
            "kind": "poc_draft_metadata",
            "drafted_at": "2026-07-20T10:00:00+00:00",
            "title": "libfoo heap OOB",
            "build_command": "gcc -o poc poc.c",
            "run_command": "./poc",
            "target_setup": "docker run -p 8080:80 libfoo:2.1",
            "expected_outcome": "SIGSEGV in parse_frame",
            "can_run": True,
            "missing_inputs": [],
            "caveats": ["requires ASLR off"],
            "safety_notes": "target only owned hosts",
        }

    def test_round_trip_via_list_wrapper(self) -> None:
        wrapped = EvidenceRefList.model_validate([self._sample()])
        assert isinstance(wrapped.root[0], PocDraftMetadataRef)
        restored = EvidenceRefList.model_validate_json(wrapped.model_dump_json())
        assert isinstance(restored.root[0], PocDraftMetadataRef)
        assert restored.root[0].title == "libfoo heap OOB"
        assert restored.root[0].can_run is True
        assert restored.root[0].caveats == ["requires ASLR off"]

    def test_defaults_fill_missing_optional_fields(self) -> None:
        """Only the discriminator is required; everything else defaults."""
        wrapped = EvidenceRefList.model_validate(
            [{"kind": "poc_draft_metadata"}],
        )
        ref = wrapped.root[0]
        assert isinstance(ref, PocDraftMetadataRef)
        assert ref.title == ""
        assert ref.can_run is False
        assert ref.missing_inputs == []
        assert ref.caveats == []

    def test_extra_field_forbidden(self) -> None:
        payload = self._sample()
        payload["bogus_field"] = "x"
        with pytest.raises(ValidationError):
            EvidenceRefList.model_validate([payload])


class TestEvidenceRefList:
    def test_mixed_list_validates(self) -> None:
        """Bare source strings and a poc_draft dict co-exist in one list.

        Reproduces the on-disk shape produced by the two writers today:
        outcome_dispatcher emits bare source ids into
        ``evidence_refs_json``, then ``run_vr_draft_poc`` appends a
        ``poc_draft_metadata`` sidecar.
        """
        raw = [
            "msg-1",
            "outcome-2",
            {
                "kind": "poc_draft_metadata",
                "title": "sample",
                "run_command": "./poc",
                "expected_outcome": "crash",
                "can_run": False,
            },
        ]
        wrapped = EvidenceRefList.model_validate(raw)
        assert len(wrapped.root) == 3
        assert isinstance(wrapped.root[0], SourceCitationRef)
        assert isinstance(wrapped.root[1], SourceCitationRef)
        assert isinstance(wrapped.root[2], PocDraftMetadataRef)

        # model_dump_json is what the writers persist; it must
        # re-validate back through the same wrapper.
        restored = EvidenceRefList.model_validate_json(wrapped.model_dump_json())
        assert [type(r).__name__ for r in restored.root] == [
            "SourceCitationRef",
            "SourceCitationRef",
            "PocDraftMetadataRef",
        ]

    def test_unknown_kind_rejected(self) -> None:
        """Discriminator with a value outside the union is a hard error."""
        with pytest.raises(ValidationError):
            EvidenceRefList.model_validate(
                [{"kind": "mystery_kind", "value": "x"}],
            )

    def test_empty_list_validates(self) -> None:
        wrapped = EvidenceRefList.model_validate([])
        assert wrapped.root == []
        assert wrapped.model_dump_json() == "[]"

    def test_invalid_json_raises(self) -> None:
        with pytest.raises(ValidationError):
            EvidenceRefList.model_validate_json("not-json")

    def test_non_list_input_rejected(self) -> None:
        """A dict where a list was expected must fail validation."""
        with pytest.raises(ValidationError):
            EvidenceRefList.model_validate({"kind": "source_citation", "ref": "x"})
