"""Phase 7: VR module Pydantic contract validation.

Tests cover the public contract surface in ``aila.modules.vr.contracts``:
enum cardinalities, required vs optional fields, ``extra='forbid'`` enforcement,
``ge=0`` constraints on PoCResult, and round-tripping through ``model_dump``/
``model_validate`` to catch silent schema drift.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from aila.modules.vr.contracts import (
    CrashSignature,
    CrashType,
    CWEMapping,
    DisclosureStatus,
    InputSource,
    PoCResult,
    TargetFormat,
    TargetIngestionSpec,
    VRProjectCreate,
    VRProjectStatus,
    VRProjectSummary,
)

__all__ = [
    "TestEnumCardinality",
    "TestVRTarget",
    "TestVRProjectCreate",
    "TestVRProjectSummary",
    "TestAdvisoryContracts",
    "TestFindingContracts",
]


class TestEnumCardinality:

    def test_target_format_has_15_members(self) -> None:
        assert len(list(TargetFormat)) == 15

    def test_input_source_has_3_members(self) -> None:
        assert len(list(InputSource)) == 3
        assert {m.value for m in InputSource} == {"upload", "git_repo", "http_url"}

    def test_crash_type_has_24_members(self) -> None:
        assert len(list(CrashType)) == 24

    def test_disclosure_status_has_6_members(self) -> None:
        assert len(list(DisclosureStatus)) == 6
        assert {m.value for m in DisclosureStatus} == {
            "undisclosed", "reported", "acknowledged",
            "patch_pending", "patched", "public",
        }

    def test_project_status_values(self) -> None:
        assert {m.value for m in VRProjectStatus} == {
            "created", "analyzing", "completed", "failed", "stalled",
        }


class TestVRTarget:
    def test_input_source_required(self) -> None:
        with pytest.raises(ValidationError):
            TargetIngestionSpec()  # type: ignore[call-arg]

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            TargetIngestionSpec(input_source=InputSource.UPLOAD, bogus_field="x")  # type: ignore[call-arg]


class TestVRProjectCreate:
    def _target(self) -> TargetIngestionSpec:
        return TargetIngestionSpec(input_source=InputSource.UPLOAD)

    def test_name_min_length(self) -> None:
        with pytest.raises(ValidationError):
            VRProjectCreate(name="", workspace_id="ws-1", target=self._target(), analysis_system_id=1)

    def test_analysis_system_id_required(self) -> None:
        with pytest.raises(ValidationError):
            VRProjectCreate(name="x", workspace_id="ws-1", target=self._target())  # type: ignore[call-arg]

    def test_workspace_id_required(self) -> None:
        with pytest.raises(ValidationError):
            VRProjectCreate(name="x", target=self._target(), analysis_system_id=1)  # type: ignore[call-arg]

    def test_patched_target_optional(self) -> None:
        p = VRProjectCreate(name="x", workspace_id="ws-1", target=self._target(), analysis_system_id=1)
        assert p.patched_target is None
        assert p.poc_system_id is None
        assert p.context_notes == ""
        assert p.workspace_id == "ws-1"

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            VRProjectCreate(  # type: ignore[call-arg]
                name="x", workspace_id="ws-1", target=self._target(), analysis_system_id=1, junk=1,
            )


class TestVRProjectSummary:
    def test_round_trip(self) -> None:
        original = VRProjectSummary(
            id="proj-1",
            name="libfoo CVE",
            cve_id="CVE-2025-1",
            status=VRProjectStatus.ANALYZING,
            workspace_id="ws-1",
            target_id="tgt-1",
            patched_target_id=None,
            finding_count=3,
            created_at="2026-01-01T00:00:00Z",
        )
        dumped = original.model_dump()
        restored = VRProjectSummary.model_validate(dumped)
        assert restored == original


class TestAdvisoryContracts:

    def test_cwe_requires_cwe_id(self) -> None:
        with pytest.raises(ValidationError):
            CWEMapping()  # type: ignore[call-arg]
        m = CWEMapping(cwe_id="CWE-122")
        assert m.cwe_id == "CWE-122"
        assert m.name == ""


class TestFindingContracts:
    def test_poc_result_ge_zero(self) -> None:
        with pytest.raises(ValidationError):
            PoCResult(code="x", crashes_vulnerable=-1)
        with pytest.raises(ValidationError):
            PoCResult(code="x", crashes_patched=-1)
        ok = PoCResult(code="x", crashes_vulnerable=0, crashes_patched=0)
        assert ok.language == "python"

    def test_crash_signature_requires_signature_hash(self) -> None:
        with pytest.raises(ValidationError):
            CrashSignature(crash_type=CrashType.OVERFLOW_HEAP)  # type: ignore[call-arg]
        sig = CrashSignature(
            crash_type=CrashType.OVERFLOW_HEAP,
            frames=["a", "b"],
            signature_hash="deadbeef",
        )
        assert sig.signature_hash == "deadbeef"
        assert sig.frames == ["a", "b"]
