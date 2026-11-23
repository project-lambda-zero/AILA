from __future__ import annotations

import json

import pytest

from aila.modules.vr.db_models import VRInvestigationOutcomeRecord
from aila.modules.vr.sast.catalog import SAST_SKILLS
from aila.modules.vr.sast.diagnostics import extract_sast_diagnostics
from aila.modules.vr.sast.source import SastSourceService


def _outcome(kind: str, payload: dict, *, investigation_id: str = "detector") -> VRInvestigationOutcomeRecord:
    return VRInvestigationOutcomeRecord(
        id=f"outcome-{kind}", investigation_id=investigation_id, branch_id="branch",
        outcome_kind=kind, payload_json=json.dumps(payload), confidence="high",
    )


def test_diagnostic_extraction_keeps_unlocated_and_excludes_report_duplicates() -> None:
    sqli = next(skill for skill in SAST_SKILLS if skill.id == "sast-sqli")
    report = next(skill for skill in SAST_SKILLS if skill.id == "sast-report")
    located = _outcome("direct_finding", {
        "diagnostics": [{
            "message": "SQL injection", "path": "src\\db.py", "line_start": 8,
            "line_end": 9, "related_locations": [{"path": "src/routes.py", "line_start": 3}],
        }],
    })
    unlocated = _outcome("direct_finding", {"message": "Unlocated authorization flaw"})
    unlocated.id = "outcome-unlocated"
    report_outcome = _outcome("assessment_report", {
        "findings": [{"message": "duplicate", "path": "src/db.py", "line_start": 8}],
    }, investigation_id="report")

    diagnostics = extract_sast_diagnostics(
        [located, unlocated, report_outcome],
        {"detector": sqli, "report": report},
    )

    assert len(diagnostics) == 2
    assert diagnostics[0].id == "outcome-direct_finding:0"
    assert diagnostics[0].path == "src/db.py"
    assert diagnostics[0].line_start == 8
    assert diagnostics[0].related_locations[0].path == "src/routes.py"
    assert diagnostics[1].message == "Unlocated authorization flaw"
    assert diagnostics[1].path is None
    assert diagnostics[1].line_start is None

    malformed = _outcome("direct_finding", {})
    malformed.payload_json = "{"
    with pytest.raises(ValueError, match="malformed payload JSON"):
        extract_sast_diagnostics([malformed], {"detector": sqli})


@pytest.mark.asyncio
async def test_source_service_rejects_traversal_and_bounds_lines(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "large.py").write_bytes(b"one\ntwo\nthree\n")
    monkeypatch.setattr("aila.modules.vr.sast.source._MAX_LINES", 2)
    service = SastSourceService(mcp_path=str(tmp_path), index_id="index")

    source = await service.read_file("large.py")
    assert source.content == "one\ntwo\n"
    assert source.total_lines == 3
    assert source.truncated is True
    with pytest.raises(ValueError, match="safe repository-relative"):
        await service.read_file("../outside.py")
    with pytest.raises(ValueError, match="safe repository-relative"):
        await service.read_file("C:/outside.py")


@pytest.mark.asyncio
async def test_remote_source_uses_indexed_read_lines() -> None:
    class Bridge:
        def __init__(self) -> None:
            self.kwargs = None

        async def forward(self, **kwargs):
            self.kwargs = kwargs
            return {"content": "first\nsecond\n", "total_lines_in_file": 3}

    bridge = Bridge()
    service = SastSourceService(mcp_path="/not/mounted", index_id="index", bridge=bridge)
    source = await service.read_file("src/app.py")

    assert bridge.kwargs == {
        "action": "read_lines", "index_id": "index", "file_path": "src/app.py",
        "start": 1, "end": 20000,
    }
    assert source.content == "first\nsecond\n"
    assert source.total_lines == 3
    assert source.truncated is True
