"""render_investigation_pdf threads the reporting task id into every LLM call.

The PDF is rendered on the reporting worker, so the render itself runs
directly (no ``run_blocking_io`` hop). What must hold is that the owning
task id arrives as ``run_id`` at both writers, so the spend lands on the
reporting task rather than ``_no_run``.

Collection, both writers and the renderer are stubbed: no DB, no LLM,
no ReportLab work.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.modules.vr.reporting import pdf_report


class _RecordingReportWriter:
    calls: list[str | None] = []

    async def write(self, _facts: dict[str, Any], *, run_id: str | None = None) -> object:
        _RecordingReportWriter.calls.append(run_id)
        return object()


class _RecordingPocWriter:
    calls: list[str | None] = []

    async def write(self, _facts: dict[str, Any], *, run_id: str | None = None) -> Any:
        _RecordingPocWriter.calls.append(run_id)
        return type(
            "_Draft",
            (),
            {
                "language": "python",
                "code": "print('x')",
                "title": "poc",
                "build_command": "",
                "run_command": "",
                "expected_outcome": "",
                "can_run": False,
                "caveats": "",
            },
        )()


@pytest.mark.asyncio
async def test_render_investigation_pdf_threads_run_id_to_writers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _RecordingReportWriter.calls = []
    _RecordingPocWriter.calls = []
    # final_answer set and no poc_drafts -> the inline PocWriter branch runs.
    canned_facts: dict[str, Any] = {
        "investigation_id": "inv-x",
        "final_answer": "SQL injection",
        "final_reasoning": "reasoning",
    }

    async def _fake_collect(_inv_id: str) -> dict[str, Any]:
        return canned_facts

    rendered: list[Any] = []

    def _stub_render(*, facts: dict[str, Any], content: Any) -> bytes:
        rendered.append((facts, content))
        return b"%PDF-STUB"

    monkeypatch.setattr(pdf_report, "_collect_facts", _fake_collect)
    monkeypatch.setattr(pdf_report, "ReportWriter", _RecordingReportWriter)
    monkeypatch.setattr(pdf_report, "PocWriter", _RecordingPocWriter)
    monkeypatch.setattr(pdf_report, "_render_pdf", _stub_render)

    result = await pdf_report.render_investigation_pdf("inv-x", run_id="task-123")

    assert result == b"%PDF-STUB"
    assert _RecordingPocWriter.calls == ["task-123"]
    assert _RecordingReportWriter.calls == ["task-123"]
    assert len(rendered) == 1
    assert rendered[0][0] is canned_facts
