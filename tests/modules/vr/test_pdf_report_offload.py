"""#48 -- render_investigation_pdf offloads the blocking ReportLab render.

The ReportLab render (``_render_pdf``) is CPU-bound and synchronous; the
async entry point must run it on the platform worker pool via
``run_blocking_io`` so a large report does not stall the event loop for
every other request on the same worker.

This test isolates the offload wiring: fact collection, the writer, and
the renderer are all stubbed so no DB, LLM, or ReportLab work runs. It
asserts that ``_render_pdf`` is invoked THROUGH ``run_blocking_io`` (not
inline on the loop) and that the produced bytes propagate unchanged.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.modules.vr.reporting import pdf_report


class _StubWriter:
    """Stand-in for ReportWriter that skips the LLM round-trip."""

    async def write(self, _facts: dict[str, Any]) -> object:
        # _render_pdf is stubbed below, so the content object is opaque.
        return object()


@pytest.mark.asyncio
async def test_render_investigation_pdf_offloads_reportlab(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # No "final_answer" key -> the inline-PoC branch (an extra LLM call)
    # is skipped, keeping this test free of the writer entirely.
    canned_facts: dict[str, Any] = {"investigation_id": "inv-x"}

    async def _fake_collect(_inv_id: str) -> dict[str, Any]:
        return canned_facts

    def _stub_render(*, facts: dict[str, Any], content: Any) -> bytes:
        assert facts is canned_facts
        return b"%PDF-STUB"

    offloaded: list[Any] = []
    real_run_blocking_io = pdf_report.run_blocking_io

    async def _spy_run_blocking_io(func: Any, /, *args: Any, **kwargs: Any) -> Any:
        offloaded.append(func)
        return await real_run_blocking_io(func, *args, **kwargs)

    monkeypatch.setattr(pdf_report, "_collect_facts", _fake_collect)
    monkeypatch.setattr(pdf_report, "ReportWriter", _StubWriter)
    monkeypatch.setattr(pdf_report, "_render_pdf", _stub_render)
    monkeypatch.setattr(pdf_report, "run_blocking_io", _spy_run_blocking_io)

    result = await pdf_report.render_investigation_pdf("inv-x")

    assert result == b"%PDF-STUB"
    # The CPU-bound renderer must be dispatched through run_blocking_io,
    # never called inline on the event loop.
    assert pdf_report._render_pdf in offloaded, (
        "_render_pdf must run through run_blocking_io, saw offloaded="
        f"{offloaded!r}"
    )


# --------------------------------------------------------------------
# asyncio marker registration -- mirrors the sibling tests under
# tests/modules/vr/ (pytest-asyncio config discovered via pyproject.toml).
