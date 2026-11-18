"""Async vulnerability PDF: POST queues render_vulnerability_pdf; GET format=pdf is rejected."""
from __future__ import annotations

import time
from collections.abc import AsyncGenerator
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.api.app import create_app
from aila.modules.vulnerability import api_router as vuln_api_router
from aila.modules.vulnerability.workflow import task as vuln_task
from aila.platform.tasks.context import TaskContext

PDF_URL_TEMPLATE = "/vulnerability/reports/{run_id}/pdf"
REPORT_URL_TEMPLATE = "/vulnerability/reports/{run_id}"


class _FakeQueue:
    def __init__(self) -> None:
        self.submitted: list[dict[str, Any]] = []

    async def submit(self, **kwargs: Any) -> SimpleNamespace:
        self.submitted.append(kwargs)
        return SimpleNamespace(task_id="task-pdf-001")


@pytest_asyncio.fixture(scope="function")
async def pdf_client(
    test_db, monkeypatch: pytest.MonkeyPatch
) -> AsyncGenerator[tuple[AsyncClient, _FakeQueue], None]:
    """Real app; only the task queue boundary is replaced by a recording fake."""
    fake_queue = _FakeQueue()
    monkeypatch.setattr(vuln_api_router, "get_task_queue", lambda _module_id, _request: fake_queue)

    stub_runtime = MagicMock()
    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(transport=ASGITransport(app=test_app), base_url="http://testserver") as client:
        yield client, fake_queue


@pytest.mark.asyncio
async def test_post_pdf_returns_202_and_submits_reporting_task(
    pdf_client: tuple[AsyncClient, _FakeQueue],
    operator_token: str,
    seeded_run,
) -> None:
    """POST returns 202 with a bare TaskActionResponse and submits run_id with bypass_dedup."""
    client, fake_queue = pdf_client
    headers = {"Authorization": f"Bearer {operator_token}"}

    response = await client.post(PDF_URL_TEMPLATE.format(run_id=seeded_run.id), headers=headers)

    assert response.status_code == 202
    assert response.json() == {"task_id": "task-pdf-001", "status": "queued"}
    assert len(fake_queue.submitted) == 1
    submitted = fake_queue.submitted[0]
    assert submitted["track"] == "reporting"
    assert submitted["fn"] is vuln_task.render_vulnerability_pdf
    assert submitted["kwargs"] == {"run_id": seeded_run.id}
    assert submitted["bypass_dedup"] is True


@pytest.mark.asyncio
async def test_post_pdf_unknown_run_returns_404_without_submitting(
    pdf_client: tuple[AsyncClient, _FakeQueue],
    operator_token: str,
) -> None:
    """A run that does not exist is 404 and enqueues nothing."""
    client, fake_queue = pdf_client
    headers = {"Authorization": f"Bearer {operator_token}"}

    response = await client.post(PDF_URL_TEMPLATE.format(run_id="run-missing"), headers=headers)

    assert response.status_code == 404
    assert fake_queue.submitted == []


@pytest.mark.asyncio
async def test_get_report_format_pdf_is_rejected(
    pdf_client: tuple[AsyncClient, _FakeQueue],
    operator_token: str,
    seeded_run,
) -> None:
    """The synchronous PDF path is gone: format=pdf is an unknown export format (422)."""
    client, _ = pdf_client
    headers = {"Authorization": f"Bearer {operator_token}"}

    response = await client.get(f"{REPORT_URL_TEMPLATE.format(run_id=seeded_run.id)}?format=pdf", headers=headers)

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_render_vulnerability_pdf_stores_artifact_and_json_result(monkeypatch: pytest.MonkeyPatch) -> None:
    """Worker renders for ctx.team_id, stores PDF then JSON result, and returns the filename and artifact id."""
    calls: dict[str, Any] = {}

    async def fake_render(run_id: str, team_id: str | None = None) -> bytes:
        calls["render"] = (run_id, team_id)
        return b"%PDF-1.4 fake"

    async def fake_store_pdf(task_id: str, content: bytes, team_id: str | None) -> int:
        calls["store_pdf"] = (task_id, content, team_id)
        return 42

    async def fake_store_json(task_id: str, module_id: str, payload: dict[str, Any], team_id: str | None) -> None:
        calls["store_json"] = (task_id, module_id, payload, team_id)

    monkeypatch.setattr(vuln_task.PDFReportRenderer, "render_bytes_async", fake_render)
    monkeypatch.setattr(vuln_task, "store_task_pdf", fake_store_pdf)
    monkeypatch.setattr(vuln_task, "store_task_json_result", fake_store_json)

    ctx = TaskContext(task_id="task-pdf-001", job_try=1, user_id="user-1", team_id="team-x")
    result = await vuln_task.render_vulnerability_pdf.__wrapped__(ctx, run_id="run-test-001")

    assert calls["render"] == ("run-test-001", "team-x")
    assert calls["store_pdf"] == ("task-pdf-001", b"%PDF-1.4 fake", "team-x")
    assert calls["store_json"] == (
        "task-pdf-001",
        "vulnerability",
        {"filename": "run-test-001.pdf", "artifact_id": 42},
        "team-x",
    )
    assert result == {"filename": "run-test-001.pdf", "artifact_id": 42}


@pytest.mark.asyncio
async def test_render_vulnerability_pdf_import_error_stores_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Missing aila[pdf] extras fail the task; no artifact or result is recorded."""

    async def failing_render(run_id: str, team_id: str | None = None) -> bytes:
        raise ImportError("weasyprint not installed")

    store_pdf = AsyncMock()
    store_json = AsyncMock()
    monkeypatch.setattr(vuln_task.PDFReportRenderer, "render_bytes_async", failing_render)
    monkeypatch.setattr(vuln_task, "store_task_pdf", store_pdf)
    monkeypatch.setattr(vuln_task, "store_task_json_result", store_json)

    ctx = TaskContext(task_id="task-pdf-002", job_try=1, user_id="user-1", team_id="team-x")
    with pytest.raises(ImportError):
        await vuln_task.render_vulnerability_pdf.__wrapped__(ctx, run_id="run-test-001")

    store_pdf.assert_not_awaited()
    store_json.assert_not_awaited()
