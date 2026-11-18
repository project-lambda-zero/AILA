"""Durable task artifact persistence: JSON results and atomic PDF writes."""

from __future__ import annotations

import os

import pytest
from sqlmodel import select

from aila.config import get_settings
from aila.platform.tasks import artifacts
from aila.platform.tasks.artifacts import store_task_json_result, store_task_pdf
from aila.storage.database import async_session_scope
from aila.storage.db_models import ArtifactRecord, ReportArtifactRecord

_JSON_LIMIT_BYTES = 64 * 1024


@pytest.fixture
def report_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "report_dir", tmp_path)
    return tmp_path


async def _json_rows(task_id: str) -> list[ArtifactRecord]:
    async with async_session_scope() as session:
        return list(
            (
                await session.exec(
                    select(ArtifactRecord).where(
                        ArtifactRecord.run_id == task_id,
                        ArtifactRecord.artifact_type == "task_result",
                    )
                )
            ).all()
        )


async def _pdf_rows(task_id: str) -> list[ReportArtifactRecord]:
    async with async_session_scope() as session:
        return list(
            (
                await session.exec(
                    select(ReportArtifactRecord).where(
                        ReportArtifactRecord.run_id == task_id,
                        ReportArtifactRecord.scope == "task",
                        ReportArtifactRecord.artifact_type == "pdf",
                    )
                )
            ).all()
        )


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_json_result_upserts_single_row_with_metadata():
    await store_task_json_result("json-task-1", "vulnerability", {"findings": 1}, "team-a")
    await store_task_json_result("json-task-1", "vulnerability", {"findings": 2}, "team-a")

    rows = await _json_rows("json-task-1")
    assert len(rows) == 1
    row = rows[0]
    assert row.module_id == "vulnerability"
    assert row.scope == "task"
    assert row.content_type == "application/json"
    assert row.team_id == "team-a"
    assert row.body == '{"findings":2}'


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_json_result_accepts_exact_64_kib_limit():
    # {"blob":"<n chars>"} compact encoding adds 11 bytes around the blob.
    payload = {"blob": "x" * (_JSON_LIMIT_BYTES - 11)}

    await store_task_json_result("json-task-limit", "vulnerability", payload, None)

    rows = await _json_rows("json-task-limit")
    assert len(rows) == 1
    assert len(rows[0].body.encode("utf-8")) == _JSON_LIMIT_BYTES


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_json_result_rejects_payload_over_limit():
    payload = {"blob": "x" * (_JSON_LIMIT_BYTES - 10)}

    with pytest.raises(ValueError, match="64 KiB"):
        await store_task_json_result("json-task-over", "vulnerability", payload, None)

    assert await _json_rows("json-task-over") == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db", "report_dir")
async def test_pdf_store_writes_file_and_row(report_dir):
    content = b"%PDF-1.4 first"

    artifact_id = await store_task_pdf("pdf-task-1", content, "team-a")

    assert isinstance(artifact_id, int)
    assert (report_dir / "pdf-task-1.pdf").read_bytes() == content
    rows = await _pdf_rows("pdf-task-1")
    assert len(rows) == 1
    assert rows[0].id == artifact_id
    assert rows[0].team_id == "team-a"
    assert rows[0].path == str((report_dir / "pdf-task-1.pdf").resolve())


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db", "report_dir")
async def test_pdf_upsert_replaces_content_and_keeps_id(report_dir):
    first_id = await store_task_pdf("pdf-task-2", b"%PDF-1.4 old", None)
    second_id = await store_task_pdf("pdf-task-2", b"%PDF-1.4 new", None)

    assert first_id == second_id
    assert (report_dir / "pdf-task-2.pdf").read_bytes() == b"%PDF-1.4 new"
    assert len(await _pdf_rows("pdf-task-2")) == 1


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db", "report_dir")
async def test_pdf_write_failure_leaves_no_file_or_row(report_dir, monkeypatch):
    def fail_replace(_src, _dst):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(artifacts.os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated rename failure"):
        await store_task_pdf("pdf-task-3", b"%PDF-1.4 lost", None)

    assert os.listdir(report_dir) == []
    assert await _pdf_rows("pdf-task-3") == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db", "report_dir")
async def test_pdf_rejects_task_id_escaping_report_dir(report_dir):
    with pytest.raises(ValueError, match="within the report directory"):
        await store_task_pdf("../escape", b"%PDF-1.4 bad", None)

    assert not (report_dir.parent / "escape.pdf").exists()
    assert await _pdf_rows("../escape") == []
