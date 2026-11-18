"""Durable JSON results and PDF artifacts for independent platform tasks."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from sqlmodel import select

from aila.config import get_settings
from aila.platform.contracts import utc_now
from aila.platform.services.runtime import run_blocking_io
from aila.storage.database import async_session_scope
from aila.storage.db_models import ArtifactRecord, ReportArtifactRecord

__all__ = [
    "TASK_ARTIFACT_SCOPE",
    "TASK_PDF_ARTIFACT_TYPE",
    "TASK_RESULT_ARTIFACT_TYPE",
    "store_task_json_result",
    "store_task_pdf",
]

_MAX_JSON_RESULT_BYTES = 64 * 1024
TASK_RESULT_ARTIFACT_TYPE = "task_result"
TASK_PDF_ARTIFACT_TYPE = "pdf"
TASK_ARTIFACT_SCOPE = "task"


async def store_task_json_result(
    task_id: str,
    module_id: str,
    payload: dict[str, Any],
    team_id: str | None,
) -> None:
    """Insert or replace one task's durable JSON result.

    The compact UTF-8 representation stored in ``ArtifactRecord.body`` is
    capped at 64 KiB. Only the payload and its metadata are persisted; no
    result bytes are written to the task queue or Redis.
    """
    body = json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    if len(body.encode("utf-8")) > _MAX_JSON_RESULT_BYTES:
        raise ValueError("Task JSON result exceeds the 64 KiB durable-artifact limit.")

    async with async_session_scope() as session:
        record = (
            await session.exec(
                select(ArtifactRecord).where(
                    ArtifactRecord.run_id == task_id,
                    ArtifactRecord.artifact_type == TASK_RESULT_ARTIFACT_TYPE,
                )
            )
        ).first()
        if record is None:
            record = ArtifactRecord(
                run_id=task_id,
                module_id=module_id,
                scope=TASK_ARTIFACT_SCOPE,
                artifact_type=TASK_RESULT_ARTIFACT_TYPE,
                content_type="application/json",
                body=body,
            )
        else:
            record.module_id = module_id
            record.scope = TASK_ARTIFACT_SCOPE
            record.content_type = "application/json"
            record.body = body
            record.updated_at = utc_now()
        record.team_id = team_id
        session.add(record)
        await session.commit()


def _write_task_pdf(report_dir: Path, task_id: str, content: bytes) -> Path:
    """Atomically write a task PDF directly beneath ``report_dir``."""
    report_dir.mkdir(parents=True, exist_ok=True)
    root = report_dir.resolve()
    destination = (root / f"{task_id}.pdf").resolve()
    if destination.parent != root:
        raise ValueError("Task PDF path must resolve directly within the report directory.")

    descriptor, temporary_name = tempfile.mkstemp(
        dir=root,
        prefix=".task-",
        suffix=".pdf.tmp",
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, destination)
    finally:
        temporary_path.unlink(missing_ok=True)
    return destination


async def store_task_pdf(task_id: str, content: bytes, team_id: str | None) -> int:
    """Atomically persist a task PDF and upsert its database pointer."""
    settings = get_settings()
    path = await run_blocking_io(_write_task_pdf, settings.report_dir, task_id, content)
    path_text = str(path)

    async with async_session_scope() as session:
        record = (
            await session.exec(
                select(ReportArtifactRecord).where(
                    ReportArtifactRecord.run_id == task_id,
                    ReportArtifactRecord.scope == TASK_ARTIFACT_SCOPE,
                    ReportArtifactRecord.artifact_type == TASK_PDF_ARTIFACT_TYPE,
                )
            )
        ).first()
        if record is None:
            record = ReportArtifactRecord(
                run_id=task_id,
                scope=TASK_ARTIFACT_SCOPE,
                artifact_type=TASK_PDF_ARTIFACT_TYPE,
                path=path_text,
                content=path_text,
            )
        else:
            record.path = path_text
            record.content = path_text
        record.team_id = team_id
        session.add(record)
        await session.commit()
        await session.refresh(record)
        if record.id is None:
            raise RuntimeError("Persisted task PDF artifact has no database identifier.")
        return record.id
