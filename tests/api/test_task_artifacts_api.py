"""HTTP tests for GET /tasks/{task_id}/result and GET /tasks/{task_id}/artifact."""

from __future__ import annotations

import pytest
import pytest_asyncio

from aila.config import get_settings
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import async_session_scope
from aila.storage.db_models import ArtifactRecord, ReportArtifactRecord

_PDF_BYTES = b"%PDF-1.4 durable"


@pytest.fixture
def report_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(get_settings(), "report_dir", tmp_path)
    return tmp_path


async def _seed_task(task_id: str, user_id: str) -> str:
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=task_id,
                track="vulnerability",
                fn_path="aila.api.routers.scans:run_platform_handle",
                fn_module="__platform__",
                status=TaskStatus.DONE,
                user_id=user_id,
                group_id="admin",
            )
        )
        await session.commit()
    return task_id


async def _seed_json_result(task_id: str, payload_body: str) -> None:
    async with async_session_scope() as session:
        session.add(
            ArtifactRecord(
                run_id=task_id,
                module_id="vulnerability",
                scope="task",
                artifact_type="task_result",
                content_type="application/json",
                body=payload_body,
            )
        )
        await session.commit()


async def _seed_pdf_row(task_id: str, path: str) -> None:
    async with async_session_scope() as session:
        session.add(
            ReportArtifactRecord(
                run_id=task_id,
                scope="task",
                artifact_type="pdf",
                path=path,
                content=path,
            )
        )
        await session.commit()


@pytest_asyncio.fixture
async def owned_task(test_db, admin_key_record):
    return await _seed_task("artifact-api-task-1", admin_key_record.id)


@pytest.mark.asyncio
async def test_result_returns_stored_json_envelope(async_client, admin_token, owned_task):
    await _seed_json_result(owned_task, '{"findings":3}')

    resp = await async_client.get(
        f"/tasks/{owned_task}/result",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert resp.status_code == 200
    assert resp.json()["data"] == {"findings": 3}


@pytest.mark.asyncio
async def test_result_404_when_no_result_stored(async_client, admin_token, owned_task):
    resp = await async_client.get(
        f"/tasks/{owned_task}/result",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_result_404_for_unknown_task(async_client, admin_token):
    resp = await async_client.get(
        "/tasks/no-such-task/result",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_result_401_without_auth(async_client, owned_task):
    resp = await async_client.get(f"/tasks/{owned_task}/result")

    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_result_404_for_other_user_task(async_client, reader_token, owned_task):
    await _seed_json_result(owned_task, '{"findings":1}')

    resp = await async_client.get(
        f"/tasks/{owned_task}/result",
        headers={"Authorization": f"Bearer {reader_token}"},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_artifact_streams_pdf_bytes(async_client, admin_token, owned_task, report_dir):
    pdf_file = report_dir / f"{owned_task}.pdf"
    pdf_file.write_bytes(_PDF_BYTES)
    await _seed_pdf_row(owned_task, str(pdf_file.resolve()))

    resp = await async_client.get(
        f"/tasks/{owned_task}/artifact",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content == _PDF_BYTES


@pytest.mark.asyncio
async def test_artifact_404_when_no_row(async_client, admin_token, owned_task):
    resp = await async_client.get(
        f"/tasks/{owned_task}/artifact",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_artifact_404_when_file_missing(async_client, admin_token, owned_task, report_dir):
    await _seed_pdf_row(owned_task, str((report_dir / f"{owned_task}.pdf").resolve()))

    resp = await async_client.get(
        f"/tasks/{owned_task}/artifact",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_artifact_404_for_path_outside_report_dir(
    async_client, admin_token, owned_task, report_dir, tmp_path_factory
):
    outside = tmp_path_factory.mktemp("outside") / f"{owned_task}.pdf"
    outside.write_bytes(_PDF_BYTES)
    await _seed_pdf_row(owned_task, str(outside.resolve()))

    resp = await async_client.get(
        f"/tasks/{owned_task}/artifact",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_artifact_404_for_symlink_escaping_report_dir(
    async_client, admin_token, owned_task, report_dir, tmp_path_factory
):
    outside = tmp_path_factory.mktemp("outside") / "secret.pdf"
    outside.write_bytes(_PDF_BYTES)
    link = report_dir / f"{owned_task}.pdf"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlink creation requires privileges on this platform")
    await _seed_pdf_row(owned_task, str(link))

    resp = await async_client.get(
        f"/tasks/{owned_task}/artifact",
        headers={"Authorization": f"Bearer {admin_token}"},
    )

    assert resp.status_code == 404
