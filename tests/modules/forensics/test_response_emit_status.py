"""Regression coverage for preserving forensics workflow outcomes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from aila.modules.forensics.contracts.status import InvestigationStatus, ProjectStatus
from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord
from aila.modules.forensics.workflow.definitions import _state_response_emit
from aila.platform.workflows.types import RESERVED_SUCCEEDED


class _FakeSession:
    def __init__(self, row: object | None) -> None:
        self.row = row
        self.added: list[object] = []

    async def exec(self, _statement: object) -> SimpleNamespace:
        return SimpleNamespace(first=lambda: self.row)

    def add(self, row: object) -> None:
        self.added.append(row)


class _FakeUnitOfWork:
    def __init__(self, row: object | None) -> None:
        self.session = _FakeSession(row)
        self.commit_count = 0

    async def __aenter__(self) -> _FakeUnitOfWork:
        return self

    async def __aexit__(self, *_args: object) -> None:
        return None

    async def commit(self) -> None:
        self.commit_count += 1


def _patch_unit_of_work(monkeypatch: pytest.MonkeyPatch, row: object | None) -> _FakeUnitOfWork:
    uow = _FakeUnitOfWork(row)
    monkeypatch.setattr("aila.platform.uow.UnitOfWork", lambda: uow)
    return uow


@pytest.mark.parametrize(
    ("initial_status", "expected_status"),
    [
        (ProjectStatus.FAILED.value, ProjectStatus.FAILED.value),
        (ProjectStatus.COMPLETED.value, ProjectStatus.COMPLETED.value),
        (ProjectStatus.CREATED.value, ProjectStatus.COMPLETED.value),
        (ProjectStatus.READY.value, ProjectStatus.COMPLETED.value),
        (ProjectStatus.ANALYZING.value, ProjectStatus.COMPLETED.value),
        ("legacy_status", "legacy_status"),
    ],
)
async def test_project_response_emit_preserves_failure_and_completes_active_states(
    monkeypatch: pytest.MonkeyPatch,
    initial_status: str,
    expected_status: str,
) -> None:
    project = ForensicsProjectRecord(
        id="project-1",
        name="test project",
        system_id=1,
        evidence_directory="/evidence",
        status=initial_status,
    )
    uow = _patch_unit_of_work(monkeypatch, project)

    result = await _state_response_emit(
        {"project_id": project.id, "status": ProjectStatus.READY.value},
        None,
    )

    assert project.status == expected_status
    assert result.output["status"] == expected_status
    assert result.next_state == RESERVED_SUCCEEDED
    assert uow.session.added == [project]
    assert uow.commit_count == 1


@pytest.mark.parametrize(
    ("initial_status", "expected_status"),
    [
        (InvestigationStatus.FAILED.value, InvestigationStatus.FAILED.value),
        (InvestigationStatus.CANCELLED.value, InvestigationStatus.CANCELLED.value),
        (InvestigationStatus.EXHAUSTED.value, InvestigationStatus.EXHAUSTED.value),
        (InvestigationStatus.COMPLETED.value, InvestigationStatus.COMPLETED.value),
        (InvestigationStatus.PENDING.value, InvestigationStatus.COMPLETED.value),
        (InvestigationStatus.RUNNING.value, InvestigationStatus.COMPLETED.value),
        ("legacy_status", "legacy_status"),
    ],
)
async def test_investigation_response_emit_preserves_terminal_outcomes(
    monkeypatch: pytest.MonkeyPatch,
    initial_status: str,
    expected_status: str,
) -> None:
    investigation = InvestigationRunRecord(
        id="investigation-1",
        project_id="project-1",
        question="What happened?",
        status=initial_status,
    )
    uow = _patch_unit_of_work(monkeypatch, investigation)

    result = await _state_response_emit(
        {
            "project_id": investigation.project_id,
            "investigation_id": investigation.id,
            "status": InvestigationStatus.RUNNING.value,
        },
        None,
    )

    assert investigation.status == expected_status
    assert result.output["status"] == expected_status
    assert result.next_state == RESERVED_SUCCEEDED
    assert uow.session.added == [investigation]
    assert uow.commit_count == 1


@pytest.mark.parametrize(
    ("input_status", "expected_status"),
    [
        (None, ProjectStatus.COMPLETED.value),
        (ProjectStatus.FAILED.value, ProjectStatus.FAILED.value),
    ],
)
async def test_response_emit_uses_input_status_when_the_record_was_removed(
    monkeypatch: pytest.MonkeyPatch,
    input_status: str | None,
    expected_status: str,
) -> None:
    uow = _patch_unit_of_work(monkeypatch, None)
    payload = {"project_id": "missing"}
    if input_status is not None:
        payload["status"] = input_status

    result = await _state_response_emit(payload, None)

    assert result.output["status"] == expected_status
    assert result.next_state == RESERVED_SUCCEEDED
    assert uow.session.added == []
    assert uow.commit_count == 1


async def test_response_emit_without_record_ids_does_not_open_a_unit_of_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "aila.platform.uow.UnitOfWork",
        lambda: pytest.fail("UnitOfWork should not be created without a record id"),
    )

    result = await _state_response_emit({"status": ProjectStatus.FAILED.value}, None)

    assert result.output["status"] == ProjectStatus.FAILED.value
    assert result.next_state == RESERVED_SUCCEEDED
