"""Stuck forensics investigations are re-driven from their rows (#450).

The platform reset calls ``prepare_recovery_submit`` before it writes anything,
so a dispatch that cannot be built leaves the row untouched. The queue is
replaced with a recorder; the rows, branches and reset are real.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from aila.modules.forensics import _task_queue as _task_queue_mod
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services.recovery_submit import prepare_recovery_submit
from aila.modules.forensics.workflow.panel.task import run_forensics_panel_investigate
from aila.modules.forensics.workflow.task import run_forensics_investigation
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import (
    BranchStatus,
    InvestigationPauseReason,
    InvestigationStatus,
)
from aila.platform.services.investigation_lifecycle import (
    ReenqueueInvestigationError,
    reenqueue_investigation,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord

pytestmark = pytest.mark.usefixtures("test_db")

# Same pattern the forensics stuck healer and reconciler pass.
_FN_PATH_PATTERN = "%run_forensics%investigat%"


class _FakeQueue:
    """Records every submit; stands in for the ARQ-backed TaskQueue."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def submit(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        return SimpleNamespace(task_id="task-1")


@pytest.fixture
def fake_queue(monkeypatch: pytest.MonkeyPatch) -> _FakeQueue:
    queue = _FakeQueue()
    monkeypatch.setattr(_task_queue_mod, "default_task_queue", lambda: queue)
    return queue


async def _seed(
    *,
    with_system: bool = True,
    branch_status: str | None = None,
) -> tuple[str, str | None]:
    """Seed a running investigation carrying a stale pause and start stamp.

    Returns ``(investigation_id, branch_id)``; ``branch_id`` is set only when
    ``branch_status`` requests a branch row.
    """
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        system = ManagedSystemRecord(name=f"sys-{suffix}", host="10.0.0.1", username="u")
        session.add(system)
        await session.flush()
        project = ForensicsProjectRecord(
            name=f"proj-{suffix}",
            system_id=system.id,
            evidence_directory=f"/evidence/{suffix}",
        )
        session.add(project)
        await session.flush()
        if not with_system:
            await session.delete(system)
            await session.flush()
        inv = InvestigationRunRecord(
            project_id=project.id,
            question="What happened on the analyzer?",
            status=InvestigationStatus.RUNNING.value,
            pause_reason=InvestigationPauseReason.OPERATOR.value,
            started_at=utc_now(),
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id
        branch_id: str | None = None
        if branch_status is not None:
            branch = ForensicsInvestigationBranchRecord(
                investigation_id=inv_id,
                status=branch_status,
            )
            session.add(branch)
            await session.flush()
            branch_id = branch.id
        await session.commit()
    return inv_id, branch_id


async def _reenqueue(inv_id: str) -> dict[str, Any]:
    return await reenqueue_investigation(
        inv_id,
        inv_model=InvestigationRunRecord,
        fn_path_pattern=_FN_PATH_PATTERN,
        prepare_submit=prepare_recovery_submit,
        branch_model=ForensicsInvestigationBranchRecord,
        branch_status_active=BranchStatus.ACTIVE.value,
    )


async def test_freeflow_row_is_reset_and_relinked(fake_queue: _FakeQueue) -> None:
    inv_id, _ = await _seed()

    summary = await _reenqueue(inv_id)

    assert summary["submitted"] == 1
    [call] = fake_queue.calls
    assert call["fn"] is run_forensics_investigation
    assert call["kwargs"]["mode"] == "freeflow"
    assert call["kwargs"]["investigation_id"] == inv_id
    assert call["team_id"] is None

    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, inv_id)
        assert inv is not None
        assert inv.status == InvestigationStatus.CREATED.value
        assert inv.pause_reason is None
        assert inv.started_at is None
        assert inv.task_id == "task-1"


async def test_missing_system_refuses_reset_before_any_write(fake_queue: _FakeQueue) -> None:
    inv_id, _ = await _seed(with_system=False)

    with pytest.raises(ReenqueueInvestigationError):
        await _reenqueue(inv_id)

    assert fake_queue.calls == []
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, inv_id)
        assert inv is not None
        assert inv.status == InvestigationStatus.RUNNING.value
        assert inv.pause_reason == InvestigationPauseReason.OPERATOR.value


async def test_branched_investigation_without_active_branch_is_refused(
    fake_queue: _FakeQueue,
) -> None:
    inv_id, _ = await _seed(branch_status=BranchStatus.ABANDONED.value)

    with pytest.raises(ReenqueueInvestigationError):
        await _reenqueue(inv_id)

    assert fake_queue.calls == []
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, inv_id)
        assert inv is not None
        assert inv.status == InvestigationStatus.RUNNING.value


async def test_panel_investigation_is_redriven_per_active_branch(fake_queue: _FakeQueue) -> None:
    inv_id, branch_id = await _seed(branch_status=BranchStatus.ACTIVE.value)

    summary = await _reenqueue(inv_id)

    assert summary["submitted"] == 1
    [call] = fake_queue.calls
    assert call["fn"] is run_forensics_panel_investigate
    assert call["kwargs"] == {"investigation_id": inv_id, "branch_id": branch_id}
