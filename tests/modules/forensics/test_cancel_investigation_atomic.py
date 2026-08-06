"""#63 -- ``cancel_investigation`` MUST commit the task flip and the
investigation flip atomically.

Before the fix ``TaskRepository.set_cancelled`` committed the caller's
session internally BEFORE the handler mutated
``InvestigationRunRecord.status`` and called ``uow.commit()`` a second
time. If that second commit failed, the task row was hard-CANCELLED in
the DB while the investigation stayed RUNNING -- the 3-sources-of-truth
desync described in ``docs/GOTCHAS`` and CLAUDE.md.

The #63 fix inverts the contract: ``set_cancelled`` only stages the flip
(``session.add`` + ``session.flush``) and returns; the caller commits
once so both rows either land together or roll back together. The ARQ
in-progress key drop moves to ``finalize_cancel_side_effects`` invoked
AFTER the commit so a rollback cannot orphan the worker slot.

These tests seed a TaskRecord + InvestigationRunRecord and drive the
same code path the endpoint runs, using a raising commit to prove the
atomic rollback.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.api.constants import ROLE_ADMIN
from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import InvestigationRunRecord
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.storage import TaskRepository
from aila.platform.uow import UnitOfWork


def _admin_auth() -> AuthContext:
    return AuthContext(
        user_id="admin-63",
        role=ROLE_ADMIN,
        auth_type="api_key",
        team_id=None,
    )


async def _seed_task_and_inv(
    task_status: TaskStatus,
    inv_status: str,
) -> tuple[str, str]:
    """Insert one RUNNING TaskRecord + one linked InvestigationRunRecord."""
    task_id = "task-63-cancel"
    inv_id = "inv-63-cancel"
    async with UnitOfWork() as uow:
        uow.session.add(TaskRecord(
            id=task_id,
            track="forensics",
            fn_path="aila.modules.forensics.workflow.task.run_forensics_investigation",
            fn_module="__module__",
            status=task_status,
            user_id="u63",
            group_id="operator",
            kwargs_json="{}",
            updated_at=datetime.now(UTC),
        ))
        uow.session.add(InvestigationRunRecord(
            id=inv_id,
            project_id="proj-63",
            question="q",
            status=inv_status,
            task_id=task_id,
        ))
        await uow.session.commit()
    return task_id, inv_id


@pytest.mark.asyncio
async def test_cancel_investigation_pattern_commits_atomically(
    test_db,
) -> None:
    """The successful path leaves BOTH rows CANCELLED after one commit.

    Mirrors ``forensics/api_router.cancel_investigation``: stage the task
    flip via ``set_cancelled``, mutate the investigation row, then one
    ``uow.commit()``. Post-commit ``finalize_cancel_side_effects`` is a
    Redis I/O and is not asserted here.
    """
    task_id, inv_id = await _seed_task_and_inv(
        task_status=TaskStatus.RUNNING,
        inv_status=InvestigationStatus.RUNNING.value,
    )

    async with UnitOfWork() as uow:
        transitioned = await TaskRepository.set_cancelled(
            uow.session, task_id, _admin_auth(),
        )
        assert transitioned is True
        inv = (await uow.session.exec(
            select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == inv_id,
            )
        )).first()
        assert inv is not None
        inv.status = InvestigationStatus.CANCELLED.value
        inv.final_answer = "Cancelled by analyst."
        uow.session.add(inv)
        await uow.commit()

    async with UnitOfWork() as uow:
        task = (await uow.session.exec(
            select(TaskRecord).where(TaskRecord.id == task_id)
        )).first()
        inv = (await uow.session.exec(
            select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == inv_id
            )
        )).first()
    assert task is not None and task.status == TaskStatus.CANCELLED
    assert inv is not None and inv.status == InvestigationStatus.CANCELLED.value


@pytest.mark.asyncio
async def test_cancel_investigation_rolls_back_task_when_commit_fails(
    test_db,
) -> None:
    """Failed commit MUST leave BOTH rows unchanged (atomic).

    This is the exact desync the #63 fix closes. We stage the task cancel
    via ``set_cancelled``, mutate the investigation row, then patch
    ``session.commit`` to raise. The staged writes MUST be rolled back --
    task stays RUNNING, investigation stays RUNNING. Under the old
    contract the internal commit inside ``set_cancelled`` would have
    hardened the task's CANCELLED state before we ever reached the second
    commit that fails.
    """
    task_id, inv_id = await _seed_task_and_inv(
        task_status=TaskStatus.RUNNING,
        inv_status=InvestigationStatus.RUNNING.value,
    )

    with pytest.raises(IntegrityError):
        async with UnitOfWork() as uow:
            transitioned = await TaskRepository.set_cancelled(
                uow.session, task_id, _admin_auth(),
            )
            assert transitioned is True
            inv = (await uow.session.exec(
                select(InvestigationRunRecord).where(
                    InvestigationRunRecord.id == inv_id,
                )
            )).first()
            assert inv is not None
            inv.status = InvestigationStatus.CANCELLED.value
            uow.session.add(inv)

            # Force the atomic commit to fail. Under the pre-fix contract
            # the task row was already committed inside set_cancelled; the
            # ``raise`` here would land AFTER that first commit and orphan
            # a CANCELLED task alongside a still-RUNNING investigation.
            # Under the #63 contract nothing is committed yet, so the
            # rollback on __aexit__ discards BOTH staged writes.
            original_commit = uow.session.commit

            async def _explode() -> None:
                # Restore so the auto-rollback path (also uses commit
                # indirectly on some drivers) does not recurse. In practice
                # rollback -- not commit -- runs after this raise.
                uow.session.commit = original_commit  # type: ignore[method-assign]
                raise IntegrityError("boom", None, Exception("simulated"))

            uow.session.commit = _explode  # type: ignore[method-assign]
            await uow.commit()

    # BOTH rows must be untouched -- atomic cancel proven.
    async with UnitOfWork() as uow:
        task = (await uow.session.exec(
            select(TaskRecord).where(TaskRecord.id == task_id)
        )).first()
        inv = (await uow.session.exec(
            select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == inv_id
            )
        )).first()
    assert task is not None and task.status == TaskStatus.RUNNING, (
        "Task row leaked CANCELLED across a failed commit -- the "
        "double-commit desync is back (#63)."
    )
    assert inv is not None and inv.status == InvestigationStatus.RUNNING.value


@pytest.mark.asyncio
async def test_set_cancelled_does_not_commit_the_caller_session(
    test_db,
) -> None:
    """Direct contract check: without a caller commit the flip is lost.

    ``set_cancelled`` MUST NOT commit the caller's session. A caller that
    forgets to commit (would trigger ``UnitOfWorkNotCommittedError`` in
    real UoW-scoped code) sees the row rolled back -- same as any other
    staged mutation. The test uses ``session.rollback`` to bypass the
    UoW backstop and prove the underlying DB state is untouched.
    """
    task_id, _inv_id = await _seed_task_and_inv(
        task_status=TaskStatus.RUNNING,
        inv_status=InvestigationStatus.RUNNING.value,
    )

    async with UnitOfWork() as uow:
        transitioned = await TaskRepository.set_cancelled(
            uow.session, task_id, _admin_auth(),
        )
        assert transitioned is True
        await uow.rollback()  # caller explicitly rolls back instead of commit

    async with UnitOfWork() as uow:
        task = (await uow.session.exec(
            select(TaskRecord).where(TaskRecord.id == task_id)
        )).first()
    assert task is not None
    assert task.status == TaskStatus.RUNNING, (
        "set_cancelled committed the caller's session -- the #63 fix has "
        "regressed (see docstring for the desync channel it closed)."
    )
