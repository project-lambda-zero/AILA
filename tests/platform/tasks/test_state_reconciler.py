"""RFC-07 phase 3 -- integration tests for
:class:`aila.platform.tasks.state_reconciler.StateReconciler`.

Exercises the deterministic per-task classification against a live
Postgres test DB (the ``test_db`` fixture wraps a per-test schema
truncation) plus a fake ``lock_present`` value via constructor -- Redis
is NOT required because the reconciler treats ``redis_url=None`` as "no
lock probe", and we simulate lock presence by driving the health path
directly.

Coverage:

* Happy path (no drift) -- reconcile is a no-op, healed=False.
* Terminal task + stale terminal cursor -- cursor deleted.
* Terminal task + resumable cursor + no lock (L3.2) -- stale cursor
  deleted, task row untouched.
* Operator-terminal task (CANCELLED) -- reconciler declines, honouring
  the RFC's "never resurrect operator-set states" rule.
* Running + no lock + resumable cursor -- re-enqueued UNDER THE SAME JOB
  ID inline (L3.1) so the checkpoint is picked back up; with the
  requeue unavailable the row is left RUNNING for the next pass (never
  CANCELLED-then-stranded).
* Running + no lock + no cursor -- status flipped to FAILED.
* Idempotency -- a second reconcile finds the drift already healed.
"""
from __future__ import annotations

import os
from datetime import timedelta
from uuid import uuid4

import pytest

import aila.platform.tasks.state_reconciler as reconciler_mod
from aila.platform.contracts import utc_now
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.state_reconciler import StateReconciler
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateCursor

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Seed helpers
# ---------------------------------------------------------------------------


async def _seed_task(
    *,
    status: str = TaskStatus.RUNNING.value,
    heartbeat_delta_min: int | None = None,
    started_delta_min: int = 60,
    track: str = "vulnerability",
) -> str:
    """Insert one TaskRecord + matching WorkflowRunRecord; return task id.

    The WorkflowRunRecord is required because the workflow_state_cursor
    row (seeded by ``_seed_cursor``) FKs to it; without the run row the
    cursor INSERT would fail with a foreign-key violation.
    """
    now = utc_now()
    task_id = f"task-{uuid4().hex[:8]}"
    heartbeat_at = (
        None if heartbeat_delta_min is None
        else now - timedelta(minutes=heartbeat_delta_min)
    )
    async with async_session_scope() as session:
        session.add(WorkflowRunRecord(
            id=task_id,
            query_text="test",
            action_id="test",
            module_id="test",
            status="running",
        ))
        session.add(TaskRecord(
            id=task_id,
            track=track,
            fn_path="aila.modules.x.tasks.run",
            fn_module="x",
            user_id="u",
            group_id="operator",
            status=status,
            started_at=now - timedelta(minutes=started_delta_min),
            heartbeat_at=heartbeat_at,
        ))
        await session.commit()
    return task_id


async def _seed_cursor(task_id: str, current_state: str) -> None:
    async with async_session_scope() as session:
        session.add(WorkflowStateCursor(
            run_id=task_id,
            current_state=current_state,
            state_input={},
            definition_id="test.v1",
        ))
        await session.commit()


async def _read_task(task_id: str) -> TaskRecord | None:
    async with async_session_scope() as session:
        return await session.get(TaskRecord, task_id)


async def _read_cursor(task_id: str) -> WorkflowStateCursor | None:
    async with async_session_scope() as session:
        return await session.get(WorkflowStateCursor, task_id)


# The reconciler under test uses a fake Redis URL that resolves to
# ``lock_present=None`` (no probe). That is the safe default for a unit
# test: every case that depends on ``lock_present`` is exercised via a
# subclass that overrides ``_probe_lock``.


class _NoLockReconciler(StateReconciler):
    """Reconciler variant with a deterministic ``_probe_lock`` return.

    Also stubs ``_drop_lock`` so the Redis mutation is deterministic
    (returns whatever ``lock_present`` reports -- True means the ghost
    key was ``delete``-d, False means the probe returned absent so
    there was nothing to drop). Tests never open a real Redis client.
    """

    def __init__(self, *, lock_present: bool | None) -> None:
        super().__init__(
            redis_url="redis://placeholder",
            heartbeat_threshold_s=60,
            zombie_threshold_s=30,
        )
        self._forced_lock = lock_present
        self._drop_lock_calls: list[str] = []

    async def _probe_lock(self, task_id: str) -> bool | None:  # noqa: ARG002
        return self._forced_lock

    async def _drop_lock(self, task_id: str) -> bool:
        self._drop_lock_calls.append(task_id)
        return bool(self._forced_lock)


# ---------------------------------------------------------------------------
# Read-only tests
# ---------------------------------------------------------------------------


class TestReadSignals:
    """``read_signals`` returns a snapshot of the three sources."""

    async def test_reads_task_and_cursor_state(self, test_db) -> None:
        del test_db
        task_id = await _seed_task()
        await _seed_cursor(task_id, "some_state")
        r = _NoLockReconciler(lock_present=False)
        signals = await r.read_signals(task_id)
        assert signals.task_id == task_id
        assert signals.task_status == TaskStatus.RUNNING.value
        assert signals.cursor_state == "some_state"
        assert signals.lock_present is False

    async def test_missing_task_returns_none_status(self, test_db) -> None:
        del test_db
        r = _NoLockReconciler(lock_present=False)
        signals = await r.read_signals("nonexistent")
        assert signals.task_status is None
        assert signals.cursor_state is None


# ---------------------------------------------------------------------------
# Happy-path (no drift) tests
# ---------------------------------------------------------------------------


class TestHappyPath:
    """Reconcile is a no-op when the three sources agree."""

    async def test_running_with_fresh_heartbeat_and_lock_no_op(
        self, test_db,
    ) -> None:
        del test_db
        task_id = await _seed_task(
            heartbeat_delta_min=0, started_delta_min=10,
        )
        # lock_present=True + fresh heartbeat -> nothing to heal.
        r = _NoLockReconciler(lock_present=True)
        report = await r.reconcile(task_id)
        assert report.healed is False
        assert report.actions == ()

    async def test_operator_cancelled_task_untouched(self, test_db) -> None:
        del test_db
        task_id = await _seed_task(status=TaskStatus.CANCELLED.value)
        r = _NoLockReconciler(lock_present=False)
        report = await r.reconcile(task_id)
        assert report.healed is False


# ---------------------------------------------------------------------------
# Drift-heal cases
# ---------------------------------------------------------------------------


class TestDriftHeal:
    """Every documented drift case flips into the correct action set."""

    async def test_terminal_task_with_terminal_cursor_deletes_cursor(
        self, test_db,
    ) -> None:
        del test_db
        task_id = await _seed_task(status=TaskStatus.DONE.value)
        await _seed_cursor(task_id, "__succeeded__")
        r = _NoLockReconciler(lock_present=False)
        report = await r.reconcile(task_id)
        assert report.healed is True
        assert report.get_action_kinds() == ("delete_stale_cursor",)
        # Post-heal: the cursor is gone.
        assert await _read_cursor(task_id) is None

    async def test_terminal_task_resumable_cursor_no_lock_deletes_cursor(
        self, test_db,
    ) -> None:
        """RFC-07 reconcile wave (L3.2 / Finding 9): the drift-table row
        "terminal | resumable | absent". The run is over (terminal task,
        no ARQ lock) but a non-terminal cursor survives -- a fresh
        dispatch would load a stale resumable position -- so the stale
        cursor is deleted. `__paused__` counts as non-reserved-terminal
        here and is cleaned too when its task has gone terminal."""
        del test_db
        task_id = await _seed_task(status=TaskStatus.FAILED.value)
        await _seed_cursor(task_id, "investigation_loop")  # resumable
        r = _NoLockReconciler(lock_present=False)
        report = await r.reconcile(task_id)
        assert report.healed is True
        assert report.get_action_kinds() == ("delete_stale_cursor",)
        # Post-heal: the stale resumable cursor is gone.
        assert await _read_cursor(task_id) is None
        # The terminal task row itself is untouched.
        rec = await _read_task(task_id)
        assert rec is not None
        assert rec.status == TaskStatus.FAILED.value

    async def test_running_no_lock_no_cursor_flips_failed(
        self, test_db,
    ) -> None:
        del test_db
        task_id = await _seed_task(
            heartbeat_delta_min=None,
            # started far enough back to trip the zombie threshold.
            started_delta_min=60,
        )
        r = _NoLockReconciler(lock_present=False)
        report = await r.reconcile(task_id)
        assert report.healed is True
        assert "flip_status_failed" in report.get_action_kinds()
        rec = await _read_task(task_id)
        assert rec is not None
        assert rec.status == TaskStatus.FAILED.value
        assert rec.error is not None
        assert "state_reconciler" in rec.error

    async def test_running_no_lock_resumable_cursor_requeues_inline(
        self, test_db, monkeypatch,
    ) -> None:
        """RFC-07 reconcile wave (L3.1): a running-without-lock task with a
        resumable cursor is re-enqueued under its OWN job id INLINE instead
        of being flipped CANCELLED-then-deferred. The cursor is left intact
        so the engine picks the checkpoint back up; the requeue is the heal.

        The requeue primitive is stubbed here (unit test has no Redis):
        asserting it was CALLED with the original task id + track and that
        its success is reported as the ``resume_same_job_id`` action is the
        behaviour contract -- a cancelled row would be invisible to the
        re-enqueue sweeps forever (Finding 3 stranding).
        """
        del test_db
        task_id = await _seed_task(
            heartbeat_delta_min=None,
            started_delta_min=60,
            track="vr",
        )
        await _seed_cursor(task_id, "investigation_loop")  # resumable

        called: list[tuple[str, str]] = []

        async def _fake_requeue(task_id_arg: str, *, track: str) -> bool:
            called.append((task_id_arg, track))
            return True

        monkeypatch.setattr(
            reconciler_mod, "requeue_same_job_id", _fake_requeue,
        )
        r = _NoLockReconciler(lock_present=False)
        report = await r.reconcile(task_id)
        assert report.healed is True
        assert report.get_action_kinds() == ("resume_same_job_id",)
        # The requeue used the original id + the row's track (never a
        # fresh uuid), so the checkpoint is picked back up.
        assert called == [(task_id, "vr")]
        rec = await _read_task(task_id)
        assert rec is not None
        # The row is NOT flipped CANCELLED by the reconciler; the requeue
        # primitive owns the run-again transition.
        assert rec.status != TaskStatus.CANCELLED.value
        # Cursor is left intact so the re-run resumes from the checkpoint.
        cursor = await _read_cursor(task_id)
        assert cursor is not None
        assert cursor.current_state == "investigation_loop"

    async def test_running_no_lock_resumable_cursor_requeue_unavailable_leaves_running(
        self, test_db,
    ) -> None:
        """L3.1 retry posture: when the same-job-id requeue cannot run
        (no Redis URL in this unit environment), the reconciler leaves the
        row RUNNING for a later pass instead of flipping CANCELLED -- a
        cancelled row is invisible to the re-enqueue sweeps forever."""
        del test_db
        task_id = await _seed_task(
            heartbeat_delta_min=None,
            started_delta_min=60,
        )
        await _seed_cursor(task_id, "investigation_loop")  # resumable
        # No AILA_PLATFORM_REDIS_URL -> requeue_same_job_id returns False.
        os.environ.pop("AILA_PLATFORM_REDIS_URL", None)
        r = _NoLockReconciler(lock_present=False)
        report = await r.reconcile(task_id)
        assert report.healed is False
        assert report.actions == ()
        rec = await _read_task(task_id)
        assert rec is not None
        assert rec.status == TaskStatus.RUNNING.value

    async def test_running_no_lock_terminal_cursor_flips_failed_and_deletes(
        self, test_db,
    ) -> None:
        """A cursor in a reserved terminal state is not resumable; the
        heal path flips FAILED and cleans up the stale cursor in the same
        call for a fully consistent row."""
        del test_db
        task_id = await _seed_task(
            heartbeat_delta_min=None,
            started_delta_min=60,
        )
        await _seed_cursor(task_id, "__crashed__")
        r = _NoLockReconciler(lock_present=False)
        report = await r.reconcile(task_id)
        assert report.healed is True
        kinds = report.get_action_kinds()
        assert "flip_status_failed" in kinds
        assert "delete_stale_cursor" in kinds
        rec = await _read_task(task_id)
        assert rec is not None
        assert rec.status == TaskStatus.FAILED.value
        assert await _read_cursor(task_id) is None

    async def test_case_d_running_lock_present_terminal_cursor_heals(
        self, test_db,
    ) -> None:
        """Case D (#120): worker completed the workflow (cursor is in a
        reserved terminal) but crashed before flipping TaskRecord, and
        the ARQ in-progress lock is still ghost-present. Without a
        dedicated case the reconciler falls through to the "consistent"
        no-op and reports healed=False, so the row sits stuck-RUNNING
        for 24h until the periodic reaper picks it up. The heal path
        MUST flip status FAILED, drop the ghost lock, and delete the
        terminal cursor -- three mutations, all idempotent."""
        del test_db
        # Fresh heartbeat: proves the heal fires on the cursor+lock
        # signal, not the stale-heartbeat reaper path (which would
        # otherwise mask the bug the test guards against).
        task_id = await _seed_task(
            heartbeat_delta_min=0, started_delta_min=5,
        )
        await _seed_cursor(task_id, "__succeeded__")
        r = _NoLockReconciler(lock_present=True)
        report = await r.reconcile(task_id)
        assert report.healed is True
        kinds = report.get_action_kinds()
        assert "flip_status_failed" in kinds
        assert "drop_in_progress_lock" in kinds
        assert "delete_stale_cursor" in kinds
        assert r._drop_lock_calls == [task_id]
        rec = await _read_task(task_id)
        assert rec is not None
        assert rec.status == TaskStatus.FAILED.value
        assert rec.error is not None
        assert "crashed mid-teardown" in rec.error
        assert await _read_cursor(task_id) is None
        # Second call: everything is already consistent -- healed=False.
        r2 = _NoLockReconciler(lock_present=False)
        second = await r2.reconcile(task_id)
        assert second.healed is False

    async def test_running_fresh_heartbeat_no_lock_left_alone(
        self, test_db,
    ) -> None:
        """A running task with a recent heartbeat but no lock is NOT a
        stale zombie yet -- reconcile declines to heal until the
        heartbeat truly stales."""
        del test_db
        task_id = await _seed_task(
            heartbeat_delta_min=0,  # brand new
            started_delta_min=5,
        )
        r = _NoLockReconciler(lock_present=False)
        report = await r.reconcile(task_id)
        assert report.healed is False


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    """A second reconcile finds the drift already healed."""

    async def test_second_call_no_op_after_terminal_cursor_delete(
        self, test_db,
    ) -> None:
        del test_db
        task_id = await _seed_task(status=TaskStatus.DONE.value)
        await _seed_cursor(task_id, "__succeeded__")
        r = _NoLockReconciler(lock_present=False)
        first = await r.reconcile(task_id)
        assert first.healed is True
        second = await r.reconcile(task_id)
        assert second.healed is False
        assert second.actions == ()

    async def test_second_call_no_op_after_flip_failed(
        self, test_db,
    ) -> None:
        del test_db
        task_id = await _seed_task(
            heartbeat_delta_min=None,
            started_delta_min=60,
        )
        r = _NoLockReconciler(lock_present=False)
        first = await r.reconcile(task_id)
        assert first.healed is True
        # After the flip, the row is terminal; a second call sees the
        # cursor still absent and takes no action.
        second = await r.reconcile(task_id)
        assert second.healed is False
