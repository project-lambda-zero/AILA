"""Issue #98: the reverse-orphan sweep in ``_sweep_orphan_running_tasks``
must re-enqueue a resumable D-86 workflow by the fully-qualified ARQ
registry name (``TaskRecord.fn_path``), NOT by ``fn_path.rsplit(".", 1)[-1]``.

``_Registry.all_functions`` (``aila.platform.tasks.template``) registers
each function with ARQ under ``name={fn.__module__}.{fn.__qualname__}``
-- i.e. the same string stored in ``TaskRecord.fn_path``. The bare tail
form never resolves against ARQ's function map, so the job is silently
dropped and the investigation stalls with a resumable cursor but no
worker pickup.

``queue.py`` (``_enqueue_arq_job`` at line 141, ``TaskQueue.submit`` at
line 873) and ``hooks._enqueue_dependents`` (covered by
``test_enqueue_dependents_qualified_name.py``) already pass the full
``fn_path``. The reverse sweep in ``worker.py`` was the last site
still stripping to the bare tail.

Test strategy: insert a RUNNING TaskRecord with a stale heartbeat and a
lock-missing signal, stub ``_workflow_cursor_is_resumable`` to True so
the D-86 branch fires, mock the aioredis client + ``arq.create_pool``,
and assert the first positional arg to ``enqueue_job`` equals the row's
``fn_path`` in full.

Runs against the SQLite failsafe DB harness in ``conftest.py``; no live
Redis is required.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlmodel import Session

import aila.platform.tasks.worker as worker_mod
from aila.platform.tasks.constants import ARQ_QUEUE_KEY_TEMPLATE
from aila.platform.tasks.models import TaskRecord, TaskStatus

from .conftest import sqlite_db_env


def _fake_redis_client() -> MagicMock:
    """Stand-in for the aioredis client the reverse sweep opens.

    ``exists(arq:in-progress:<id>)`` returns 0 -- the lock-missing
    signal that steers ``_sweep_orphan_running_tasks`` into the
    D-86-resumable branch.
    """
    client = MagicMock()
    client.exists = AsyncMock(return_value=0)
    client.delete = AsyncMock(return_value=1)
    client.aclose = AsyncMock()
    return client


def _insert_stale_running(session: Session, *, fn_path: str) -> str:
    """Insert a RUNNING row whose heartbeat + started_at both predate
    the reverse-sweep stale_cutoff, so the D-86 branch fires when the
    ARQ in-progress lock is absent.
    """
    tid = str(uuid4())
    stale = datetime.now(UTC) - timedelta(minutes=10)
    rec = TaskRecord(
        id=tid,
        track="vulnerability",
        fn_path=fn_path,
        fn_module="vulnerability",
        status=TaskStatus.RUNNING,
        user_id="u",
        group_id="operator",
        kwargs_json='{"target_id": "abc123"}',
        created_at=stale,
        updated_at=stale,
        started_at=stale,
        heartbeat_at=stale,
    )
    session.add(rec)
    session.commit()
    return tid


@pytest.mark.asyncio
async def test_reverse_sweep_reenqueue_uses_qualified_fn_path(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Issue #98 regression: the sweep must call
    ``arq_pool.enqueue_job(rec.fn_path, ...)`` with the fully-qualified
    registry key, not the bare tail.

    Before the fix, ``fn_short = rec.fn_path.rsplit(".", 1)[-1]`` was
    passed as the ARQ function name. ARQ's function map is keyed on the
    qualified ``{fn.__module__}.{fn.__qualname__}`` string (see
    ``_Registry.all_functions`` in ``aila.platform.tasks.template``), so
    the bare tail never resolved and the re-enqueue silently failed --
    leaving the workflow cursor resumable forever with no worker pickup
    (the visible-stall symptom on investigation runs).
    """
    monkeypatch.setenv(
        "AILA_PLATFORM_REDIS_URL", "redis://127.0.0.1:6379/15",
    )

    # The fully-qualified path chosen to expose the bug: the trailing
    # segment ``run_investigation_turn`` collides with hypothetical
    # namesakes across modules, exactly the CLAUDE.md #19 hazard that
    # motivated ARQ's qualified-name registry. Enqueuing by the bare
    # tail would route this fresh job id to whichever
    # ``run_investigation_turn`` ARQ resolved last.
    fn_path = "aila.modules.vulnerability.workflow.run_investigation_turn"

    fake_arq_pool = MagicMock()
    fake_arq_pool.enqueue_job = AsyncMock()
    fake_arq_pool.close = AsyncMock()

    with sqlite_db_env(tmp_path, "orphan_reenq") as (engine, _):
        with Session(engine) as s:
            task_id = _insert_stale_running(s, fn_path=fn_path)

        # Force the D-86 resumable-workflow branch: the sweep looks up
        # workflow_state_cursor via a raw ``text(...)`` query that the
        # SQLite failsafe schema doesn't carry (only TaskRecord is
        # created). Patching at the callsite keeps the test hermetic
        # and locked to the branch this regression covers.
        with patch(
            "aila.platform.tasks.worker._workflow_cursor_is_resumable",
            new=AsyncMock(return_value=True),
        ), patch(
            "aila.platform.tasks.worker.aioredis.Redis.from_url",
            return_value=_fake_redis_client(),
        ), patch(
            "arq.create_pool",
            new=AsyncMock(return_value=fake_arq_pool),
        ), patch(
            "aila.platform.services.resilience."
            "get_default_resilience_layer",
        ) as resil:
            resil.return_value.emit_recovery_event = AsyncMock()
            await worker_mod._sweep_orphan_running_tasks(grace_seconds=30)

    # Primary assertion: ARQ enqueue was addressed by the FULL fn_path.
    # A regression that reintroduces the ``rsplit(".", 1)[-1]`` derivation
    # would fail this line -- the positional arg would be the bare
    # ``run_investigation_turn`` tail, missing the module prefix ARQ
    # keys on.
    fake_arq_pool.enqueue_job.assert_awaited_once()
    call = fake_arq_pool.enqueue_job.await_args
    assert call.args == (fn_path,), (
        "reverse-sweep re-enqueue must address ARQ by the fully-qualified "
        "fn_path (matching _Registry.all_functions), NOT the "
        "rsplit('.', 1)[-1] tail; got positional args "
        f"{call.args!r} expected {(fn_path,)!r}."
    )
    assert call.kwargs["_queue_name"] == ARQ_QUEUE_KEY_TEMPLATE.format(
        track="vulnerability",
    )
    # A fresh UUID job id, distinct from the reaped row's task id: the
    # sweep issues a NEW ARQ job that will pick up the same workflow
    # cursor, rather than trying to re-drive the abandoned one.
    assert call.kwargs["_job_id"] != task_id
    assert call.kwargs["target_id"] == "abc123"
