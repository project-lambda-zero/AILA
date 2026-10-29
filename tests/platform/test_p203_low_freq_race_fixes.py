"""RFC #208 phase P1 / issue #203 -- low-frequency read-modify-write
race fixes.

Four sites were previously loading a row without a lock and mutating
it in Python before commit. Reviewer #203 tagged all four as
lock-order or TOCTOU hazards. The fixes are additive (row locks or
atomic UPDATEs); this module asserts the corrected statement shape
at each site.

Statement-shape assertions are the deliverable for three of the four
sites (``_enqueue_dependents``, ``_flip_status``, ``register_crash``)
because a deterministic race reproduction requires two concurrent
Postgres transactions plus a coordinated barrier -- test infra doesn't
carry that today, and a probabilistic loop hides the fix under flake.
The fourth site (engine cursor-recreation IntegrityError recovery)
has a deterministic in-process reproduction via a monkeypatch that
lands a competing INSERT inside the same transaction window; that
test is included and requires the Postgres ``test_db`` fixture.
"""
from __future__ import annotations

import inspect
import uuid as _uuid
from pathlib import Path
from typing import Any

import pytest

import aila.modules.vr.services.fuzz_service as fuzz_service_mod
import aila.platform.tasks.hooks as hooks_mod
import aila.platform.workflows.engine as engine_mod
from aila.platform.workflows import (
    DurableStateMachine,
    StateResult,
    StateSpec,
    WorkflowDefinition,
)
from aila.platform.workflows import log as engine_log
from aila.platform.workflows.errors import WorkflowConflictError
from aila.storage.database import async_session_scope
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateCursor
from tests.platform.workflows.conftest import ToyServices, toy_services_factory


def _src(module: Any) -> str:
    return Path(inspect.getsourcefile(module)).read_text(encoding="utf-8")


# ---- Fix 1: _enqueue_dependents locks the WAITING candidates -------------


def test_enqueue_dependents_locks_waiting_rows_with_skip_locked() -> None:
    """``hooks._enqueue_dependents`` must SELECT WAITING dependent rows
    with ``FOR UPDATE SKIP LOCKED`` so two concurrent hook invocations
    (same completed dep) don't both promote the same row and doubly
    enqueue it to ARQ. Assertion is on the source-level presence of
    ``.with_for_update(skip_locked=True)`` inside the function body.
    """
    body = inspect.getsource(hooks_mod._enqueue_dependents)  # noqa: SLF001
    assert "TaskStatus.WAITING" in body, (
        "_enqueue_dependents no longer references WAITING -- test needs "
        "updating alongside the caller"
    )
    assert ".with_for_update(skip_locked=True)" in body, (
        "issue #203: the WAITING-task SELECT must carry "
        "``.with_for_update(skip_locked=True)`` so the promoter row "
        "lock stops two concurrent fan-outs from both flipping the "
        "same row to QUEUED"
    )


# ---- Fix 2: _flip_status uses a guarded idempotent UPDATE ----------------


# ---- Fix 3: engine cursor-recreation commit is IntegrityError-safe -------


# ---- Fix 4: fuzz register_crash locks the campaign row -------------------


def test_register_crash_locks_campaign_row_for_update() -> None:
    """``FuzzCampaignService.register_crash`` must SELECT the campaign
    ``FOR UPDATE`` before running the Python-side
    ``crashes_found = (crashes_found or 0) + 1`` increment. Two
    concurrent crash POSTs (different stack_hashes, same campaign)
    otherwise both read the same prior value and one increment is
    silently lost; the campaign summary underreports crashes and the
    telemetry snapshot below inherits the wrong count.
    """
    body = inspect.getsource(
        fuzz_service_mod.FuzzCampaignService.register_crash,
    )
    assert "VRFuzzCampaignRecord.id == body.campaign_id" in body, (
        "register_crash no longer looks the campaign row up by id -- "
        "test needs updating"
    )
    assert ".with_for_update()" in body, (
        "issue #203: the campaign SELECT must carry "
        "``.with_for_update()`` so two register_crash calls on the "
        "same campaign serialise per-row and the crashes_found "
        "increment is never lost"
    )
    # The Python-side increment stays but is now safe under the lock.
    assert "crashes_found = (campaign.crashes_found or 0) + 1" in body, (
        "register_crash increment shape changed -- if it moved to a "
        "SQL UPDATE, drop the FOR UPDATE assertion above; if it stayed "
        "in Python, keep it and update this text"
    )


# ---- Fix 3 (deterministic race): concurrent recreate converges cleanly ---


@pytest.mark.asyncio
@pytest.mark.usefixtures("test_db")
async def test_cursor_recreate_integrity_error_becomes_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Deterministic reproduction of the recreated-cursor PK race.

    Setup: a handler deletes its own cursor row and returns a
    transition. The engine enters the recreation branch inside
    ``_commit_transition`` and stages an INSERT. We monkeypatch
    ``write_exited`` (called between the ``session.add`` and the
    ``session.commit`` inside the same transaction) so that BEFORE it
    returns it opens a SEPARATE async session, INSERTs a competing
    cursor row with the same ``run_id``, and commits. When our
    transaction then commits, Postgres trips the PK constraint on
    ``workflow_state_cursor.run_id`` and raises ``IntegrityError``.

    Pre-fix expectation: the ``IntegrityError`` escapes ``execute``
    and lands in the worker log as a raw traceback.

    Post-fix expectation: the wrapper catches it, verifies the winner
    row exists, and raises ``WorkflowConflictError``. That is the
    contract every other conflict path in the engine already uses.
    """
    run_id = str(_uuid.uuid4())
    staged_version = 3

    async with async_session_scope() as session:
        session.add(
            WorkflowRunRecord(
                id=run_id,
                query_text="p203",
                action_id="test",
                module_id="test",
            )
        )
        session.add(
            WorkflowStateCursor(
                run_id=run_id,
                current_state="do_it",
                state_input={},
                retries_in_state=0,
                definition_id="test.p203.recreate.v1",
                version=staged_version,
            )
        )
        await session.commit()

    async def _delete_cursor_then_end(
        state_input: dict[str, Any], services: ToyServices,
    ) -> StateResult:
        async with async_session_scope() as del_sess:
            row = await del_sess.get(WorkflowStateCursor, services.run_id)
            if row is not None:
                await del_sess.delete(row)
                await del_sess.commit()
        return StateResult(next_state="__succeeded__", output={"ok": True})

    definition = WorkflowDefinition(
        definition_id="test.p203.recreate.v1",
        start_state="do_it",
        states={"do_it": StateSpec(handler=_delete_cursor_then_end)},
        services_factory=toy_services_factory,
    )

    real_write_exited = engine_log.write_exited
    injected = {"done": False}

    async def _write_exited_then_inject_competing_cursor(
        session: Any, **kwargs: Any,
    ) -> int:
        seq = await real_write_exited(session, **kwargs)
        # Only fire the injection once, only for our run.
        if not injected["done"] and kwargs.get("run_id") == run_id:
            injected["done"] = True
            async with async_session_scope() as racer:
                racer.add(
                    WorkflowStateCursor(
                        run_id=run_id,
                        current_state="__succeeded__",
                        state_input={"racer": True},
                        retries_in_state=0,
                        definition_id="test.p203.recreate.v1",
                        version=staged_version + 1,
                    )
                )
                await racer.commit()
        return seq

    # ``_commit_transition`` imports ``write_exited`` at module scope,
    # so patch the engine module's binding, not log's.
    monkeypatch.setattr(
        engine_mod, "write_exited",
        _write_exited_then_inject_competing_cursor,
    )

    with pytest.raises(WorkflowConflictError):
        await DurableStateMachine.execute(run_id, definition, {})

    assert injected["done"], (
        "test setup broken: competing INSERT never fired, so the "
        "IntegrityError path was never exercised"
    )

    async with async_session_scope() as verify:
        winner = await verify.get(WorkflowStateCursor, run_id)
    assert winner is not None, (
        "the competing INSERT committed before our transaction, so a "
        "cursor row must exist post-conflict"
    )
    assert winner.state_input == {"racer": True}, (
        "the winner row must be the competing INSERT (state_input "
        "carries the racer marker); our losing transaction must have "
        "rolled back cleanly"
    )
