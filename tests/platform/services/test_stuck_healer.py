"""RFC-07 #31 criterion 6 -- stuck-investigation healer tests.

Pins the exact eligibility contract the sweep enforces plus the
durable-recovery-event contract the healer honours per honesty rule 54:

* a ``RUNNING`` investigation with NO live task AND NO resumable cursor
  (or only a ``__crashed__`` cursor) whose ``updated_at`` is older than
  the idle grace IS detected, calls ``reenqueue_investigation``, and
  writes a ``kind='recovery'`` ledger entry;
* a ``RUNNING`` investigation WITH a live queued / running / waiting
  ``TaskRecord`` is NOT healed (the task-level sweep owns it);
* a ``RUNNING`` investigation WITH a resumable ``workflow_state_cursor``
  is NOT healed (the state reconciler owns it);
* a ``PAUSED`` / ``CANCELLED`` / ``COMPLETED`` investigation is NEVER
  healed (operator terminals are respected);
* a just-created ``RUNNING`` investigation (fresher than the idle grace)
  is NOT healed.

Every fixture is seeded against the shared ``test_db`` Postgres schema
so the ``UPDATE ... SET updated_at = NOW() - INTERVAL ...`` back-date
paths exercise the same clause the SELECT gates on in production.
``reenqueue_investigation`` and the resilience-layer heal journal are
monkeypatched to record their calls -- the platform sweep itself is the
unit under test, not the downstream re-enqueue mechanics.
"""
from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import text as _sql_text
from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.stuck_healer import (
    sweep_stuck_investigations as _vr_module_sweep,
)
from aila.platform.services import stuck_healer as _sh_mod
from aila.platform.services.ledger import InvestigationLedgerRecord
from aila.platform.services.stuck_healer import sweep_stuck_investigations
from aila.platform.tasks.models import TaskRecord
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import WorkflowRunRecord, WorkflowStateCursor

# ---------------------------------------------------------------------------
# Test-local seeders
# ---------------------------------------------------------------------------


async def _seed_target(slug: str) -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"sh-{slug}", slug=f"sh-{slug}",
            description="", theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name=f"sh {slug}", kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/x.apk"}),  # noqa: S108
            primary_language=None, secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


async def _seed_inv(
    target_id: str,
    *,
    status: str = "running",
    pause_reason: str | None = None,
    idle: bool = True,
    kind: str = "audit",
) -> str:
    """Seed a VR investigation.

    ``idle=True`` back-dates ``updated_at`` by 30 minutes so the sweep's
    default 15-minute idle grace accepts it. ``idle=False`` leaves
    ``updated_at`` fresh so the within-idle skip path fires.
    """
    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=target_id, team_id="admin",
            kind=kind, title=f"sh {kind} {status}", initial_question="test",
            status=status, pause_reason=pause_reason,
            auto_pilot=False,
            strategy_family=f"vulnerability_research.{kind}",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.commit()
        await uow.session.refresh(inv)
        if idle:
            await uow.session.exec(
                _sql_text(
                    "UPDATE vr_investigations "
                    "SET updated_at = NOW() - INTERVAL '30 minutes' "
                    "WHERE id = :id",
                ).bindparams(id=inv.id),
            )
            await uow.session.commit()
        return inv.id


async def _seed_live_task(investigation_id: str, *, status: str = "running") -> str:
    """Seed a TaskRecord in ``status='queued'/'running'/'waiting'``.

    The eligibility SQL blocks re-enqueue as long as any live task
    references the investigation via ``kwargs_json``.
    """
    async with UnitOfWork() as uow:
        tr = TaskRecord(
            track="vr",
            fn_path="aila.modules.vr.workflow.task.run_vr_investigate",
            fn_module="vr",
            status=status,
            user_id="system",
            group_id="vr_test",
            team_id="admin",
            kwargs_json=json.dumps({"investigation_id": investigation_id}),
            depends_on_json=None,
            input_hash=uuid4().hex,
        )
        uow.session.add(tr)
        await uow.session.commit()
        await uow.session.refresh(tr)
        return tr.id


async def _seed_cursor(
    investigation_id: str,
    *,
    current_state: str,
) -> str:
    """Seed a workflow_state_cursor row keyed on ``investigation_id``.

    The stuck healer's eligibility SQL queries cursors by the
    denormalised ``investigation_id`` column, so the run_id can be any
    fresh ARQ-like uuid.
    """
    run_id = f"arq-{uuid4().hex[:12]}"
    async with UnitOfWork() as uow:
        uow.session.add(
            WorkflowRunRecord(
                id=run_id,
                query_text="stuck healer test",
                action_id="vr.investigate",
                module_id="vr",
                status="running",
                team_id="admin",
            )
        )
        await uow.session.flush()
        uow.session.add(
            WorkflowStateCursor(
                run_id=run_id,
                current_state=current_state,
                definition_id="VR_INVESTIGATE_V1",
                state_input={},
                version=0,
                investigation_id=investigation_id,
                branch_id=None,
            )
        )
        await uow.session.commit()
    return run_id


class _CaptureReenqueue:
    """Spy replacing ``reenqueue_investigation`` for the whole sweep call."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def __call__(
        self,
        investigation_id: str,
        *,
        inv_model: type[Any],
        fn_path_pattern: str,
        submit_one: Callable[[str, str | None], Awaitable[None]],
        branch_model: type[Any] | None = None,
        branch_status_active: str | None = None,
        new_kind: str | None = None,
        new_strategy: str | None = None,
    ) -> dict[str, Any]:
        del inv_model, fn_path_pattern, branch_model, branch_status_active
        del new_kind, new_strategy, submit_one  # unused by the spy
        self.calls.append({"investigation_id": investigation_id})
        return {
            "submitted": 1,
            "cancelled_stale_tasks": 0,
            "wiped_crashed_cursors": 0,
            "investigation_id": investigation_id,
        }


async def _noop_submit(inv_id: str, branch_id: str | None) -> None:
    """Sweep's ``submit_one`` is opaque -- the spy short-circuits it."""
    del inv_id, branch_id


async def _read_recovery_events(
    investigation_id: str,
) -> list[dict[str, Any]]:
    """Fetch every ``kind='recovery'`` ledger row for ``investigation_id``."""
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(InvestigationLedgerRecord)
            .where(InvestigationLedgerRecord.investigation_id == investigation_id)
            .where(InvestigationLedgerRecord.kind == "recovery"),
        )).all()
    return [
        {
            "kind": r.kind,
            "payload": json.loads(r.payload_json or "{}"),
        }
        for r in rows
    ]


# ---------------------------------------------------------------------------
# THE single comprehensive test -- one fixture set, one sweep, every branch
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_stuck_healer_full_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    """Seed 8 fixtures covering every eligibility branch + assert.

    Fixtures:
      A: RUNNING, idle, no live task, no cursor            -> healed
      B: RUNNING, idle, no live task, __crashed__ cursor   -> healed
      C: RUNNING, idle, LIVE queued TaskRecord             -> NOT healed
      D: RUNNING, idle, RESUMABLE cursor (investigation_loop) -> NOT healed
      E: PAUSED,  idle, no live task, no cursor            -> NOT healed
      F: CANCELLED, idle, no live task, no cursor          -> NOT healed
      G: COMPLETED, idle, no live task, no cursor          -> NOT healed
      H: RUNNING, FRESH updated_at, no live task, no cursor -> NOT healed

    The single healed fixture A also verifies the durable recovery-event
    journal (RFC-07 #31 honesty rule 54) fires with the expected payload.
    Fixture B verifies a ``__crashed__`` cursor is treated as absent for
    healer purposes (the state reconciler cannot resume from it).
    """
    spy = _CaptureReenqueue()
    monkeypatch.setattr(
        _sh_mod, "reenqueue_investigation", spy,
    )

    target = await _seed_target("matrix")

    # A: bare RUNNING zombie -- healed
    inv_a = await _seed_inv(target, status="running")

    # B: RUNNING with only a __crashed__ cursor -- healed (crashed is
    # not resumable)
    inv_b = await _seed_inv(target, status="running")
    await _seed_cursor(inv_b, current_state="__crashed__")

    # C: RUNNING with a live queued task -- task-level sweep owns it
    inv_c = await _seed_inv(target, status="running")
    await _seed_live_task(inv_c, status="queued")

    # D: RUNNING with a resumable cursor -- state reconciler owns it
    inv_d = await _seed_inv(target, status="running")
    await _seed_cursor(inv_d, current_state="investigation_loop")

    # E: PAUSED -- operator terminal, never touched
    inv_e = await _seed_inv(
        target, status="paused", pause_reason="operator",
    )

    # F: CANCELLED -- operator terminal, never touched
    inv_f = await _seed_inv(target, status="cancelled")

    # G: COMPLETED -- terminal, never touched
    inv_g = await _seed_inv(target, status="completed")

    # H: RUNNING fresh -- within idle grace, never touched
    inv_h = await _seed_inv(target, status="running", idle=False)

    report = await sweep_stuck_investigations(
        inv_model=VRInvestigationRecord,
        running_status_values=("running",),
        fn_path_pattern="%run_vr_investigate%",
        module_id="vr",
        submit_one=_noop_submit,
        branch_model=None,
        branch_status_active=None,
        # Explicit knobs so the test never depends on operator config.
        idle_grace_s=600,
        max_heals_per_tick=10,
    )

    healed_ids = {call["investigation_id"] for call in spy.calls}
    assert healed_ids == {inv_a, inv_b}, (
        f"only bare-RUNNING + __crashed__-cursor rows should heal; "
        f"got={sorted(healed_ids)!r}"
    )
    assert set(report["ids"]) == {inv_a, inv_b}
    assert report["healed"] == 2
    assert report["examined"] == 2

    # Explicit non-heal assertions -- guard against a future change that
    # widens eligibility.
    for skipped in (inv_c, inv_d, inv_e, inv_f, inv_g, inv_h):
        assert skipped not in healed_ids, (
            f"inv {skipped!r} should not have been healed"
        )

    # Recovery-event journal fires per healed id (rule 54).
    for inv_id in (inv_a, inv_b):
        events = await _read_recovery_events(inv_id)
        assert len(events) == 1, (
            f"expected exactly one recovery event for inv={inv_id!r}, "
            f"got {events!r}"
        )
        payload = events[0]["payload"]
        assert payload["action"] == "stuck_reenqueue"
        assert payload["source"] == "stuck_healer"
        detail = payload["detail"]
        assert detail["module_id"] == "vr"
        assert detail["reason"] == "running_no_task_no_cursor"

    # Nothing journaled for the skipped ids.
    for inv_id in (inv_c, inv_d, inv_e, inv_f, inv_g, inv_h):
        assert await _read_recovery_events(inv_id) == [], (
            f"skipped inv {inv_id!r} must not carry a recovery event"
        )


@pytest.mark.usefixtures("test_db")
async def test_stuck_healer_per_id_failure_isolates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A per-id ``reenqueue_investigation`` failure logs and continues.

    Two stuck-eligible rows. The spy raises OSError on the first and
    succeeds on the second. The sweep must:

    * heal the second row despite the first raising;
    * NOT journal a recovery event for the failed id (the heal never
      completed, so no audit row is written);
    * report ``examined=2 healed=1 ids=[<second>]``.
    """

    async def _raising_reenqueue(
        investigation_id: str,
        *,
        inv_model: type[Any],
        fn_path_pattern: str,
        submit_one: Callable[[str, str | None], Awaitable[None]],
        branch_model: type[Any] | None = None,
        branch_status_active: str | None = None,
        new_kind: str | None = None,
        new_strategy: str | None = None,
    ) -> dict[str, Any]:
        del inv_model, fn_path_pattern, submit_one
        del branch_model, branch_status_active, new_kind, new_strategy
        if investigation_id == _failed_id:
            raise OSError("simulated re-enqueue failure")
        return {
            "submitted": 1,
            "cancelled_stale_tasks": 0,
            "wiped_crashed_cursors": 0,
            "investigation_id": investigation_id,
        }

    monkeypatch.setattr(
        _sh_mod, "reenqueue_investigation", _raising_reenqueue,
    )

    target = await _seed_target("isolate")
    # Seed order pins the ORDER BY updated_at ASC: the earlier back-date
    # wins the first slot.
    _failed_id = await _seed_inv(target, status="running")
    survivor_id = await _seed_inv(target, status="running")

    report = await sweep_stuck_investigations(
        inv_model=VRInvestigationRecord,
        running_status_values=("running",),
        fn_path_pattern="%run_vr_investigate%",
        module_id="vr",
        submit_one=_noop_submit,
        idle_grace_s=600,
        max_heals_per_tick=10,
    )

    assert report["examined"] == 2
    assert report["healed"] == 1
    assert report["ids"] == [survivor_id]

    # Only the survivor was journaled; the failed id must not carry
    # a recovery event (rule 54 -- no heal, no audit row).
    assert len(await _read_recovery_events(survivor_id)) == 1
    assert await _read_recovery_events(_failed_id) == []


@pytest.mark.usefixtures("test_db")
async def test_stuck_healer_module_partial_smoke() -> None:
    """The VR module-level ``partial`` is registered as a no-arg sweep.

    Confirms the module binding presents the platform generic as the
    zero-argument ``PeriodicSweep`` callable the reaper cron iterates
    (:mod:`aila.platform.tasks.sweeps`). No DB rows exist yet so the
    sweep short-circuits on the empty SELECT and returns an empty
    report -- the assertion here is that the partial closes over the
    binding args without raising.
    """
    report = await _vr_module_sweep(
        # Explicit config knobs so the test never depends on the shared
        # ConfigRegistry / DB config table state.
        idle_grace_s=600, max_heals_per_tick=5,
    )
    assert report == {"examined": 0, "healed": 0, "ids": []}
