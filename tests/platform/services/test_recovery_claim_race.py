"""Issue #121 -- stall_recovery + stuck_healer mutual exclusion.

Both sweeps' eligibility clauses overlap on the shape
``status=running, past idle grace, no live task, no resumable cursor``,
so an investigation matching that shape used to be re-enqueued twice
in one cron tick: once by ``stall_recovery`` (direct ``submit_fn`` with
``bypass_dedup=True``) and once by ``stuck_healer`` (via
``reenqueue_investigation``). This test pins the atomic-claim contract
introduced by :mod:`aila.platform.services.recovery_claim`: two
concurrent sweep calls submit the same investigation AT MOST ONCE.

Scenario:

  * seed one investigation matching both sweeps' eligibility;
  * mock the downstream submitters so the assertions inspect exactly
    which sweep won (a real ARQ submit would race the taskrecord
    dedup itself);
  * fire ``sweep_stalled_investigations`` and
    ``sweep_stuck_investigations`` under ``asyncio.gather`` so the
    Postgres transaction pool sees both racers;
  * assert the sum of ``stall_recovery`` submits + ``stuck_healer``
    re-enqueue calls == 1.

Also asserts the primitive itself: two direct
:func:`try_claim_recovery` calls with the same seen_ts converge on
exactly one winner (a race that does not involve the surrounding
sweep loop).
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

import pytest
from sqlalchemy import text as _sql_text

from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.services import stuck_healer as _sh_mod
from aila.platform.services.recovery_claim import try_claim_recovery
from aila.platform.services.stall_recovery import (
    sweep_stalled_investigations,
)
from aila.platform.services.stuck_healer import sweep_stuck_investigations
from aila.platform.uow import UnitOfWork

# ---------------------------------------------------------------------------
# Test-local seeders
# ---------------------------------------------------------------------------


async def _seed_target(slug: str) -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"rc-{slug}", slug=f"rc-{slug}",
            description="", theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name=f"rc {slug}", kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/x.apk"}),  # noqa: S108
            primary_language=None, secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


async def _seed_stuck_running_inv(target_id: str) -> tuple[str, datetime]:
    """Seed one RUNNING investigation eligible for BOTH sweeps.

    Back-dates ``updated_at`` by 30 minutes so the default 15-minute
    idle threshold (stall_recovery) and the 600-second idle grace
    (stuck_healer) both accept it. Returns the id and the exact
    ``updated_at`` value observed after the back-date so the direct
    claim-primitive test can compare against a real timestamp.
    """
    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=target_id, team_id="admin",
            kind="audit", title="rc race", initial_question="test",
            status="running", pause_reason=None,
            auto_pilot=False,
            strategy_family="vulnerability_research.audit",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.commit()
        await uow.session.refresh(inv)
        await uow.session.exec(
            _sql_text(
                "UPDATE vr_investigations "
                "SET updated_at = NOW() - INTERVAL '30 minutes' "
                "WHERE id = :id",
            ).bindparams(id=inv.id),
        )
        await uow.session.commit()
        row = (await uow.session.exec(
            _sql_text(
                "SELECT updated_at FROM vr_investigations WHERE id = :id",
            ).bindparams(id=inv.id),
        )).first()
        seen = row[0] if row is not None else None
        assert seen is not None
        return inv.id, seen


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_try_claim_recovery_only_one_winner() -> None:
    """The compare-and-set primitive lets exactly one racer win.

    N concurrent claims against the same (inv_id, seen_ts) tuple
    produce exactly ONE ``True`` return; every other racer's UPDATE
    matches zero rows and returns ``False``. This is the invariant
    the two-sweep race relies on.
    """
    target = await _seed_target("prim")
    inv_id, seen_ts = await _seed_stuck_running_inv(target)

    async def _claim() -> bool:
        return await try_claim_recovery(
            inv_table="vr_investigations",
            timestamp_column="updated_at",
            inv_id=inv_id,
            seen_timestamp=seen_ts,
        )

    results = await asyncio.gather(*[_claim() for _ in range(8)])
    winners = [r for r in results if r]
    assert len(winners) == 1, (
        f"exactly one claim must win, got {len(winners)} "
        f"(results={results!r})"
    )


@pytest.mark.usefixtures("test_db")
async def test_stall_recovery_and_stuck_healer_double_submit_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two concurrent sweeps submit the same investigation AT MOST once.

    Before issue #121, both sweeps matched the same
    ``status=running, no live task, no cursor, past idle`` fixture and
    each fired its own submit path (``submit_fn`` +
    ``reenqueue_investigation``) with no cross-sweep guard. The atomic
    claim on ``updated_at`` collapses the race: whichever sweep wins
    the compare-and-set proceeds; the other observes the bumped
    timestamp and skips.
    """
    target = await _seed_target("race")
    inv_id, _seen = await _seed_stuck_running_inv(target)

    # Capture the two submit paths.
    stall_calls: list[tuple[str, str, str | None, str | None]] = []
    stuck_calls: list[str] = []

    async def _capture_submit(
        inv_kind: str,
        inv_id_: str,
        branch_id: str | None,
        team_id: str | None,
    ) -> None:
        stall_calls.append((inv_kind, inv_id_, branch_id, team_id))

    async def _capture_reenqueue(
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
        stuck_calls.append(investigation_id)
        return {
            "submitted": 1,
            "cancelled_stale_tasks": 0,
            "wiped_crashed_cursors": 0,
            "investigation_id": investigation_id,
        }

    monkeypatch.setattr(_sh_mod, "reenqueue_investigation", _capture_reenqueue)

    async def _noop_submit_one(_inv_id: str, _branch_id: str | None) -> None:
        return None

    stall_task = sweep_stalled_investigations(
        submit_fn=_capture_submit,
        sweepable_kinds=("audit", "discovery", "variant_hunt", "triage", "n_day"),
        single_submit_kinds=("n_day",),
        env_prefix="AILA_VR_STALL_RECOVERY",
        investigations_table="vr_investigations",
        branches_table="vr_investigation_branches",
        idle_minutes=15,
        rate_per_tick=6,
    )
    stuck_task = sweep_stuck_investigations(
        inv_model=VRInvestigationRecord,
        running_status_values=("running",),
        fn_path_pattern="%run_vr_investigate%",
        module_id="vr",
        submit_one=_noop_submit_one,
        branch_model=None,
        branch_status_active=None,
        idle_grace_s=600,
        max_heals_per_tick=10,
    )

    # Fire both under asyncio.gather so the underlying asyncpg
    # connections interleave. The atomic claim MUST collapse the race.
    stall_result, _stuck_result = await asyncio.gather(stall_task, stuck_task)

    stall_submits_for_inv = [c for c in stall_calls if c[1] == inv_id]
    stuck_submits_for_inv = [c for c in stuck_calls if c == inv_id]
    total_submits = len(stall_submits_for_inv) + len(stuck_submits_for_inv)

    assert total_submits == 1, (
        "issue #121 regression: two concurrent recovery sweeps must "
        "submit the eligible investigation AT MOST ONCE "
        f"(stall={len(stall_submits_for_inv)} "
        f"stuck={len(stuck_submits_for_inv)} "
        f"stall_calls={stall_calls!r} stuck_calls={stuck_calls!r})"
    )
    # Sanity: the stall sweep still recorded the row as examined even
    # if it lost the claim -- ``examined`` counts SELECT matches, not
    # submits.
    assert stall_result.examined >= 1


@pytest.mark.usefixtures("test_db")
async def test_stall_recovery_stalled_flip_is_the_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stalled row's ``status=stalled->running`` UPDATE is the claim.

    Two concurrent stall-recovery sweeps against the same stalled
    investigation must flip it exactly once; the loser observes
    ``rowcount == 0`` on its atomic UPDATE and skips its submit.
    """
    target = await _seed_target("stalled")

    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=target, team_id="admin",
            kind="audit", title="rc stalled", initial_question="test",
            status="stalled", pause_reason=None,
            auto_pilot=False,
            strategy_family="vulnerability_research.audit",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.commit()
        await uow.session.refresh(inv)
        inv_id = inv.id
        # Stalled rows bypass the idle threshold, but back-date anyway
        # so this test does not depend on wall-clock resolution.
        await uow.session.exec(
            _sql_text(
                "UPDATE vr_investigations "
                "SET updated_at = NOW() - INTERVAL '30 minutes' "
                "WHERE id = :id",
            ).bindparams(id=inv_id),
        )
        await uow.session.commit()

    submits: list[tuple[str, str, str | None, str | None]] = []

    async def _capture_submit(
        inv_kind: str,
        inv_id_: str,
        branch_id: str | None,
        team_id: str | None,
    ) -> None:
        submits.append((inv_kind, inv_id_, branch_id, team_id))

    async def _run() -> Any:
        return await sweep_stalled_investigations(
            submit_fn=_capture_submit,
            sweepable_kinds=("audit",),
            single_submit_kinds=(),
            env_prefix="AILA_VR_STALL_RECOVERY",
            investigations_table="vr_investigations",
            branches_table="vr_investigation_branches",
            idle_minutes=15,
            rate_per_tick=6,
        )

    await asyncio.gather(_run(), _run())

    for_inv = [s for s in submits if s[1] == inv_id]
    assert len(for_inv) == 1, (
        "the stalled->running flip must claim the row exactly once "
        f"across concurrent sweeps (submits={submits!r})"
    )
