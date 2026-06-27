"""Stall-recovery sweep -- single comprehensive integration test.

Exercises every eligibility branch + every dispatch branch of
``sweep_stalled_investigations`` against a real Postgres test DB.
The sweep itself is the unit under test; the LLM / task-queue side
is replaced by a mock ``SubmitFn`` so we can assert exactly which
submits would happen, without spawning ARQ jobs.

Test matrix (9 seeded fixtures, one comprehensive assertion phase):

  A: audit / running / 3 active branches / idle / no live task
     → 3 submits (one per active branch, all with branch_id)
  B: variant_hunt / running / 6 active branches / idle / no live task
     → 6 submits (whole fan-out fits in default cap=6)
  C: n_day / running / has branches / idle
     → 1 submit (inv-level, no branch_id -- nday owns branches)
  D: audit / running / 1 active branch / idle / **live task present**
     → 0 submits (skipped -- in-flight task blocks recovery)
  E: audit / paused / pause_reason='operator' / idle
     → 0 submits (paused branches owned by operator)
  F: masvs_audit / running / branches / idle
     → 0 submits (parent_reconciler owns MASVS parents)
  G: audit / running / branches / **just updated** (within idle)
     → 0 submits (idle threshold not reached)
  H: discovery / created / no branches yet / idle
     → 1 submit (inv-level, no branch_id; setup state spawns)
  I: audit / completed / branches / idle
     → 0 submits (terminal status not eligible)

Plus three follow-up assertions on the same fixture set:

  J: with rate_per_tick=2, only 2 of A's branches submit; remaining
     skipped, reported via skipped_rate_cap.
  K: cap=0 short-circuits and returns empty result without examining
     any rows (defensive guard for misconfigured env).
  L: submit_fn raising OSError on every call -> sweep still completes;
     ``enqueued`` stays 0, ``examined`` reflects what we saw.

One test, vigorously assertive, end-to-end.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.services.stall_recovery import (
    sweep_stalled_investigations,
)
from aila.platform.tasks.models import TaskRecord
from aila.platform.uow import UnitOfWork

# ----------------------------------------------------------------------
# Test-local seeders -- kept here so the test file stays self-contained
# ----------------------------------------------------------------------


async def _seed_target(slug: str) -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"sr-{slug}", slug=f"sr-{slug}",
            description="", theme="custom", team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()
        target = VRTargetRecord(
            workspace_id=ws.id, team_id="admin",
            display_name=f"sr {slug}", kind="android_apk",
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
    kind: str = "audit",
    status: str = "running",
    pause_reason: str | None = None,
    idle: bool = True,
) -> str:
    """Seed a VR investigation.

    ``idle=True`` (default) backdates updated_at by 30 minutes so the
    sweep's idle threshold (default 15 min) accepts it. ``idle=False``
    leaves updated_at fresh -- used for fixture G (within-idle skip).
    """
    async with UnitOfWork() as uow:
        inv = VRInvestigationRecord(
            target_id=target_id, team_id="admin",
            kind=kind,
            title=f"sr {kind} {status}",
            initial_question="test",
            status=status,
            pause_reason=pause_reason,
            auto_pilot=False,
            strategy_family=f"vulnerability_research.{kind}",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.commit()
        await uow.session.refresh(inv)
        if idle:
            # Back-date updated_at so the idle threshold accepts it.
            # Done with raw SQL to bypass ORM auto-touching.
            from sqlalchemy import text as _sql_text  # noqa: PLC0415
            await uow.session.exec(
                _sql_text(
                    "UPDATE vr_investigations "
                    "SET updated_at = NOW() - INTERVAL '30 minutes' "
                    "WHERE id = :id",
                ).bindparams(id=inv.id),
            )
            await uow.session.commit()
        return inv.id


async def _seed_branch(
    investigation_id: str,
    *,
    status: str = "active",
    persona_voice: str = "noor",
) -> str:
    async with UnitOfWork() as uow:
        br = VRInvestigationBranchRecord(
            investigation_id=investigation_id,
            status=status,
            persona_voice=persona_voice,
            turn_count=5,
            fork_reason="primary",
        )
        uow.session.add(br)
        await uow.session.commit()
        await uow.session.refresh(br)
        return br.id


async def _seed_live_task(investigation_id: str) -> str:
    """Seed a TaskRecord in status='running' for this investigation.

    Used to test the eligibility filter that blocks re-enqueue while
    a task is in-flight.
    """
    async with UnitOfWork() as uow:
        tr = TaskRecord(
            track="vr",
            fn_path="aila.modules.vr.workflow.task.run_vr_investigate",
            fn_module="vr",
            status="running",
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


class _CaptureSubmit:
    """Mock SubmitFn that records every call instead of enqueueing."""

    def __init__(self, raise_on_call: bool = False) -> None:
        self.calls: list[tuple[str, str, str | None, str | None]] = []
        self._raise = raise_on_call

    async def __call__(
        self,
        inv_kind: str,
        inv_id: str,
        branch_id: str | None,
        team_id: str | None,
    ) -> None:
        if self._raise:
            raise OSError("simulated submit failure")
        self.calls.append((inv_kind, inv_id, branch_id, team_id))


def _by_inv(
    calls: list[tuple[str, str, str | None, str | None]],
) -> dict[str, list[str | None]]:
    """Group submit calls by investigation id, returning branch_ids."""
    out: dict[str, list[str | None]] = {}
    for kind, inv_id, branch_id, team_id in calls:  # noqa: B007
        out.setdefault(inv_id, []).append(branch_id)
    return out


# ----------------------------------------------------------------------
# THE single comprehensive test
# ----------------------------------------------------------------------


@pytest.mark.usefixtures("test_db")
async def test_stall_recovery_full_matrix() -> None:
    """Seed 9 investigations covering every eligibility / dispatch path
    + assert sweep behavior across three rate-cap scenarios."""

    target_id = await _seed_target("matrix")

    # ── A: audit / running / 3 active branches / eligible
    inv_a = await _seed_inv(target_id, kind="audit", status="running")
    a_branches = [
        await _seed_branch(inv_a, status="active", persona_voice="halvar"),
        await _seed_branch(inv_a, status="active", persona_voice="noor"),
        await _seed_branch(inv_a, status="active", persona_voice="maddie"),
    ]
    # one completed branch -- MUST NOT be touched
    await _seed_branch(inv_a, status="completed", persona_voice="renzo")

    # ── B: variant_hunt / running / 6 active branches
    inv_b = await _seed_inv(target_id, kind="variant_hunt", status="running")
    b_branches = [
        await _seed_branch(inv_b, status="active", persona_voice=p)
        for p in ("halvar", "noor", "maddie", "yuki", "renzo", "wei")
    ]

    # ── C: n_day / running / has branches (sweep ignores branches)
    inv_c = await _seed_inv(target_id, kind="n_day", status="running")
    await _seed_branch(inv_c, status="active", persona_voice="halvar")

    # ── D: audit / running / 1 active branch / LIVE TASK present
    inv_d = await _seed_inv(target_id, kind="audit", status="running")
    await _seed_branch(inv_d, status="active", persona_voice="halvar")
    await _seed_live_task(inv_d)  # blocks recovery

    # ── E: audit / paused (operator) / branches
    inv_e = await _seed_inv(
        target_id, kind="audit", status="paused", pause_reason="operator",
    )
    await _seed_branch(inv_e, status="active", persona_voice="halvar")

    # ── F: masvs_audit / running / branches
    inv_f = await _seed_inv(target_id, kind="masvs_audit", status="running")
    await _seed_branch(inv_f, status="active", persona_voice="halvar")

    # ── G: audit / running / branches / WITHIN idle threshold
    inv_g = await _seed_inv(
        target_id, kind="audit", status="running", idle=False,
    )
    await _seed_branch(inv_g, status="active", persona_voice="halvar")

    # ── H: discovery / created / NO BRANCHES (inv-level enqueue)
    inv_h = await _seed_inv(target_id, kind="discovery", status="created")

    # ── I: audit / completed / branches (terminal)
    inv_i = await _seed_inv(target_id, kind="audit", status="completed")
    await _seed_branch(inv_i, status="active", persona_voice="halvar")

    # ─────────────────────────────────────────────────────────────────
    # Scenario 1: high cap (15) -- every eligible fixture should fire
    # ─────────────────────────────────────────────────────────────────
    capture1 = _CaptureSubmit()
    result1 = await sweep_stalled_investigations(
        idle_minutes=15,
        rate_per_tick=15,
        submit_fn=capture1,
    )

    by_inv = _by_inv(capture1.calls)

    # A: 3 active branches → 3 submits (all with branch_id; completed branch absent)
    assert inv_a in by_inv, "fixture A should have been recovered"
    assert sorted(by_inv[inv_a]) == sorted(a_branches), (
        f"A expected branch_ids={sorted(a_branches)!r} "
        f"got={sorted(by_inv[inv_a])!r}"
    )

    # B: 6 active branches → 6 submits
    assert inv_b in by_inv
    assert sorted(by_inv[inv_b]) == sorted(b_branches), (
        f"B expected 6 branches, got {by_inv[inv_b]!r}"
    )

    # C: n_day → 1 submit, branch_id=None (nday body owns branches)
    assert inv_c in by_inv
    assert by_inv[inv_c] == [None], (
        f"C n_day should produce inv-level submit, got {by_inv[inv_c]!r}"
    )

    # D: live task → SKIPPED entirely
    assert inv_d not in by_inv, "D has a live task; must not be re-enqueued"

    # E: paused / operator → SKIPPED entirely
    assert inv_e not in by_inv, "E is operator-paused; must not be re-enqueued"

    # F: masvs_audit kind → SKIPPED (parent_reconciler owns it)
    assert inv_f not in by_inv, "F is masvs_audit; sweep must skip"

    # G: fresh updated_at → SKIPPED (within idle threshold)
    assert inv_g not in by_inv, "G is within idle threshold"

    # H: created with no branches → 1 submit, branch_id=None
    assert inv_h in by_inv
    assert by_inv[inv_h] == [None], (
        f"H expected inv-level submit, got {by_inv[inv_h]!r}"
    )

    # I: completed (terminal) → SKIPPED
    assert inv_i not in by_inv, "I is completed; must not be re-enqueued"

    # Result totals
    # Expected submits: 3 (A) + 6 (B) + 1 (C) + 1 (H) = 11
    assert result1.enqueued == 11, (
        f"expected 11 submits, got {result1.enqueued} "
        f"(by_kind={result1.by_kind_enqueued})"
    )
    assert set(result1.investigations_recovered) == {
        inv_a, inv_b, inv_c, inv_h,
    }
    assert result1.by_kind_enqueued == {
        "audit": 3,        # A: 3 branches
        "variant_hunt": 6, # B: 6 branches
        "n_day": 1,        # C: 1 inv-level
        "discovery": 1,    # H: 1 inv-level
    }
    assert result1.skipped_rate_cap == 0, (
        "high cap should not skip anyone"
    )

    # ─────────────────────────────────────────────────────────────────
    # Scenario 2: tight cap (2) -- partial fan-out mid-fixture
    # ─────────────────────────────────────────────────────────────────
    # The eligibility query sorts by updated_at ASC, oldest first.
    # Fixtures A-C-H-B were all back-dated to NOW-30min in seed order
    # (A → B → C → H), so A wins the first slot. With cap=2, only
    # 2 of A's 3 branches submit; B/C/H remain unswept and contribute
    # to skipped_rate_cap.
    capture2 = _CaptureSubmit()
    result2 = await sweep_stalled_investigations(
        idle_minutes=15,
        rate_per_tick=2,
        submit_fn=capture2,
    )
    assert result2.enqueued == 2, (
        f"cap=2 should produce 2 submits, got {result2.enqueued}"
    )
    # All 2 submits belong to A (or whichever oldest inv wins ordering)
    invs_touched_2 = {inv for _, inv, _, _ in capture2.calls}
    assert len(invs_touched_2) == 1, (
        f"cap=2 mid-fan-out should hit a single inv, got "
        f"{invs_touched_2!r}"
    )
    # Skipped_rate_cap > 0 (remaining eligible rows weren't reached)
    assert result2.skipped_rate_cap > 0, (
        "remaining eligible rows must increment skipped_rate_cap"
    )

    # ─────────────────────────────────────────────────────────────────
    # Scenario 3: cap=0 short-circuits (defensive guard)
    # ─────────────────────────────────────────────────────────────────
    capture3 = _CaptureSubmit()
    result3 = await sweep_stalled_investigations(
        idle_minutes=15,
        rate_per_tick=0,
        submit_fn=capture3,
    )
    assert result3.enqueued == 0
    assert result3.examined == 0, (
        "cap=0 must not even examine eligible rows"
    )
    assert capture3.calls == []

    # ─────────────────────────────────────────────────────────────────
    # Scenario 4: submit_fn raises every time
    # Verifies the sweep doesn't abort on per-submit failures.
    # ─────────────────────────────────────────────────────────────────
    raising = _CaptureSubmit(raise_on_call=True)
    result4 = await sweep_stalled_investigations(
        idle_minutes=15,
        rate_per_tick=15,
        submit_fn=raising,
    )
    # Examined the eligible rows but enqueued nothing (every submit
    # raised, _safe_submit swallowed and didn't increment counters).
    assert result4.examined > 0, (
        "raising submit shouldn't prevent eligibility query from running"
    )
    assert result4.enqueued == 0
    assert result4.by_kind_enqueued == {}
    assert result4.investigations_recovered == []
