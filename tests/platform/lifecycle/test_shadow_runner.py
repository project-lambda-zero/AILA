"""Tests for the RFC-10 shadow runner (G2) + canary-hold alert (G3).

Covers the two acceptance criteria in the shadow-runner slice:

1. ``run_shadow`` verifies the ACTIVE shadow assignment for (key,
   version), samples recent recorded turns, replays each through
   :meth:`EvalRunner.replay` under a deterministic fake
   :class:`ReplayLLMClient`, and persists a :class:`ShadowReportRecord`
   with ``sample_succeeded >= 1`` when a seeded transcript is present.
   A tuple whose transcript reconstruction raises
   :class:`TranscriptAssemblyError` is SKIPPED (increments
   ``sample_attempted`` without ``sample_succeeded``), and the run
   continues so a single broken sample never aborts the whole report.
   Missing shadow assignment raises :class:`StageTransitionError`.

2. ``record_canary_signal`` on a drift or cost breach flips the active
   canary to HELD and ALSO calls the RFC-07 resilience layer's
   ``record_signal(op='canary_hold', source='lifecycle')`` so the
   operator dashboard's alert counter surfaces the hold. Verified via
   a spy monkeypatched onto ``ResilienceLayer.record_signal``; the
   spy fires exactly once with the expected op/source labels, and
   the assignment row is confirmed HELD in the same test.

Importing :class:`ShadowReportRecord` at module scope registers
``lifecycle_shadow_reports`` on ``SQLModel.metadata`` so the shared
``test_db`` fixture's ``create_all`` builds it. The shadow row +
assignment row are seeded directly (no evaluate gate) to keep each
test independent of the eval-runner surface.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.platform.contracts import utc_now
from aila.platform.eval.runner import EvalRunner
from aila.platform.lifecycle.assignments import (
    AssignmentKind,
    AssignmentState,
    LifecycleCanaryAssignment,
)
from aila.platform.lifecycle.controller import (
    AgentLifecycleController,
    StageTransitionError,
)
from aila.platform.lifecycle.models import (
    LifecycleStage,
    LifecycleTransitionRecord,
)
from aila.platform.lifecycle.shadow import ShadowReportRecord, run_shadow
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.llm.idempotency_cache import LLMIdempotencyCache
from aila.platform.prompts.version_store import PromptVersionStore
from aila.platform.services import resilience as _resilience_module
from aila.storage.database import async_session_scope


class _FakeReplayClient:
    """Deterministic replay client: every ``replay_decide`` returns ``decision``.

    Byte-identical responses across the two candidate replays yield a
    determinism score of 1.0. When ``decision`` matches the recorded
    decision seeded into the idempotency cache, the faithfulness pass
    (which uses the ORIGINAL prompt but the SAME fake client here)
    also scores 1.0 -- exactly the shape a well-behaved candidate
    should produce and a clean signal for the aggregate assertions.
    """

    def __init__(self, decision: dict[str, Any]) -> None:
        self.decision = decision
        self.calls = 0

    async def replay_decide(
        self,
        *,
        prompt_key: str,
        prompt_version: str,
        prompt_body: str,
        frozen_inputs: Any,
    ) -> dict[str, Any]:
        del prompt_key, prompt_version, prompt_body, frozen_inputs
        self.calls += 1
        return dict(self.decision)


def _key() -> str:
    """A test-unique lifecycle key using the ``module/task_type`` shape."""
    # task_type suffix drives the run_shadow sampling preference.
    return f"vr/shadow-{uuid4().hex[:8]}"


async def _seed_shadow_assignment(*, key: str, version: str) -> str:
    """Insert one ACTIVE shadow assignment for (key, version); return its id.

    Bypasses the evaluate gate so this test does not depend on the
    eval-runner surface. In production the ``shadow`` controller method
    writes the same row after an eval-gate + assignment-supersede pass.
    """
    row = LifecycleCanaryAssignment(
        key=key,
        kind=AssignmentKind.SHADOW.value,
        version=version,
        cohort_percent=None,
        state=AssignmentState.ACTIVE.value,
        actor="test",
        reason="test seed",
    )
    async with async_session_scope() as session:
        session.add(row)
        await session.commit()
        await session.refresh(row)
    return row.id


async def _seed_active_canary(
    *, key: str, version: str, cohort_percent: int = 25,
) -> str:
    """Insert one ACTIVE canary assignment for (key, version); return its id."""
    row = LifecycleCanaryAssignment(
        key=key,
        kind=AssignmentKind.CANARY.value,
        version=version,
        cohort_percent=cohort_percent,
        state=AssignmentState.ACTIVE.value,
        actor="test",
        reason="test seed",
    )
    async with async_session_scope() as session:
        session.add(row)
        await session.commit()
        await session.refresh(row)
    return row.id


async def _seed_recorded_turn(
    *,
    inv_id: str,
    branch_id: str,
    turn_number: int,
    task_type: str,
    prompt_version: str,
    decision: dict[str, Any],
    created_at: datetime | None = None,
) -> None:
    """Seed one llm_idempotency_cache + one llm_cost_record for a turn.

    ``record_from_history`` requires BOTH rows and reads:
        * the cache row's ``response_json.content`` as the raw
          model-response body (JSON-decoded into the recorded decision);
        * the cost row's ``prompt_version`` + ``task_type`` to attribute
          the transcript to a versioned prompt.
    """
    when = created_at or utc_now()
    cache_response = {
        "content": json.dumps(decision),
        "model": "test-model",
        "finish_reason": "stop",
    }
    async with async_session_scope() as session:
        session.add(LLMIdempotencyCache(
            request_key=uuid4().hex,
            investigation_id=inv_id,
            branch_id=branch_id,
            turn_number=turn_number,
            response_json=json.dumps(cache_response),
            prompt_tokens=10,
            completion_tokens=5,
            cost_usd=0.01,
            created_at=when,
            expires_at=when + timedelta(days=7),
        ))
        session.add(LLMCostRecord(
            run_id="_no_run",
            investigation_id=inv_id,
            branch_id=branch_id,
            turn_number=turn_number,
            prompt_version=prompt_version,
            model_id="test-model",
            task_type=task_type,
            created_at=when,
        ))
        await session.commit()


@pytest.mark.asyncio
async def test_run_shadow_produces_report_with_success_over_seeded_transcript(
    test_db,
) -> None:
    """G2 happy path: one seeded turn -> report with succeeded>=1 and a
    mean_faithfulness == 1.0 under a deterministic fake client."""
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()
    task_type = key.split("/", 1)[1]

    # Two registered versions: one recorded (matches cost_row.prompt_version)
    # and one candidate (the shadow being replayed). The replay harness
    # resolves both bodies via PromptVersionStore, so both MUST exist.
    recorded_version = await store.register(
        key, "RECORDED PROMPT BODY", author="test",
    )
    candidate_version = await store.register(
        key, "CANDIDATE PROMPT BODY", author="test",
    )

    await _seed_shadow_assignment(key=key, version=candidate_version)

    decision = {"verdict": "accept", "confidence": 0.9}
    inv = f"inv-{uuid4().hex[:8]}"
    branch = f"branch-{uuid4().hex[:8]}"
    await _seed_recorded_turn(
        inv_id=inv,
        branch_id=branch,
        turn_number=1,
        task_type=task_type,
        prompt_version=recorded_version,
        decision=decision,
    )

    fake = _FakeReplayClient(decision=decision)
    report = await run_shadow(
        controller=controller,
        key=key,
        version=candidate_version,
        sample_n=1,
        actor="op-test",
        llm_client=fake,
    )

    # The persisted row carries the aggregates.
    assert isinstance(report, ShadowReportRecord)
    assert report.key == key
    assert report.version == candidate_version
    assert report.sample_attempted >= 1
    assert report.sample_succeeded >= 1
    assert report.mean_faithfulness == pytest.approx(1.0)
    assert report.mean_determinism == pytest.approx(1.0)
    assert report.regressions == 0
    # Three replay_decide calls per successful sample: two candidate
    # replays for determinism + one faithful replay under the recorded
    # prompt version. sample_succeeded * 3 is the exact call count.
    assert fake.calls == report.sample_succeeded * 3

    # diff_summary carries the per-sample trail.
    summary = json.loads(report.diff_summary_json)
    assert summary["faithfulness_floor"] == pytest.approx(0.9)
    assert isinstance(summary["attempts"], list)
    assert isinstance(summary["successes"], list)
    assert len(summary["successes"]) == report.sample_succeeded

    # A SHADOW-to-SHADOW journal row was written referencing the report.
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(LifecycleTransitionRecord)
            .where(LifecycleTransitionRecord.key == key)
            .order_by(LifecycleTransitionRecord.created_at.desc())
        )).all()
    journal_ids = [json.loads(r.metrics_snapshot_json or "{}").get(
        "shadow_report_id"
    ) for r in rows]
    assert report.id in journal_ids


@pytest.mark.asyncio
async def test_run_shadow_skips_transcript_assembly_failures(test_db) -> None:
    """A tuple whose cost record is missing raises TranscriptAssemblyError
    inside record_from_history and MUST be skipped: sample_attempted
    ticks, sample_succeeded does not, and the run persists a report."""
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()
    task_type = key.split("/", 1)[1]
    candidate_version = await store.register(key, "BODY", author="test")
    await _seed_shadow_assignment(key=key, version=candidate_version)

    # Seed a cache row WITHOUT a companion cost record -> assembly raises.
    inv_bad = f"inv-{uuid4().hex[:8]}"
    branch_bad = f"branch-{uuid4().hex[:8]}"
    when_bad = utc_now()
    async with async_session_scope() as session:
        session.add(LLMIdempotencyCache(
            request_key=uuid4().hex,
            investigation_id=inv_bad,
            branch_id=branch_bad,
            turn_number=1,
            response_json=json.dumps({
                "content": json.dumps({"decision": "x"}),
            }),
            created_at=when_bad,
            expires_at=when_bad + timedelta(days=7),
        ))
        await session.commit()

    fake = _FakeReplayClient(decision={"decision": "x"})
    report = await run_shadow(
        controller=controller,
        key=key,
        version=candidate_version,
        sample_n=1,
        llm_client=fake,
    )

    # Attempted the bad tuple, skipped it, produced a report with zero
    # successes -- the run did not abort.
    assert report.sample_attempted >= 1
    assert report.sample_succeeded == 0
    assert report.mean_faithfulness == pytest.approx(0.0)
    assert report.regressions == 0
    del task_type  # unused; documented for readers of the seed

    summary = json.loads(report.diff_summary_json)
    skipped = [a for a in summary["attempts"] if a["status"] == "skipped"]
    assert skipped, "the assembly-error tuple must appear in attempts as skipped"
    assert any(a["stage"] == "assemble" for a in skipped)


@pytest.mark.asyncio
async def test_run_shadow_without_active_shadow_raises(test_db) -> None:
    """No ACTIVE shadow assignment for (key, version) -> StageTransitionError
    and NO report row written."""
    del test_db
    store = PromptVersionStore()
    controller = AgentLifecycleController(
        eval_runner=EvalRunner(store), version_store=store,
    )
    key = _key()
    version = await store.register(key, "BODY", author="test")

    with pytest.raises(StageTransitionError) as excinfo:
        await run_shadow(
            controller=controller,
            key=key,
            version=version,
            sample_n=1,
            llm_client=_FakeReplayClient(decision={}),
        )
    assert "no ACTIVE shadow assignment" in str(excinfo.value)

    async with async_session_scope() as session:
        rows = (await session.exec(
            select(ShadowReportRecord)
            .where(ShadowReportRecord.key == key)
        )).all()
    assert rows == []


@pytest.mark.asyncio
async def test_record_canary_signal_breach_fires_resilience_alert(
    test_db, monkeypatch,
) -> None:
    """G3: a drift breach both flips the canary to HELD AND emits an
    operator-facing resilience signal (spy proves the call landed)."""
    del test_db
    # Force a low drift ceiling so 0.9 breaches.
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_DRIFT_CEILING", "0.2")
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_COST_CEILING_USD", "10.0")

    # Spy the ResilienceLayer.record_signal so we can assert the
    # canary_hold alert reached the operator dashboard path.
    calls: list[dict[str, Any]] = []
    original = _resilience_module.ResilienceLayer.record_signal

    def _spy(
        self: Any,
        *,
        op: str,
        source: str,
        exc: BaseException | None = None,
    ) -> None:
        calls.append({"op": op, "source": source, "exc_type": type(exc).__name__ if exc else None})
        # Preserve original behaviour so any downstream side effects
        # (metric bump, log line) still exercise their real code paths.
        original(self, op=op, source=source, exc=exc)

    monkeypatch.setattr(
        _resilience_module.ResilienceLayer, "record_signal", _spy,
    )

    store = PromptVersionStore()
    controller = AgentLifecycleController(
        eval_runner=EvalRunner(store), version_store=store,
    )
    key = _key()
    version = await store.register(key, "BODY", author="test")
    assignment_id = await _seed_active_canary(
        key=key, version=version, cohort_percent=25,
    )

    outcome = await controller.record_canary_signal(
        key=key, drift=0.9, cost=1.0, actor="canary_monitor",
    )

    # The hold committed: state HELD, transition journaled.
    assert outcome.fired is True
    assert outcome.reason == "held"
    assert outcome.transition is not None
    assert outcome.transition.to_stage == LifecycleStage.HELD.value

    async with async_session_scope() as session:
        row = (await session.exec(
            select(LifecycleCanaryAssignment)
            .where(LifecycleCanaryAssignment.id == assignment_id)
        )).first()
    assert row is not None
    assert row.state == AssignmentState.HELD.value

    # The G3 alert fired: at least one call with op=canary_hold,
    # source=lifecycle landed on the operator dashboard counter.
    canary_hold_calls = [
        c for c in calls
        if c["op"] == "canary_hold" and c["source"] == "lifecycle"
    ]
    assert len(canary_hold_calls) == 1, (
        f"expected exactly one canary_hold operator alert, got: {calls}"
    )


@pytest.mark.asyncio
async def test_record_canary_signal_within_ceilings_does_not_alert(
    test_db, monkeypatch,
) -> None:
    """No breach -> no operator alert fires; only the sample-count bump
    happens on the assignment row and the resilience layer is silent for
    ``canary_hold``. Guards the alert against noisy false positives."""
    del test_db
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_DRIFT_CEILING", "0.5")
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_COST_CEILING_USD", "10.0")

    calls: list[dict[str, Any]] = []
    original = _resilience_module.ResilienceLayer.record_signal

    def _spy(self: Any, *, op: str, source: str, exc: BaseException | None = None) -> None:
        calls.append({"op": op, "source": source})
        original(self, op=op, source=source, exc=exc)

    monkeypatch.setattr(
        _resilience_module.ResilienceLayer, "record_signal", _spy,
    )

    store = PromptVersionStore()
    controller = AgentLifecycleController(
        eval_runner=EvalRunner(store), version_store=store,
    )
    key = _key()
    version = await store.register(key, "BODY", author="test")
    await _seed_active_canary(key=key, version=version)

    outcome = await controller.record_canary_signal(
        key=key, drift=0.1, cost=1.0,
    )
    assert outcome.fired is False
    assert outcome.reason == "within_ceilings"

    # Zero canary_hold alerts -- a within-ceilings sample must not
    # surface the operator alert.
    assert not [c for c in calls if c["op"] == "canary_hold"]
