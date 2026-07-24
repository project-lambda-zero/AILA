"""Tests for the RFC-10 shadow + canary + hold routing.

Covers the RFC-10 acceptance scenarios remaining after evaluate /
approve / promote / rollback shipped in a prior increment:

1. ``shadow`` requires a prior passing evaluate; on success supersedes
   any prior active shadow row for the key and journals an evaluated ->
   shadow transition. ``active_shadow(key)`` resolves the winner.
2. ``canary`` requires the same (key, version) pair to be the current
   active shadow AND cohort_percent to sit in [1, 100]. On success
   supersedes prior active canary rows and journals a shadow -> canary
   transition. ``active_canary(key)`` resolves the winner.
3. ``resolve_version_for_investigation`` is deterministic (same id ->
   same bucket) and splits ~cohort_percent of a large id sample onto
   the canary.
4. ``record_canary_signal`` flips the active canary to held when either
   drift or cost breaches its ceiling; the assignment row's
   ``last_signal_json`` and a canary -> held transition both carry the
   breach payload. A within-ceilings sample stays live. No active
   canary -> fired=False with reason='no_active_canary'.
5. ``promote_from_canary`` still enforces the eval + quorum gate --
   promoting an unapproved canary raises exactly like a cold ``promote``
   and the assignment row stays live.

Importing ``LifecycleTransitionRecord`` + ``LifecycleCanaryAssignment``
at module scope registers both tables on ``SQLModel.metadata`` so the
shared ``test_db`` fixture's ``create_all`` builds them.
"""
from __future__ import annotations

import json
import os
from uuid import uuid4

import pytest

from aila.platform.eval.runner import PRODUCTION_ALIAS, EvalRunner
from aila.platform.lifecycle.assignments import (
    AssignmentKind,
    AssignmentState,
    LifecycleCanaryAssignment,
)
from aila.platform.lifecycle.controller import (
    AgentLifecycleController,
    StageTransitionError,
    _cohort_bucket,
)
from aila.platform.lifecycle.models import (
    LifecycleStage,
    LifecycleTransitionRecord,
)
from aila.platform.prompts.version_store import PromptVersionStore

__all__: list[str] = []


def _key() -> str:
    return f"vr/lifecycle-shadow-{uuid4().hex[:8]}"


def _perfect_cases(version: str, n: int = 8) -> list[dict[str, object]]:
    """Cases matching the truth at high confidence -- eval verdict pass."""
    out: list[dict[str, object]] = []
    for i in range(n):
        kind = "sqli" if i % 2 == 0 else "xss"
        out.append({
            "outcome_kind": kind,
            "predicted_verdict": "accept",
            "verified_verdict": "accept",
            "confidence": 0.95,
            "version": version,
        })
    return out


async def _prepare_evaluated(
    controller: AgentLifecycleController,
    store: PromptVersionStore,
    runner: EvalRunner,
    *,
    key: str,
    body: str = "PROMPT BODY",
) -> str:
    version = await store.register(key, body, author="test")
    bench = await runner.register_benchmark(
        key=key, name="acc-1", cases=_perfect_cases(version), created_by="op",
    )
    await controller.evaluate(
        key=key, version=version, benchmark_id=bench.id, actor="op",
    )
    return version


def _controller() -> tuple[
    AgentLifecycleController, PromptVersionStore, EvalRunner,
]:
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    return controller, store, runner


@pytest.mark.asyncio
async def test_shadow_registers_active_assignment_and_journals(
    test_db,
) -> None:
    """A passing evaluate + shadow leaves exactly one active shadow row
    for the key, and ``active_shadow`` resolves to that row's version."""
    del test_db
    controller, store, runner = _controller()
    key = _key()
    version = await _prepare_evaluated(
        controller, store, runner, key=key,
    )

    transition = await controller.shadow(
        key=key, version=version, actor="op", reason="off-path compare",
    )
    assert transition.from_stage == LifecycleStage.EVALUATED.value
    assert transition.to_stage == LifecycleStage.SHADOW.value
    snapshot = json.loads(transition.metrics_snapshot_json)
    assert snapshot["assignment_kind"] == AssignmentKind.SHADOW.value
    assert snapshot["verdict"] == "pass"

    active = await controller.active_shadow(key)
    assert active is not None
    assert active.version == version
    assert active.state == AssignmentState.ACTIVE.value
    assert active.kind == AssignmentKind.SHADOW.value
    assert active.cohort_percent is None


@pytest.mark.asyncio
async def test_shadow_without_passing_evaluate_raises(test_db) -> None:
    """Shadow on a (key, version) with no passing evaluate row raises
    ``StageTransitionError`` and writes no assignment / journal row."""
    del test_db
    controller, store, _runner = _controller()
    key = _key()
    version = await store.register(key, "PROMPT BODY", author="test")

    with pytest.raises(StageTransitionError) as exc_info:
        await controller.shadow(
            key=key, version=version, actor="op",
        )
    assert "no prior passing 'evaluated'" in str(exc_info.value)

    assert await controller.active_shadow(key) is None
    assert await controller.list_transitions(key) == []


@pytest.mark.asyncio
async def test_shadow_supersedes_prior_active_shadow(test_db) -> None:
    """A second shadow for the same key supersedes the first: exactly
    one active shadow row per key at a time."""
    del test_db
    controller, store, runner = _controller()
    key = _key()
    v1 = await _prepare_evaluated(
        controller, store, runner, key=key, body="BODY-A",
    )
    v2 = await _prepare_evaluated(
        controller, store, runner, key=key, body="BODY-B",
    )
    await controller.shadow(key=key, version=v1, actor="op")
    await controller.shadow(key=key, version=v2, actor="op")

    active = await controller.active_shadow(key)
    assert active is not None
    assert active.version == v2


@pytest.mark.asyncio
async def test_canary_requires_active_shadow_for_same_version(
    test_db,
) -> None:
    """Canary on a candidate that never entered shadow raises; canary
    on a candidate whose shadow was superseded also raises."""
    del test_db
    controller, store, runner = _controller()
    key = _key()
    v1 = await _prepare_evaluated(
        controller, store, runner, key=key, body="BODY-A",
    )
    v2 = await _prepare_evaluated(
        controller, store, runner, key=key, body="BODY-B",
    )

    with pytest.raises(StageTransitionError):
        await controller.canary(
            key=key, version=v1, cohort_percent=10, actor="op",
        )

    await controller.shadow(key=key, version=v1, actor="op")
    await controller.shadow(key=key, version=v2, actor="op")
    with pytest.raises(StageTransitionError):
        await controller.canary(
            key=key, version=v1, cohort_percent=10, actor="op",
        )


@pytest.mark.asyncio
async def test_canary_registers_cohort_and_journals(test_db) -> None:
    """A shadow -> canary flip records a canary assignment with the
    cohort_percent and journals the transition; active_canary reflects
    the new row."""
    del test_db
    controller, store, runner = _controller()
    key = _key()
    version = await _prepare_evaluated(
        controller, store, runner, key=key,
    )
    await controller.shadow(key=key, version=version, actor="op")

    transition = await controller.canary(
        key=key, version=version, cohort_percent=25,
        actor="op", reason="first-cohort",
    )
    assert transition.from_stage == LifecycleStage.SHADOW.value
    assert transition.to_stage == LifecycleStage.CANARY.value
    snapshot = json.loads(transition.metrics_snapshot_json)
    assert snapshot["cohort_percent"] == 25

    active = await controller.active_canary(key)
    assert active is not None
    assert active.version == version
    assert active.cohort_percent == 25
    assert active.state == AssignmentState.ACTIVE.value


@pytest.mark.asyncio
async def test_canary_cohort_percent_bounds(test_db) -> None:
    """cohort_percent must sit in [1, 100]. 0 rejects; 101 rejects."""
    del test_db
    controller, store, runner = _controller()
    key = _key()
    version = await _prepare_evaluated(
        controller, store, runner, key=key,
    )
    await controller.shadow(key=key, version=version, actor="op")

    for bad in (0, 101, -5, 1000):
        with pytest.raises(StageTransitionError):
            await controller.canary(
                key=key, version=version, cohort_percent=bad, actor="op",
            )


@pytest.mark.asyncio
async def test_cohort_bucket_is_deterministic_and_uniform() -> None:
    """The bucket function is a stable SHA-256 mod 100: same id always
    the same bucket, and a large sample spreads roughly uniformly."""
    inv = f"inv-{uuid4()}"
    a = _cohort_bucket(inv)
    b = _cohort_bucket(inv)
    assert a == b
    assert 0 <= a < 100

    counts = [0] * 100
    for i in range(5_000):
        counts[_cohort_bucket(f"inv-{i:08d}")] += 1
    # A uniform distribution over 100 buckets on 5000 samples should
    # give each bucket ~50 hits; guard the loosest sanity band.
    assert min(counts) > 15
    assert max(counts) < 100


@pytest.mark.asyncio
async def test_resolve_version_routes_stable_cohort(test_db) -> None:
    """resolve_version_for_investigation deterministically routes
    ~cohort_percent of investigations to the canary version; the same
    investigation_id always lands in the same bucket."""
    del test_db
    controller, store, runner = _controller()
    key = _key()
    prod_version = await _prepare_evaluated(
        controller, store, runner, key=key, body="PROD",
    )
    canary_version = await _prepare_evaluated(
        controller, store, runner, key=key, body="CANARY",
    )
    await controller.approve(
        key=key, version=prod_version, actor="reviewer-alice",
    )
    await controller.promote(
        key=key, version=prod_version, actor="op",
    )
    await controller.shadow(key=key, version=canary_version, actor="op")
    await controller.canary(
        key=key, version=canary_version, cohort_percent=30, actor="op",
    )

    # Determinism: repeat the same id and expect the same route.
    inv_id = f"inv-{uuid4()}"
    r1 = await controller.resolve_version_for_investigation(
        key=key, investigation_id=inv_id,
    )
    r2 = await controller.resolve_version_for_investigation(
        key=key, investigation_id=inv_id,
    )
    assert r1.version == r2.version
    assert r1.bucket == r2.bucket
    assert r1.on_canary == r2.on_canary
    assert r1.canary_version == canary_version
    assert r1.production_version == prod_version
    assert r1.cohort_percent == 30

    # Distribution: 2000 ids ~ 30% land on the canary (allow +/-6%).
    on_canary = 0
    trials = 2_000
    for i in range(trials):
        route = await controller.resolve_version_for_investigation(
            key=key, investigation_id=f"inv-{i:08d}",
        )
        if route.on_canary:
            on_canary += 1
    frac = on_canary / trials
    assert 0.24 <= frac <= 0.36, (
        f"cohort routing skewed: {frac:.3f} of {trials} ids on canary"
    )


@pytest.mark.asyncio
async def test_resolve_version_without_canary_returns_production(
    test_db,
) -> None:
    """No active canary on record -> every investigation routes to the
    production alias regardless of bucket."""
    del test_db
    controller, store, runner = _controller()
    key = _key()
    prod_version = await _prepare_evaluated(
        controller, store, runner, key=key,
    )
    await controller.approve(
        key=key, version=prod_version, actor="reviewer-alice",
    )
    await controller.promote(
        key=key, version=prod_version, actor="op",
    )

    for i in range(20):
        route = await controller.resolve_version_for_investigation(
            key=key, investigation_id=f"inv-{i}",
        )
        assert route.on_canary is False
        assert route.version == prod_version
        assert route.canary_version is None
        assert route.cohort_percent is None


@pytest.mark.asyncio
async def test_canary_signal_within_ceilings_does_not_hold(
    test_db, monkeypatch,
) -> None:
    """Drift and cost both below ceilings -> fired=False, no hold."""
    del test_db
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_DRIFT_CEILING", "0.5")
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_COST_CEILING_USD", "10.0")
    controller, store, runner = _controller()
    key = _key()
    version = await _prepare_evaluated(
        controller, store, runner, key=key,
    )
    await controller.shadow(key=key, version=version, actor="op")
    await controller.canary(
        key=key, version=version, cohort_percent=10, actor="op",
    )

    outcome = await controller.record_canary_signal(
        key=key, drift=0.1, cost=1.0,
    )
    assert outcome.fired is False
    assert outcome.reason == "within_ceilings"
    assert outcome.signal is not None
    assert outcome.signal.drift_breach is False
    assert outcome.signal.cost_breach is False

    active = await controller.active_canary(key)
    assert active is not None
    assert active.state == AssignmentState.ACTIVE.value


@pytest.mark.asyncio
async def test_canary_signal_drift_breach_holds_and_journals(
    test_db, monkeypatch,
) -> None:
    """A drift breach flips the canary to held, journals canary -> held,
    stamps last_signal_json on the assignment row, and returns fired."""
    del test_db
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_DRIFT_CEILING", "0.2")
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_COST_CEILING_USD", "10.0")
    controller, store, runner = _controller()
    key = _key()
    version = await _prepare_evaluated(
        controller, store, runner, key=key,
    )
    await controller.shadow(key=key, version=version, actor="op")
    await controller.canary(
        key=key, version=version, cohort_percent=15, actor="op",
    )

    outcome = await controller.record_canary_signal(
        key=key, drift=0.9, cost=1.0,
    )
    assert outcome.fired is True
    assert outcome.reason == "held"
    assert outcome.signal is not None
    assert outcome.signal.drift_breach is True
    assert outcome.signal.cost_breach is False
    assert outcome.transition is not None
    assert outcome.transition.to_stage == LifecycleStage.HELD.value
    assert outcome.transition.from_stage == LifecycleStage.CANARY.value

    snapshot = json.loads(outcome.transition.metrics_snapshot_json)
    assert snapshot["drift_breach"] is True
    assert snapshot["drift"] == pytest.approx(0.9)
    assert snapshot["drift_ceiling"] == pytest.approx(0.2)

    # The held canary is no longer active; the router falls back to
    # production for every investigation.
    assert await controller.active_canary(key) is None


@pytest.mark.asyncio
async def test_canary_signal_cost_breach_holds(
    test_db, monkeypatch,
) -> None:
    """A cost breach with drift within ceiling still flips to held."""
    del test_db
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_DRIFT_CEILING", "0.5")
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_COST_CEILING_USD", "2.0")
    controller, store, runner = _controller()
    key = _key()
    version = await _prepare_evaluated(
        controller, store, runner, key=key,
    )
    await controller.shadow(key=key, version=version, actor="op")
    await controller.canary(
        key=key, version=version, cohort_percent=20, actor="op",
    )

    outcome = await controller.record_canary_signal(
        key=key, drift=0.1, cost=8.0,
    )
    assert outcome.fired is True
    assert outcome.reason == "held"
    assert outcome.signal is not None
    assert outcome.signal.drift_breach is False
    assert outcome.signal.cost_breach is True


@pytest.mark.asyncio
async def test_canary_signal_no_active_canary(test_db) -> None:
    """No canary on record -> fired=False with reason no_active_canary
    and no journal row written."""
    del test_db
    controller, _store, _runner = _controller()
    key = _key()

    outcome = await controller.record_canary_signal(
        key=key, drift=99.0, cost=99.0,
    )
    assert outcome.fired is False
    assert outcome.reason == "no_active_canary"
    assert outcome.signal is None
    assert outcome.transition is None
    assert await controller.list_transitions(key) == []


@pytest.mark.asyncio
async def test_held_canary_stops_cohort_routing(
    test_db, monkeypatch,
) -> None:
    """Once a canary is held, every investigation routes to production."""
    del test_db
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_DRIFT_CEILING", "0.2")
    monkeypatch.setenv("AILA_PLATFORM_AGENT_CANARY_COST_CEILING_USD", "10.0")
    controller, store, runner = _controller()
    key = _key()
    prod_version = await _prepare_evaluated(
        controller, store, runner, key=key, body="PROD",
    )
    canary_version = await _prepare_evaluated(
        controller, store, runner, key=key, body="CANARY",
    )
    await controller.approve(
        key=key, version=prod_version, actor="reviewer-alice",
    )
    await controller.promote(
        key=key, version=prod_version, actor="op",
    )
    await controller.shadow(key=key, version=canary_version, actor="op")
    await controller.canary(
        key=key, version=canary_version, cohort_percent=50, actor="op",
    )
    await controller.record_canary_signal(
        key=key, drift=0.9, cost=1.0,
    )

    for i in range(30):
        route = await controller.resolve_version_for_investigation(
            key=key, investigation_id=f"inv-{i}",
        )
        assert route.on_canary is False
        assert route.version == prod_version


@pytest.mark.asyncio
async def test_promote_from_canary_still_enforces_eval_and_quorum_gate(
    test_db,
) -> None:
    """promote_from_canary reuses the eval + quorum gate: an unapproved
    canary can never reach production even after a shadow + canary run."""
    del test_db
    controller, store, runner = _controller()
    key = _key()
    version = await _prepare_evaluated(
        controller, store, runner, key=key,
    )
    await controller.shadow(key=key, version=version, actor="op")
    await controller.canary(
        key=key, version=version, cohort_percent=10, actor="op",
    )

    # No approve on record -> quorum not met -> promote raises and the
    # production alias is not created.
    with pytest.raises(StageTransitionError):
        await controller.promote_from_canary(
            key=key, version=version, actor="op",
        )
    assert await store.resolve(key, alias=PRODUCTION_ALIAS) is None

    # The canary assignment stays live because promotion did not complete.
    active = await controller.active_canary(key)
    assert active is not None
    assert active.state == AssignmentState.ACTIVE.value

    # An explicit approval lifts the gate; the second promote succeeds
    # and supersedes the canary assignment.
    await controller.approve(
        key=key, version=version, actor="reviewer-alice",
    )
    await controller.promote_from_canary(
        key=key, version=version, actor="op",
    )
    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == version
    assert await controller.active_canary(key) is None


@pytest.mark.asyncio
async def test_assignment_table_model_registered(test_db) -> None:
    """Guardrail: importing the assignment model at module scope must
    register the table on SQLModel.metadata so create_all builds it."""
    del test_db
    assert LifecycleCanaryAssignment.__tablename__ == (
        "lifecycle_canary_assignments"
    )
    # Sanity-check the LifecycleTransitionRecord import is still what
    # the create_all path builds; both models must live side-by-side.
    assert LifecycleTransitionRecord.__tablename__ == "lifecycle_transitions"
    # Env plumbing round-trip: os.environ should carry our test DB URL
    # so the assertion is not comparing against a stale settings cache.
    assert os.environ.get("AILA_DATABASE_URL")
