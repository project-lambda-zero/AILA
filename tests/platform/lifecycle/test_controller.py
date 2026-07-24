"""Tests for the RFC-10 agent lifecycle controller.

Covers the acceptance scenarios:

1. Evaluate a passing candidate -> transition to 'evaluated' with a
   pass verdict journaled and the eval report packed into the metrics
   snapshot.
2. Approve + promote after a passing evaluate -> production alias
   flipped to the candidate + 'evaluated' -> 'approved' and
   'evaluated' -> 'production' transitions journaled.
3. Promote WITHOUT a prior passing evaluate (either no evaluate at all,
   or an evaluate that returned 'fail') -> StageTransitionError; the
   production alias is not touched.
4. Promote WITH a passing evaluate but ZERO approvals ->
   StageTransitionError naming approver_count vs threshold; the alias
   is not touched (RFC-10 quorum gate).
5. Approve WITHOUT a passing evaluate -> StageTransitionError; no
   journal row is written.
6. Quorum threshold > 1 requires that many DISTINCT actor strings on
   approved rows -- the same approver twice does not lift the gate.
7. Rollback -> production alias returns to the prior production version
   + a 'production' -> 'rolled_back' transition journaled on the
   rolled-back version with the restored target in the snapshot.
8. LifecycleTransitionRecord row has all columns populated (id, key,
   version, from_stage, to_stage, actor, reason, metrics_snapshot_json,
   created_at).

Importing ``LifecycleTransitionRecord`` at module scope registers the
``lifecycle_transitions`` table on ``SQLModel.metadata`` so the shared
``test_db`` fixture's ``create_all`` builds it -- no migration and no
edit to ``storage/db_models.py`` is needed to pass these tests.

Quorum-threshold tests set ``AILA_PLATFORM_AGENT_PROMOTION_QUORUM``
(env var overrides the ConfigRegistry read) so no schema registration
or DB seeding is required; the env is scoped to the test function via
``monkeypatch``.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest

from aila.platform.eval.runner import PRODUCTION_ALIAS, EvalRunner
from aila.platform.lifecycle.controller import (
    AgentLifecycleController,
    StageTransitionError,
)
from aila.platform.lifecycle.models import (
    LifecycleStage,
    LifecycleTransitionRecord,
)
from aila.platform.prompts.version_store import PromptVersionStore


def _key() -> str:
    return f"vr/lifecycle-{uuid4().hex[:8]}"


def _perfect_cases(version: str, n: int = 8) -> list[dict[str, object]]:
    """Cases matching the truth at high confidence -- verdict = 'pass'."""
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


def _mediocre_cases(version: str) -> list[dict[str, object]]:
    """Cases where the predictor is confidently wrong on some calls."""
    return [
        {"outcome_kind": "sqli", "predicted_verdict": "accept",
         "verified_verdict": "accept", "confidence": 0.95, "version": version},
        {"outcome_kind": "sqli", "predicted_verdict": "accept",
         "verified_verdict": "accept", "confidence": 0.95, "version": version},
        {"outcome_kind": "sqli", "predicted_verdict": "accept",
         "verified_verdict": "reject", "confidence": 0.95, "version": version},
        {"outcome_kind": "sqli", "predicted_verdict": "accept",
         "verified_verdict": "reject", "confidence": 0.95, "version": version},
        {"outcome_kind": "xss", "predicted_verdict": "accept",
         "verified_verdict": "accept", "confidence": 0.95, "version": version},
        {"outcome_kind": "xss", "predicted_verdict": "accept",
         "verified_verdict": "accept", "confidence": 0.95, "version": version},
    ]


@pytest.mark.asyncio
async def test_evaluate_passes_and_journals_evaluated(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()

    version = await store.register(key, "PROMPT BODY", author="test")
    bench = await runner.register_benchmark(
        key=key, name="acc-1", cases=_perfect_cases(version), created_by="op",
    )

    transition = await controller.evaluate(
        key=key, version=version, benchmark_id=bench.id, actor="op",
    )

    assert isinstance(transition, LifecycleTransitionRecord)
    assert transition.key == key
    assert transition.version == version
    assert transition.from_stage == LifecycleStage.BUILT.value
    assert transition.to_stage == LifecycleStage.EVALUATED.value
    assert transition.actor == "op"
    assert transition.metrics_snapshot_json is not None
    payload = json.loads(transition.metrics_snapshot_json)
    assert payload["verdict"] == "pass"
    assert payload["eval_run_id"]
    assert payload["candidate_version"] == version
    assert payload["report"]["promoted"] is False


@pytest.mark.asyncio
async def test_promote_after_passing_evaluate_flips_alias(test_db) -> None:
    """Golden path: evaluate + approve (quorum=1 default) + promote flips
    the production alias and packs the observed approver count into the
    promote row's metrics snapshot."""
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()

    version = await store.register(key, "PROMPT BODY", author="test")
    bench = await runner.register_benchmark(
        key=key, name="acc-1", cases=_perfect_cases(version), created_by="op",
    )
    await controller.evaluate(
        key=key, version=version, benchmark_id=bench.id, actor="op",
    )
    approve_row = await controller.approve(
        key=key, version=version, actor="reviewer-alice",
        reason="looks good",
    )
    assert approve_row.from_stage == LifecycleStage.EVALUATED.value
    assert approve_row.to_stage == LifecycleStage.APPROVED.value

    transition = await controller.promote(
        key=key, version=version, actor="op", reason="ship it",
    )

    assert transition.from_stage == LifecycleStage.EVALUATED.value
    assert transition.to_stage == LifecycleStage.PRODUCTION.value
    assert transition.reason == "ship it"
    snapshot = json.loads(transition.metrics_snapshot_json)
    assert snapshot["approver_count"] == 1
    assert snapshot["quorum_threshold"] == 1
    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == version


@pytest.mark.asyncio
async def test_promote_without_approval_raises_and_leaves_alias(
    test_db,
) -> None:
    """Eval passes but zero approvers on record -> StageTransitionError,
    the message names the approver count vs the required quorum, and
    the production alias is not touched."""
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()

    version = await store.register(key, "PROMPT BODY", author="test")
    bench = await runner.register_benchmark(
        key=key, name="acc-1", cases=_perfect_cases(version), created_by="op",
    )
    await controller.evaluate(
        key=key, version=version, benchmark_id=bench.id, actor="op",
    )

    with pytest.raises(StageTransitionError) as exc_info:
        await controller.promote(
            key=key, version=version, actor="op", reason="skip approval",
        )
    msg = str(exc_info.value)
    assert "quorum not met" in msg
    assert "0 distinct approver" in msg
    assert "1 required" in msg

    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is None, (
        "alias must not be created when quorum is not met"
    )


@pytest.mark.asyncio
async def test_approve_without_passing_evaluate_raises(test_db) -> None:
    """Approve on a version with no passing evaluate row -> raises and
    writes no journal row (the transitions list stays empty)."""
    del test_db
    store = PromptVersionStore()
    controller = AgentLifecycleController(version_store=store)
    key = _key()

    version = await store.register(key, "PROMPT BODY", author="test")

    with pytest.raises(StageTransitionError) as exc_info:
        await controller.approve(
            key=key, version=version, actor="reviewer",
        )
    assert "no prior passing 'evaluated'" in str(exc_info.value)

    rows = await controller.list_transitions(key)
    assert rows == [], "approve must write no journal row on the guard path"


@pytest.mark.asyncio
async def test_quorum_gt_one_requires_distinct_actors(
    test_db, monkeypatch,
) -> None:
    """With quorum=2, two rows from the SAME actor do not satisfy; a
    second distinct actor is required. This is the RFC-10 acceptance
    line "same actor twice does not satisfy"."""
    del test_db
    monkeypatch.setenv("AILA_PLATFORM_AGENT_PROMOTION_QUORUM", "2")

    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()

    version = await store.register(key, "PROMPT BODY", author="test")
    bench = await runner.register_benchmark(
        key=key, name="acc-1", cases=_perfect_cases(version), created_by="op",
    )
    await controller.evaluate(
        key=key, version=version, benchmark_id=bench.id, actor="op",
    )

    # Same actor twice: still one distinct approver.
    await controller.approve(
        key=key, version=version, actor="reviewer-alice",
    )
    await controller.approve(
        key=key, version=version, actor="reviewer-alice",
    )

    with pytest.raises(StageTransitionError) as exc_info:
        await controller.promote(
            key=key, version=version, actor="op", reason="one-vote-twice",
        )
    msg = str(exc_info.value)
    assert "1 distinct approver" in msg
    assert "2 required" in msg

    # A second distinct approver satisfies the quorum.
    await controller.approve(
        key=key, version=version, actor="reviewer-bob",
    )
    transition = await controller.promote(
        key=key, version=version, actor="op", reason="quorum met",
    )
    snapshot = json.loads(transition.metrics_snapshot_json)
    assert snapshot["approver_count"] == 2
    assert snapshot["quorum_threshold"] == 2
    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == version


@pytest.mark.asyncio
async def test_promote_without_prior_evaluate_raises_and_leaves_alias(
    test_db,
) -> None:
    del test_db
    store = PromptVersionStore()
    controller = AgentLifecycleController(version_store=store)
    key = _key()

    version = await store.register(key, "PROMPT BODY", author="test")

    with pytest.raises(StageTransitionError):
        await controller.promote(
            key=key, version=version, actor="op", reason="premature",
        )

    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is None, "alias must not be created without a passing eval"


@pytest.mark.asyncio
async def test_promote_after_failing_evaluate_raises_and_leaves_alias(
    test_db,
) -> None:
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()

    # Baseline perfect, candidate mediocre -- candidate must lose.
    baseline = await store.register(key, "BODY A", author="test")
    candidate = await store.register(key, "BODY B", author="test")
    await store.set_alias(key, PRODUCTION_ALIAS, baseline, actor="setup")

    bench = await runner.register_benchmark(
        key=key, name="regr",
        cases=[*_perfect_cases(baseline), *_mediocre_cases(candidate)],
        created_by="op",
    )
    transition = await controller.evaluate(
        key=key, version=candidate, benchmark_id=bench.id, actor="op",
    )
    assert transition.metrics_snapshot_json is not None
    assert json.loads(transition.metrics_snapshot_json)["verdict"] == "fail"

    with pytest.raises(StageTransitionError):
        await controller.promote(
            key=key, version=candidate, actor="op", reason="ignore fail",
        )

    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == baseline


@pytest.mark.asyncio
async def test_rollback_reverts_alias_to_prior_and_journals(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()

    version_a = await store.register(key, "BODY A", author="test")
    version_b = await store.register(key, "BODY B", author="test")

    # Evaluate + approve + promote A (first-ever eval auto-passes with
    # no baseline; the default quorum=1 needs one approve).
    bench_a = await runner.register_benchmark(
        key=key, name="a", cases=_perfect_cases(version_a), created_by="op",
    )
    await controller.evaluate(
        key=key, version=version_a, benchmark_id=bench_a.id, actor="op",
    )
    await controller.approve(
        key=key, version=version_a, actor="reviewer-a",
    )
    await controller.promote(
        key=key, version=version_a, actor="op", reason="ship a",
    )

    # Evaluate + approve + promote B (baseline is now A; benchmark
    # scores only B, so the runner falls back to the first-ever
    # auto-pass path).
    bench_b = await runner.register_benchmark(
        key=key, name="b", cases=_perfect_cases(version_b), created_by="op",
    )
    await controller.evaluate(
        key=key, version=version_b, benchmark_id=bench_b.id, actor="op",
    )
    await controller.approve(
        key=key, version=version_b, actor="reviewer-b",
    )
    await controller.promote(
        key=key, version=version_b, actor="op", reason="ship b",
    )

    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == version_b

    transition = await controller.rollback(
        key=key, version=version_b, actor="op", reason="b broken",
    )
    assert transition.from_stage == LifecycleStage.PRODUCTION.value
    assert transition.to_stage == LifecycleStage.ROLLED_BACK.value
    assert transition.version == version_b
    assert transition.metrics_snapshot_json is not None
    payload = json.loads(transition.metrics_snapshot_json)
    assert payload["rolled_back_to"] == version_a

    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == version_a


@pytest.mark.asyncio
async def test_transition_row_has_all_columns_populated(test_db) -> None:
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    controller = AgentLifecycleController(
        eval_runner=runner, version_store=store,
    )
    key = _key()

    version = await store.register(key, "BODY", author="test")
    bench = await runner.register_benchmark(
        key=key, name="c", cases=_perfect_cases(version), created_by="op",
    )
    transition = await controller.evaluate(
        key=key, version=version, benchmark_id=bench.id, actor="op",
    )

    assert transition.id
    assert transition.key == key
    assert transition.version == version
    assert transition.from_stage == LifecycleStage.BUILT.value
    assert transition.to_stage == LifecycleStage.EVALUATED.value
    assert transition.actor == "op"
    assert transition.reason
    assert transition.metrics_snapshot_json
    assert transition.created_at is not None
