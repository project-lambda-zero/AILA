"""Tests for the RFC-10 agent lifecycle controller.

Covers the five acceptance scenarios:

1. Evaluate a passing candidate -> transition to 'evaluated' with a
   pass verdict journaled and the eval report packed into the metrics
   snapshot.
2. Promote after a passing evaluate -> production alias flipped to the
   candidate + an 'evaluated' -> 'production' transition journaled.
3. Promote WITHOUT a prior passing evaluate (either no evaluate at all,
   or an evaluate that returned 'fail') -> StageTransitionError; the
   production alias is not touched.
4. Rollback -> production alias returns to the prior production version
   + a 'production' -> 'rolled_back' transition journaled on the
   rolled-back version with the restored target in the snapshot.
5. LifecycleTransitionRecord row has all columns populated (id, key,
   version, from_stage, to_stage, actor, reason, metrics_snapshot_json,
   created_at).

Importing ``LifecycleTransitionRecord`` at module scope registers the
``lifecycle_transitions`` table on ``SQLModel.metadata`` so the shared
``test_db`` fixture's ``create_all`` builds it -- no migration and no
edit to ``storage/db_models.py`` is needed to pass these tests.
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

    transition = await controller.promote(
        key=key, version=version, actor="op", reason="ship it",
    )

    assert transition.from_stage == LifecycleStage.EVALUATED.value
    assert transition.to_stage == LifecycleStage.PRODUCTION.value
    assert transition.reason == "ship it"
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

    # Evaluate + promote A (first-ever eval auto-passes with no baseline).
    bench_a = await runner.register_benchmark(
        key=key, name="a", cases=_perfect_cases(version_a), created_by="op",
    )
    await controller.evaluate(
        key=key, version=version_a, benchmark_id=bench_a.id, actor="op",
    )
    await controller.promote(
        key=key, version=version_a, actor="op", reason="ship a",
    )

    # Evaluate + promote B (baseline is now A; benchmark scores only B,
    # so the runner falls back to the first-ever auto-pass path).
    bench_b = await runner.register_benchmark(
        key=key, name="b", cases=_perfect_cases(version_b), created_by="op",
    )
    await controller.evaluate(
        key=key, version=version_b, benchmark_id=bench_b.id, actor="op",
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
