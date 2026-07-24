"""Tests for the RFC-08 eval runner and promotion gate.

Covers the five acceptance scenarios:

1. Candidate beats baseline -> verdict 'pass'; production alias flipped
   when auto_promote is True.
2. Candidate regresses vs baseline -> verdict 'fail'; alias unchanged.
3. Missing benchmark id -> ``BenchmarkNotFoundError``.
4. No production baseline (first ever eval) -> verdict 'pass' via the
   warning-logged auto-pass path.
5. Candidate beats baseline but auto_promote=False -> verdict 'pass';
   alias still unchanged.
"""
from __future__ import annotations

import json
import logging
from uuid import uuid4

import pytest

from aila.platform.eval.runner import (
    PRODUCTION_ALIAS,
    BenchmarkNotFoundError,
    EvalRunner,
)
from aila.platform.prompts.version_store import PromptVersionStore


def _key() -> str:
    return f"vr/audit-{uuid4().hex[:8]}"


def _perfect_cases(version: str, n: int = 8) -> list[dict[str, object]]:
    """Cases where every prediction matches the truth at high confidence.

    ECE ~= 0 (confident and correct). Precision = recall = 1.0.
    """
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
    """Cases where the predictor is confidently wrong on half the calls.

    ECE is high (confident and often wrong). Precision on 'sqli' drops
    because false-accepts are recorded against verified 'reject'.
    """
    return [
        # Confident correct accepts.
        {"outcome_kind": "sqli", "predicted_verdict": "accept",
         "verified_verdict": "accept", "confidence": 0.95, "version": version},
        {"outcome_kind": "sqli", "predicted_verdict": "accept",
         "verified_verdict": "accept", "confidence": 0.95, "version": version},
        # Confident WRONG accepts -- drives ECE up and precision down.
        {"outcome_kind": "sqli", "predicted_verdict": "accept",
         "verified_verdict": "reject", "confidence": 0.95, "version": version},
        {"outcome_kind": "sqli", "predicted_verdict": "accept",
         "verified_verdict": "reject", "confidence": 0.95, "version": version},
        # XSS handled correctly.
        {"outcome_kind": "xss", "predicted_verdict": "accept",
         "verified_verdict": "accept", "confidence": 0.95, "version": version},
        {"outcome_kind": "xss", "predicted_verdict": "accept",
         "verified_verdict": "accept", "confidence": 0.95, "version": version},
    ]


async def _register_versions(
    store: PromptVersionStore, key: str, bodies: list[str],
) -> list[str]:
    return [await store.register(key, body, author="test") for body in bodies]


@pytest.mark.asyncio
async def test_candidate_beats_baseline_promotes_when_opted_in(
    test_db,
) -> None:
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    key = _key()

    # Register two versions; promote v1 to production first.
    v_base, v_cand = await _register_versions(store, key, ["BODY A", "BODY B"])
    await store.set_alias(key, PRODUCTION_ALIAS, v_base, actor="setup")

    # Benchmark: baseline mediocre, candidate perfect.
    bench = await runner.register_benchmark(
        key=key,
        name="mixed",
        cases=[*_mediocre_cases(v_base), *_perfect_cases(v_cand)],
        created_by="op",
    )

    run = await runner.run(
        key=key,
        candidate_version=v_cand,
        benchmark_id=bench.id,
        auto_promote=True,
        actor="op",
    )
    assert run.verdict == "pass"
    assert run.baseline_version == v_base
    assert run.candidate_version == v_cand
    payload = json.loads(run.report_json)
    assert payload["promoted"] is True
    assert payload["baseline"] is not None
    assert payload["candidate"]["ece"] < payload["baseline"]["ece"]

    # Production alias flipped to the candidate.
    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == v_cand


@pytest.mark.asyncio
async def test_candidate_regresses_verdict_fails_and_alias_unchanged(
    test_db,
) -> None:
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    key = _key()

    v_base, v_cand = await _register_versions(store, key, ["BODY A", "BODY B"])
    await store.set_alias(key, PRODUCTION_ALIAS, v_base, actor="setup")

    # Baseline perfect, candidate mediocre -- candidate must lose.
    bench = await runner.register_benchmark(
        key=key,
        name="regression",
        cases=[*_perfect_cases(v_base), *_mediocre_cases(v_cand)],
        created_by="op",
    )

    run = await runner.run(
        key=key,
        candidate_version=v_cand,
        benchmark_id=bench.id,
        auto_promote=True,
        actor="op",
    )
    assert run.verdict == "fail"
    payload = json.loads(run.report_json)
    assert payload["promoted"] is False

    # Alias unchanged: still pointing at the baseline version.
    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == v_base


@pytest.mark.asyncio
async def test_missing_benchmark_raises(test_db) -> None:
    del test_db
    runner = EvalRunner()
    with pytest.raises(BenchmarkNotFoundError):
        await runner.run(
            key=_key(),
            candidate_version="1.0.0",
            benchmark_id="does-not-exist",
            auto_promote=False,
            actor="op",
        )


@pytest.mark.asyncio
async def test_no_baseline_first_eval_auto_passes_with_warning(
    test_db, caplog: pytest.LogCaptureFixture,
) -> None:
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    key = _key()

    (v_cand,) = await _register_versions(store, key, ["FIRST BODY"])
    bench = await runner.register_benchmark(
        key=key,
        name="first",
        cases=_perfect_cases(v_cand),
        created_by="op",
    )

    with caplog.at_level(logging.WARNING, logger="aila.platform.eval.runner"):
        run = await runner.run(
            key=key,
            candidate_version=v_cand,
            benchmark_id=bench.id,
            auto_promote=True,
            actor="op",
        )
    assert run.verdict == "pass"
    assert run.baseline_version is None
    assert any(
        "first-ever eval" in rec.message for rec in caplog.records
    ), "expected the first-eval auto-pass warning to be logged"

    # auto_promote=True + verdict=pass -> alias set to candidate.
    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == v_cand


@pytest.mark.asyncio
async def test_pass_but_auto_promote_false_leaves_alias_unchanged(
    test_db,
) -> None:
    del test_db
    store = PromptVersionStore()
    runner = EvalRunner(store)
    key = _key()

    v_base, v_cand = await _register_versions(store, key, ["BODY A", "BODY B"])
    await store.set_alias(key, PRODUCTION_ALIAS, v_base, actor="setup")

    bench = await runner.register_benchmark(
        key=key,
        name="dry-run",
        cases=[*_mediocre_cases(v_base), *_perfect_cases(v_cand)],
        created_by="op",
    )

    run = await runner.run(
        key=key,
        candidate_version=v_cand,
        benchmark_id=bench.id,
        auto_promote=False,
        actor="op",
    )
    assert run.verdict == "pass"
    payload = json.loads(run.report_json)
    assert payload["promoted"] is False

    resolved = await store.resolve(key, alias=PRODUCTION_ALIAS)
    assert resolved is not None
    assert resolved.version == v_base, "alias must NOT flip when auto_promote is False"
