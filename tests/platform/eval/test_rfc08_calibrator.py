"""Tests for the RFC-08 Tier D post-hoc calibrator + promotion gate.

Covers:

* :class:`Calibrator` -- pure fit + apply behavior.
  - Isotonic fit on an overconfident synthetic sample set lowers ECE
    vs the identity mapping.
  - Isotonic apply is monotone non-decreasing and clamped to ``[0, 1]``.
  - JSON round-trip via ``to_params`` / :meth:`Calibrator.from_params`
    preserves the fitted state.
* :func:`_apply_calibration` -- gate hot-path seam.
  - Returns the raw score when no active :class:`CalibratorVersionRecord`
    exists for the request's ``task_type``.
  - Returns the calibrated score when one is active.
* :func:`promote_calibrator` -- the C7 gate.
  - Rejects when ECE fails to improve.
  - Rejects when the distinct-approver quorum is not met.
  - Accepts and flips the active row when both gates clear
    (prior active supersedes).
* ``POST /admin/eval/calibration-proposals/{id}/promote`` -- threshold
  promote route writes into the live ConfigRegistry ONLY when quorum
  holds; refuses on insufficient approvers.

The calibrator's SQLModel tables (``eval_calibrator_versions`` and
``eval_calibration_samples``) are registered by importing
``aila.platform.eval.calibrator`` at module scope; ``tests/_db_bootstrap.py``
also lists the module so a fresh test DB carries the same schema. The
admin route test uses a stubbed :class:`AuthContext` + rate-limiter
bypass matching the existing admin-eval test patterns.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.platform.config import PlatformConfigSchema
from aila.platform.eval.calibration import (
    CALIBRATION_STATUS_ACTIVE,
    CalibrationProposalRecord,
)
from aila.platform.eval.calibrator import (
    CALIBRATOR_METHOD_ISOTONIC,
    CALIBRATOR_METHOD_TEMPERATURE,
    CALIBRATOR_STATUS_ACTIVE,
    CALIBRATOR_STATUS_CANDIDATE,
    CALIBRATOR_STATUS_SUPERSEDED,
    Calibrator,
    CalibratorPromotionError,
    CalibratorVersionRecord,
    _ece_of,
    _invalidate_active_cache,
    load_active_calibrator,
    promote_calibrator,
)
from aila.platform.eval.metrics import ece as _ece_metric
from aila.storage.database import async_session_scope
from aila.storage.registry import ConfigRegistry


# ---------------------------------------------------------------------------
# Pure Calibrator: fit lowers ECE + apply is monotone + params round-trip
# ---------------------------------------------------------------------------


def _overconfident_samples() -> list[tuple[float, bool]]:
    """Synthetic set: LLM says 0.95 confident but only 50% correct.

    Splits the raw axis into a low band (0.15, actually right 15% of
    the time -- also miscalibrated but in the other direction) and a
    high band (0.95, actually right 50% of the time). ECE against the
    identity mapping is large (bucket-vs-accuracy gap of ~0.45 in the
    high bucket). A monotone fit should push the high band DOWN toward
    0.5 and the low band UP toward 0.15, collapsing the gap.
    """
    samples: list[tuple[float, bool]] = []
    for i in range(40):
        samples.append((0.15, i < 6))  # 6/40 = 0.15 accuracy at conf=0.15
    for i in range(40):
        samples.append((0.95, i < 20))  # 20/40 = 0.5 accuracy at conf=0.95
    return samples


def test_calibrator_isotonic_fit_lowers_ece_vs_identity() -> None:
    """Isotonic fit on overconfident samples produces a lower ECE than raw."""
    samples = _overconfident_samples()
    baseline = _ece_of(samples, None)
    calibrator = Calibrator.fit(samples, CALIBRATOR_METHOD_ISOTONIC)
    fitted = _ece_of(samples, calibrator)
    # Sanity: the raw feed IS overconfident by construction.
    assert baseline > 0.1, f"baseline ECE unexpectedly low: {baseline}"
    assert fitted < baseline, (
        f"isotonic fit should lower ECE: baseline={baseline}, fitted={fitted}"
    )


def test_calibrator_isotonic_apply_is_monotone_and_clamped() -> None:
    """apply(x) is non-decreasing across x and always inside [0, 1]."""
    samples = _overconfident_samples()
    calibrator = Calibrator.fit(samples, CALIBRATOR_METHOD_ISOTONIC)
    grid = [i / 100.0 for i in range(101)]  # 0.00, 0.01, ..., 1.00
    values = [calibrator.apply(x) for x in grid]
    # All in [0, 1]:
    for v in values:
        assert 0.0 <= v <= 1.0, f"apply out of range: {v}"
    # Monotone non-decreasing (adjacent-pair walk; values[1:] is one
    # shorter by construction, so no strict= length check here):
    for prev, nxt in zip(values, values[1:]):
        assert nxt + 1e-9 >= prev, (
            f"isotonic apply not monotone at ({prev} -> {nxt})"
        )
    # Extreme inputs clamp:
    assert calibrator.apply(-0.1) == calibrator.apply(0.0)
    assert calibrator.apply(1.5) == calibrator.apply(1.0)


def test_calibrator_params_json_round_trip() -> None:
    """to_params -> json.dumps -> from_params reproduces the same apply()."""
    samples = _overconfident_samples()
    for method in (
        CALIBRATOR_METHOD_ISOTONIC, CALIBRATOR_METHOD_TEMPERATURE,
    ):
        original = Calibrator.fit(samples, method)
        blob = json.dumps(original.to_params(), sort_keys=True)
        restored = Calibrator.from_params(json.loads(blob))
        for x in (0.0, 0.15, 0.5, 0.85, 0.95, 1.0):
            assert restored.apply(x) == pytest.approx(original.apply(x)), (
                f"round-trip broke apply({x}) for method={method}: "
                f"orig={original.apply(x)}, restored={restored.apply(x)}"
            )


# ---------------------------------------------------------------------------
# Gate seam: _apply_calibration returns raw when absent, calibrated when active
# ---------------------------------------------------------------------------


class _FakeRegistry:
    """Minimal ConfigRegistry stand-in for gate config reads."""

    def __init__(self, overrides: dict[str, object] | None = None) -> None:
        self._data = overrides or {}

    async def get(self, namespace: str, key: str) -> object | None:
        del namespace
        return self._data.get(key)


class _FakeConfigProvider:
    """Wraps _FakeRegistry as ``_registry`` (mirrors LLMConfigProvider)."""

    def __init__(self, overrides: dict[str, object] | None = None) -> None:
        self._registry = _FakeRegistry(overrides)


async def test_apply_calibration_returns_raw_when_no_active(test_db) -> None:
    """No active calibrator -> raw pass-through, calibrator flag ignored."""
    del test_db
    from aila.platform.llm.gate import _apply_calibration

    _invalidate_active_cache()
    task_type = f"task_{uuid4().hex[:6]}"
    provider = _FakeConfigProvider()
    for raw in (0.1, 0.5, 0.9):
        result = await _apply_calibration(provider, task_type, raw)
        assert result == pytest.approx(raw)


async def test_apply_calibration_uses_active_row(test_db) -> None:
    """A persisted active calibrator recalibrates the raw score."""
    del test_db
    from aila.platform.llm.gate import _apply_calibration

    _invalidate_active_cache()
    task_type = f"task_{uuid4().hex[:6]}"
    calibrator = Calibrator.fit(
        _overconfident_samples(), CALIBRATOR_METHOD_ISOTONIC,
    )
    row = CalibratorVersionRecord(
        task_type=task_type,
        method=calibrator.method,
        params_json=json.dumps(calibrator.to_params(), sort_keys=True),
        ece_before=0.5,
        ece_after=0.1,
        sample_count=len(_overconfident_samples()),
        status=CALIBRATOR_STATUS_ACTIVE,
        actor="tester",
    )
    async with async_session_scope() as session:
        session.add(row)
        await session.commit()

    provider = _FakeConfigProvider()
    for raw in (0.1, 0.5, 0.95):
        expected = calibrator.apply(raw)
        result = await _apply_calibration(provider, task_type, raw)
        assert result == pytest.approx(expected), (
            f"calibrator not applied for raw={raw}: "
            f"got={result}, expected={expected}"
        )


# ---------------------------------------------------------------------------
# promote_calibrator: rejects on ECE regression / quorum miss; accepts otherwise
# ---------------------------------------------------------------------------


async def _seed_active_calibrator(task_type: str, ece_after: float) -> str:
    """Insert one already-active calibrator row for ``task_type``."""
    row = CalibratorVersionRecord(
        task_type=task_type,
        method=CALIBRATOR_METHOD_TEMPERATURE,
        params_json=json.dumps({
            "method": CALIBRATOR_METHOD_TEMPERATURE, "temperature": 1.0,
        }, sort_keys=True),
        ece_before=ece_after + 0.05,
        ece_after=ece_after,
        sample_count=100,
        status=CALIBRATOR_STATUS_ACTIVE,
        actor="tester_seed",
    )
    async with async_session_scope() as session:
        session.add(row)
        await session.commit()
    return row.id


async def _persist_candidate(
    task_type: str, ece_after: float,
) -> str:
    """Insert one candidate row and return its id."""
    calibrator = Calibrator.fit(
        _overconfident_samples(), CALIBRATOR_METHOD_ISOTONIC,
    )
    row = CalibratorVersionRecord(
        task_type=task_type,
        method=calibrator.method,
        params_json=json.dumps(calibrator.to_params(), sort_keys=True),
        ece_before=ece_after + 0.1,
        ece_after=ece_after,
        sample_count=len(_overconfident_samples()),
        status=CALIBRATOR_STATUS_CANDIDATE,
        actor="trainer",
    )
    async with async_session_scope() as session:
        session.add(row)
        await session.commit()
    return row.id


async def _set_promotion_quorum(value: int) -> None:
    """Set ``platform.agent_promotion_quorum`` via the real registry.

    ConfigRegistry.set requires the platform schema registered on the
    instance (a fresh ConfigRegistry carries no schemas); register first,
    mirroring the app-boot path. The persisted DB row is then visible to
    the fresh ConfigRegistry() that promote_calibrator reads through.
    """
    registry = ConfigRegistry()
    await registry.register("platform", PlatformConfigSchema)
    await registry.set(
        "platform", "agent_promotion_quorum", str(value),
    )


async def test_promote_calibrator_rejects_when_ece_no_improvement(
    test_db,
) -> None:
    """Candidate ECE tied with active -> promotion refused."""
    del test_db
    _invalidate_active_cache()
    task_type = f"task_{uuid4().hex[:6]}"
    await _seed_active_calibrator(task_type, ece_after=0.05)
    candidate_id = await _persist_candidate(task_type, ece_after=0.05)

    with pytest.raises(CalibratorPromotionError, match="ece_no_improvement"):
        await promote_calibrator(
            candidate_id,
            actor="admin",
            quorum_approver_ids=["a1", "a2", "a3"],
        )
    async with async_session_scope() as session:
        row = (await session.exec(
            select(CalibratorVersionRecord).where(
                CalibratorVersionRecord.id == candidate_id,
            ),
        )).first()
    assert row is not None
    assert row.status == CALIBRATOR_STATUS_CANDIDATE


async def test_promote_calibrator_rejects_when_quorum_insufficient(
    test_db,
) -> None:
    """Distinct-approver count below quorum -> promotion refused."""
    del test_db
    _invalidate_active_cache()
    task_type = f"task_{uuid4().hex[:6]}"
    await _set_promotion_quorum(3)
    try:
        candidate_id = await _persist_candidate(task_type, ece_after=0.02)
        with pytest.raises(
            CalibratorPromotionError, match="quorum_insufficient",
        ):
            # Two distinct approvers, threshold 3 -> reject.
            await promote_calibrator(
                candidate_id,
                actor="admin",
                quorum_approver_ids=["a1", "a2", "a1"],
            )
    finally:
        await _set_promotion_quorum(
            PlatformConfigSchema().agent_promotion_quorum,
        )


async def test_promote_calibrator_flips_active_when_both_gates_clear(
    test_db,
) -> None:
    """ECE improves AND quorum met -> candidate flips to active + prior supersedes."""
    del test_db
    _invalidate_active_cache()
    task_type = f"task_{uuid4().hex[:6]}"
    prior_id = await _seed_active_calibrator(task_type, ece_after=0.15)
    candidate_id = await _persist_candidate(task_type, ece_after=0.05)

    promoted = await promote_calibrator(
        candidate_id,
        actor="admin",
        quorum_approver_ids=["a1", "a2"],
    )
    assert promoted.status == CALIBRATOR_STATUS_ACTIVE

    async with async_session_scope() as session:
        prior = (await session.exec(
            select(CalibratorVersionRecord).where(
                CalibratorVersionRecord.id == prior_id,
            ),
        )).first()
        active = (await session.exec(
            select(CalibratorVersionRecord).where(
                CalibratorVersionRecord.id == candidate_id,
            ),
        )).first()
    assert prior is not None
    assert active is not None
    assert prior.status == CALIBRATOR_STATUS_SUPERSEDED
    assert prior.superseded_by == candidate_id
    assert active.status == CALIBRATOR_STATUS_ACTIVE
    assert active.superseded_by is None

    # The active-cache invalidation kicks in: next load returns the new row.
    loaded = await load_active_calibrator(task_type)
    assert loaded is not None
    # A promoted temperature-of-1 seed vs isotonic candidate: apply should
    # NOT be the identity on the overconfident bucket.
    assert loaded.apply(0.95) < 0.95


# ---------------------------------------------------------------------------
# Threshold-promote route: writes ConfigRegistry only when quorum holds
# ---------------------------------------------------------------------------


async def _seed_active_proposal(
    outcome_kind: str, after_threshold: float,
) -> str:
    """Insert one ACTIVE :class:`CalibrationProposalRecord` and return its id."""
    row = CalibrationProposalRecord(
        outcome_kind=outcome_kind,
        before_threshold=0.6,
        after_threshold=after_threshold,
        approve_count=5,
        reject_count=5,
        mean_confidence_reject=0.8,
        mean_confidence_approve=0.7,
        reasoning="test seed",
        evidence_json="{}",
        status=CALIBRATION_STATUS_ACTIVE,
        actor="tester_seed",
    )
    async with async_session_scope() as session:
        session.add(row)
        await session.commit()
    return row.id


async def _read_threshold(outcome_kind: str) -> object:
    """Read the live threshold via ConfigRegistry, bypassing the cache."""
    registry = ConfigRegistry()
    return await registry.get(
        "platform", f"calibration_threshold_{outcome_kind}",
    )


async def test_threshold_promote_route_writes_config_when_quorum_holds(
    test_db,
) -> None:
    """The admin threshold-promote route flips ConfigRegistry only on quorum."""
    del test_db
    _invalidate_active_cache()
    outcome_kind = f"kind_{uuid4().hex[:6]}"
    target_after = 0.82
    proposal_id = await _seed_active_proposal(outcome_kind, target_after)
    await _set_promotion_quorum(2)
    from aila.api.limiter import limiter
    limiter_was_enabled = limiter.enabled
    limiter.enabled = False  # direct-invocation test: bypass slowapi Request check
    try:
        from aila.api.routers.admin_eval import (
            CalibrationProposalPromoteRequest,
            promote_calibration_proposal,
        )
        from aila.api.auth import AuthContext
        from aila.api.constants import ROLE_ADMIN
        from fastapi import HTTPException

        ctx = AuthContext(
            user_id="admin-user",
            role=ROLE_ADMIN,
            team_id=None,
            auth_type="user",
        )

        # Insufficient approvers -> refused, config untouched.
        with pytest.raises(HTTPException) as excinfo:
            await promote_calibration_proposal(
                request=None,  # rate limiter injects request only for its own use
                body=CalibrationProposalPromoteRequest(
                    approver_ids=["only_one"],
                ),
                proposal_id=proposal_id,
                ctx=ctx,
            )
        assert excinfo.value.status_code == 409
        assert "quorum_insufficient" in str(excinfo.value.detail)
        pre = await _read_threshold(outcome_kind)
        # Default float from the DynamicKeyFamily is 0.0 (schema seeded default);
        # the important assertion is it is NOT target_after.
        assert pre != pytest.approx(target_after)

        # Sufficient approvers -> config flipped to after_threshold.
        result = await promote_calibration_proposal(
            request=None,
            body=CalibrationProposalPromoteRequest(
                approver_ids=["a1", "a2", "a2"],  # two distinct
            ),
            proposal_id=proposal_id,
            ctx=ctx,
        )
        assert result.data.after_threshold == pytest.approx(target_after)
        assert result.data.config_key == f"calibration_threshold_{outcome_kind}"
        # Config now reads back as the promoted value.
        stored = await _read_threshold(outcome_kind)
        assert float(stored) == pytest.approx(target_after)
    finally:
        limiter.enabled = limiter_was_enabled
        await _set_promotion_quorum(
            PlatformConfigSchema().agent_promotion_quorum,
        )


# ---------------------------------------------------------------------------
# Sanity: the metrics ECE we import is the same one calibrator._ece_of uses.
# ---------------------------------------------------------------------------


def test_ece_of_matches_metrics_ece() -> None:
    """Guard against a silent drift between calibrator + metrics ECE."""
    samples = _overconfident_samples()
    from_metrics = _ece_metric(
        [c for c, _ in samples], [ok for _, ok in samples], n_buckets=10,
    )
    from_calibrator = _ece_of(samples, None)
    assert from_metrics == pytest.approx(from_calibrator)
