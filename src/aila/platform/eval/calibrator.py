"""Post-hoc confidence calibrator (RFC-08 Tier D / contracts C6 + C7).

The gate step (``aila.platform.llm.gate``) reads a raw ``confidence_score``
via :func:`extract_confidence`. That extractor still ships a
length-heuristic fallback for the case where the model omits the field;
the raw number is deliberately unopinionated. What the operator wants
is a NUMBER THAT MEANS SOMETHING -- ``0.8`` in truly ~80% of the cases
it fires on. The post-hoc :class:`Calibrator` is the piece that turns
the raw scalar into that operator-meaningful number: it fits from the
accept/reject review history the platform already writes (via
``DEFAULT_CALIBRATION_TABLES``), sits behind the gate, and is applied
AFTER :func:`extract_confidence` and BEFORE
``_map_confidence_level`` / ``_resolve_thresholds``. The extractor's
fallback is preserved verbatim -- the calibrator sits on top and
authoritatively shapes whatever number the extractor produced.

Two methods, both pure-Python + dependency-free:

* ``isotonic`` -- monotone non-decreasing PAV (pool-adjacent-violators)
  step-fit. Sort samples by raw confidence, then pool adjacent points
  until the empirical accuracy sequence is non-decreasing. The result
  is a piecewise-linear monotone map from raw -> calibrated, clamped
  to ``[0, 1]``.
* ``temperature`` -- single scalar T fit by grid search over a small
  grid of T values, minimizing NLL against the observed labels. Apply
  is ``sigmoid(logit(p) / T)`` with p clipped away from 0/1 to keep
  the logit finite. ``T=1`` = identity.

The trainer (:class:`CalibrationTrainer`) fits both, keeps the
lower-ECE method, and persists a ``status='candidate'``
:class:`CalibratorVersionRecord`. Promotion is the C7 gate:
:func:`promote_calibrator` demands eval-improvement (candidate ECE
strictly lower than the currently active) AND a distinct-approver
count at or above ``platform.agent_promotion_quorum``. Only then does
the row flip to ``'active'`` and the prior active row supersede.

Storage: :class:`CalibratorVersionRecord` (versioned journal) +
:class:`CalibrationScoreSample` (audit trail of the fit set). Both are
declared here so ``SQLModel.metadata`` registers them for the shared
test bootstrap; the alembic migration ``112_eval_calibrator`` creates
the same DDL on production.
"""
from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text
from sqlmodel import Field, SQLModel, select

from aila.platform.config import PlatformConfigSchema
from aila.platform.contracts import utc_now
from aila.platform.eval.calibration_sweep import (
    DEFAULT_CALIBRATION_TABLES,
    _read_samples_from_table_pair,
)
from aila.platform.eval.metrics import ece
from aila.storage.database import async_session_scope
from aila.storage.registry import ConfigRegistry

__all__ = [
    "CALIBRATOR_METHOD_ISOTONIC",
    "CALIBRATOR_METHOD_TEMPERATURE",
    "CALIBRATOR_STATUS_ACTIVE",
    "CALIBRATOR_STATUS_CANDIDATE",
    "CALIBRATOR_STATUS_SUPERSEDED",
    "Calibrator",
    "CalibratorPromotionError",
    "CalibratorVersionRecord",
    "CalibrationScoreSample",
    "CalibrationTrainer",
    "load_active_calibrator",
    "promote_calibrator",
]

_log = logging.getLogger(__name__)


CALIBRATOR_METHOD_ISOTONIC: str = "isotonic"
CALIBRATOR_METHOD_TEMPERATURE: str = "temperature"

CALIBRATOR_STATUS_CANDIDATE: str = "candidate"
CALIBRATOR_STATUS_ACTIVE: str = "active"
CALIBRATOR_STATUS_SUPERSEDED: str = "superseded"

_VALID_METHODS: frozenset[str] = frozenset({
    CALIBRATOR_METHOD_ISOTONIC,
    CALIBRATOR_METHOD_TEMPERATURE,
})

# Approve/reject vote literals. Duplicated instead of imported from
# ``aila.platform.services.outcome_review`` to sidestep the load-time
# cycle documented in :mod:`aila.platform.eval.calibration`
# (``services/__init__ -> audit -> journal -> db_models -> eval.models``).
_VOTE_APPROVE: str = "approve"
_VOTE_REJECT: str = "reject"

# Temperature grid used by ``Calibrator.fit(..., method='temperature')``.
# Small, ordered, and includes 1.0 so a well-calibrated feed collapses
# to identity. Grid over log-space so overconfidence (T > 1) and
# underconfidence (T < 1) are covered symmetrically.
_TEMPERATURE_GRID: tuple[float, ...] = (
    0.25, 0.4, 0.5, 0.65, 0.8, 1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 4.0, 6.0,
)

# Clip epsilon for logit / NLL so ``logit(0)`` / ``logit(1)`` do not
# blow to +/-inf. Matches the standard scikit-learn choice.
_PROB_EPS: float = 1e-7

# ECE bucket count used by the trainer + promotion gate. Matches the
# metrics-module default so a fitted calibrator is scored against the
# same reliability diagram the eval runner uses.
_ECE_BUCKETS: int = 10

# In-memory cache TTL for :func:`load_active_calibrator`. The gate
# reads on every LLM call; a per-call DB round trip would be silly.
# TTL is small so a promote-through-the-admin-route change lands in a
# minute across peers even without an explicit invalidation hop.
_ACTIVE_CACHE_TTL_S: float = 60.0

_ACTIVE_CACHE: dict[str, tuple[float, Calibrator | None]] = {}
_ACTIVE_CACHE_LOCK = asyncio.Lock()


# ---------------------------------------------------------------------------
# Storage records
# ---------------------------------------------------------------------------


class CalibratorVersionRecord(SQLModel, table=True):
    """One fitted calibrator snapshot for a ``task_type``.

    Rows are append-only. ``status`` starts at
    :data:`CALIBRATOR_STATUS_CANDIDATE`; promotion via
    :func:`promote_calibrator` flips it to :data:`CALIBRATOR_STATUS_ACTIVE`
    and marks the prior active row for the same ``task_type``
    :data:`CALIBRATOR_STATUS_SUPERSEDED` with ``superseded_by`` pointing
    at the new row. The chain is the audit trail: nothing is ever
    updated in place except the status + supersede pair on the row
    that just fell off active.
    """

    __tablename__ = "eval_calibrator_versions"
    __table_args__ = (
        Index("ix_eval_calibrator_versions_task_status", "task_type", "status"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    task_type: str = Field(max_length=64, index=True)
    method: str = Field(max_length=32)
    params_json: str = Field(default="{}", sa_type=Text)
    ece_before: float = Field(default=0.0)
    ece_after: float = Field(default=0.0)
    sample_count: int = Field(default=0)
    status: str = Field(
        default=CALIBRATOR_STATUS_CANDIDATE, max_length=16,
    )
    superseded_by: str | None = Field(default=None, max_length=64)
    actor: str = Field(default="", max_length=128)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class CalibrationScoreSample(SQLModel, table=True):
    """One ``(raw_confidence, correct)`` fit sample assembled post-hoc.

    Written by :func:`CalibrationTrainer.fit_and_propose`, not by the
    gate. Kept as an audit trail so a later replay can rebuild the
    exact fit set that produced a given :class:`CalibratorVersionRecord`
    -- calibrator drift is traceable end-to-end.
    """

    __tablename__ = "eval_calibration_samples"
    __table_args__ = (
        Index(
            "ix_eval_calibration_samples_task_created",
            "task_type", "created_at",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    task_type: str = Field(max_length=64, index=True)
    outcome_kind: str = Field(default="", max_length=64)
    model_id: str = Field(default="", max_length=128)
    raw_confidence: float = Field(default=0.0)
    correct: bool = Field(default=False)
    outcome_id: str | None = Field(default=None, max_length=64)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class CalibratorPromotionError(RuntimeError):
    """Raised when :func:`promote_calibrator` refuses the flip.

    Carries the specific gap named ('ece_no_improvement' or
    'quorum_insufficient') plus the observed values so the operator UI
    surfaces the reason without a second round trip.
    """


# ---------------------------------------------------------------------------
# Pure Calibrator
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _IsotonicKnots:
    """Piecewise-linear monotone step-fit produced by PAV.

    ``xs`` is the sorted list of distinct raw-confidence knot inputs,
    ``ys`` the corresponding calibrated outputs. ``Calibrator.apply``
    linearly interpolates between adjacent knots and extrapolates flat
    outside the fit range, so the output is monotone and bounded.
    """

    xs: tuple[float, ...]
    ys: tuple[float, ...]


class Calibrator:
    """Post-hoc monotone recalibrator.

    Immutable once fitted. ``apply(raw) -> float`` returns the
    calibrated confidence clamped to ``[0, 1]``. ``to_params`` /
    :meth:`from_params` round-trip through JSON so the fitted state is
    persistable via :class:`CalibratorVersionRecord.params_json`.
    """

    __slots__ = ("_method", "_knots", "_temperature")

    def __init__(
        self,
        *,
        method: str,
        knots: _IsotonicKnots | None = None,
        temperature: float | None = None,
    ) -> None:
        if method not in _VALID_METHODS:
            raise ValueError(f"unknown calibrator method: {method!r}")
        if method == CALIBRATOR_METHOD_ISOTONIC and knots is None:
            raise ValueError("isotonic calibrator requires fitted knots")
        if method == CALIBRATOR_METHOD_TEMPERATURE and temperature is None:
            raise ValueError("temperature calibrator requires fitted T")
        self._method = method
        self._knots = knots
        self._temperature = temperature

    @property
    def method(self) -> str:
        return self._method

    @property
    def temperature(self) -> float | None:
        return self._temperature

    @classmethod
    def from_identity(cls) -> Calibrator:
        """A no-op temperature calibrator (T = 1) -- ``apply(x) == x``.

        Used as the safe fallback in :meth:`fit` (empty samples) and
        :meth:`from_params` (malformed / unknown method payload) so the
        gate stays raw-passthrough instead of silently mis-calibrating.
        """
        return cls(method=CALIBRATOR_METHOD_TEMPERATURE, temperature=1.0)

    @classmethod
    def fit(
        cls,
        samples: Sequence[tuple[float, bool]],
        method: str,
    ) -> Calibrator:
        """Fit ``method`` to ``samples`` and return the calibrator.

        ``samples`` is a sequence of ``(raw_confidence, correct)``
        tuples. An empty or degenerate set collapses to identity so
        the trainer never persists an "everything is broken" fit.
        """
        clean: list[tuple[float, bool]] = []
        for raw, correct in samples:
            raw_f = _clip_prob(float(raw))
            clean.append((raw_f, bool(correct)))
        if not clean:
            return cls.from_identity()

        if method == CALIBRATOR_METHOD_ISOTONIC:
            knots = _fit_isotonic(clean)
            return cls(method=method, knots=knots)
        if method == CALIBRATOR_METHOD_TEMPERATURE:
            temperature = _fit_temperature(clean)
            return cls(method=method, temperature=temperature)
        raise ValueError(f"unknown calibrator method: {method!r}")

    def apply(self, raw: float) -> float:
        """Return the calibrated confidence for ``raw`` in ``[0, 1]``."""
        raw_f = _clip_prob(float(raw))
        if self._method == CALIBRATOR_METHOD_ISOTONIC:
            knots = self._knots
            if knots is None:
                return raw_f
            out = _apply_isotonic(knots, raw_f)
        else:
            temperature = self._temperature or 1.0
            out = _apply_temperature(raw_f, temperature)
        # Defensive clamp -- both branches produce values in [0, 1] but
        # a rounding sliver at the edges should never leak downstream.
        if out < 0.0:
            return 0.0
        if out > 1.0:
            return 1.0
        return out

    def to_params(self) -> dict[str, Any]:
        """Return the fitted state as a JSON-serializable dict."""
        if self._method == CALIBRATOR_METHOD_ISOTONIC:
            knots = self._knots
            return {
                "method": self._method,
                "knots": {
                    "xs": list(knots.xs) if knots else [],
                    "ys": list(knots.ys) if knots else [],
                },
            }
        return {
            "method": self._method,
            "temperature": self._temperature or 1.0,
        }

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> Calibrator:
        """Rebuild a calibrator from :meth:`to_params` output.

        Unknown / malformed payloads collapse to identity so a corrupt
        row in ``params_json`` cannot brick the gate: it degrades to
        raw-passthrough behavior and logs the parse failure.
        """
        method = str(params.get("method") or "")
        if method == CALIBRATOR_METHOD_ISOTONIC:
            knots_raw = params.get("knots") or {}
            xs_raw = knots_raw.get("xs") if isinstance(knots_raw, dict) else []
            ys_raw = knots_raw.get("ys") if isinstance(knots_raw, dict) else []
            try:
                xs = tuple(float(x) for x in (xs_raw or []))
                ys = tuple(float(y) for y in (ys_raw or []))
            except (TypeError, ValueError):
                _log.warning(
                    "Calibrator.from_params: malformed isotonic knots, "
                    "returning identity",
                )
                return cls.from_identity()
            if not xs or len(xs) != len(ys):
                return cls.from_identity()
            return cls(
                method=method,
                knots=_IsotonicKnots(xs=xs, ys=ys),
            )
        if method == CALIBRATOR_METHOD_TEMPERATURE:
            try:
                temperature = float(params.get("temperature") or 1.0)
            except (TypeError, ValueError):
                _log.warning(
                    "Calibrator.from_params: malformed temperature, "
                    "returning identity",
                )
                return cls.from_identity()
            if temperature <= 0.0:
                return cls.from_identity()
            return cls(method=method, temperature=temperature)
        _log.debug(
            "Calibrator.from_params: unknown method %r; returning identity",
            method,
        )
        return cls.from_identity()


# ---------------------------------------------------------------------------
# Pure fit helpers
# ---------------------------------------------------------------------------


def _clip_prob(raw: float) -> float:
    """Clamp a probability to ``[0, 1]`` with a small epsilon guard.

    The epsilon guard is only applied INSIDE the logit call; the
    return here is the tight clamp so the calibrator's audit trail
    (``params_json``, gate metadata) stays free of magic epsilons.
    """
    if raw != raw:  # NaN
        return 0.0
    if raw < 0.0:
        return 0.0
    if raw > 1.0:
        return 1.0
    return raw


def _logit(p: float) -> float:
    """Numerically-stable logit with epsilon clipping."""
    p_clipped = min(1.0 - _PROB_EPS, max(_PROB_EPS, p))
    return math.log(p_clipped / (1.0 - p_clipped))


def _sigmoid(x: float) -> float:
    """Numerically-stable logistic sigmoid."""
    if x >= 0.0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def _fit_isotonic(
    samples: Sequence[tuple[float, bool]],
) -> _IsotonicKnots:
    """Pool-adjacent-violators (PAV) monotone regression.

    Groups samples by identical ``raw`` value first (deterministic:
    ties collapse to their pooled mean accuracy), then walks the
    sorted sequence pooling any left neighbour whose mean is higher
    than the current so the resulting knot values are non-decreasing.
    """
    if not samples:
        return _IsotonicKnots(xs=(), ys=())
    grouped: dict[float, list[bool]] = {}
    for raw, correct in samples:
        grouped.setdefault(raw, []).append(correct)
    xs_sorted = sorted(grouped)
    # Each "block" is (sum_correct, weight, x_of_block). Walk left-to-right;
    # merge any block whose mean is strictly less than the previous.
    blocks: list[list[float]] = []
    for x in xs_sorted:
        outcomes = grouped[x]
        weight = float(len(outcomes))
        total = float(sum(1 for c in outcomes if c))
        blocks.append([total, weight, x])
        while len(blocks) >= 2 and (
            blocks[-2][0] / blocks[-2][1] > blocks[-1][0] / blocks[-1][1]
        ):
            merged_total = blocks[-2][0] + blocks[-1][0]
            merged_weight = blocks[-2][1] + blocks[-1][1]
            # Pooling keeps the LEFT block's x -- the calibrated value at
            # the smaller raw input is the pooled mean; the higher raw
            # input takes the same value (still monotone at the tie).
            blocks[-2] = [merged_total, merged_weight, blocks[-2][2]]
            blocks.pop()
    xs: list[float] = []
    ys: list[float] = []
    for total, weight, x in blocks:
        xs.append(x)
        ys.append(total / weight)
    return _IsotonicKnots(xs=tuple(xs), ys=tuple(ys))


def _apply_isotonic(knots: _IsotonicKnots, raw: float) -> float:
    """Piecewise-linear interpolate ``raw`` against the fitted knots.

    Extrapolation is flat: below ``xs[0]`` returns ``ys[0]``; above
    ``xs[-1]`` returns ``ys[-1]``. Empty knots return raw unchanged.
    """
    xs = knots.xs
    ys = knots.ys
    if not xs:
        return raw
    if raw <= xs[0]:
        return ys[0]
    if raw >= xs[-1]:
        return ys[-1]
    # Binary search for the interval [xs[i], xs[i+1]] containing raw.
    lo, hi = 0, len(xs) - 1
    while lo < hi - 1:
        mid = (lo + hi) // 2
        if xs[mid] <= raw:
            lo = mid
        else:
            hi = mid
    x0, x1 = xs[lo], xs[hi]
    y0, y1 = ys[lo], ys[hi]
    if x1 == x0:
        return y0
    return y0 + (y1 - y0) * (raw - x0) / (x1 - x0)


def _fit_temperature(
    samples: Sequence[tuple[float, bool]],
) -> float:
    """Grid-search the temperature scalar that minimizes NLL.

    Applies ``sigmoid(logit(p) / T)`` per sample. NLL is the negative
    log-likelihood of the observed 0/1 correctness under the calibrated
    probabilities. Ties in NLL prefer T=1 (identity) so a
    near-well-calibrated feed does not chase a noisy grid minimum.
    """
    if not samples:
        return 1.0
    best_t = 1.0
    best_nll = _nll_at_temperature(samples, 1.0)
    for t in _TEMPERATURE_GRID:
        if t <= 0.0 or t == 1.0:
            continue
        nll = _nll_at_temperature(samples, t)
        if nll + 1e-9 < best_nll:
            best_nll = nll
            best_t = t
    return best_t


def _apply_temperature(raw: float, temperature: float) -> float:
    """Apply ``sigmoid(logit(raw) / T)``. T <= 0 collapses to identity."""
    if temperature <= 0.0 or temperature == 1.0:
        return raw
    return _sigmoid(_logit(raw) / temperature)


def _nll_at_temperature(
    samples: Sequence[tuple[float, bool]],
    temperature: float,
) -> float:
    """Mean negative log-likelihood of ``samples`` at scaled temperature."""
    n = len(samples)
    if n == 0:
        return 0.0
    total = 0.0
    for raw, correct in samples:
        p = _apply_temperature(raw, temperature)
        p_clipped = min(1.0 - _PROB_EPS, max(_PROB_EPS, p))
        if correct:
            total -= math.log(p_clipped)
        else:
            total -= math.log(1.0 - p_clipped)
    return total / n


def _ece_of(
    samples: Sequence[tuple[float, bool]],
    calibrator: Calibrator | None,
) -> float:
    """Expected calibration error of ``samples`` under ``calibrator``.

    ``None`` = identity (raw scores). Reuses :func:`ece` from
    ``platform.eval.metrics`` so the reliability diagram is bucketed
    identically to the runner.
    """
    if not samples:
        return 0.0
    if calibrator is None:
        confs = [raw for raw, _ in samples]
    else:
        confs = [calibrator.apply(raw) for raw, _ in samples]
    correct = [c for _, c in samples]
    return ece(confs, correct, n_buckets=_ECE_BUCKETS)


# ---------------------------------------------------------------------------
# Trainer + active loader + promotion gate
# ---------------------------------------------------------------------------


class CalibrationTrainer:
    """Assemble fit samples, fit both methods, persist a candidate row.

    Instances are cheap; construct one per invocation. Kept as a class
    (not a bare function) so a future test can inject a fake sample
    source without wiring env vars.
    """

    def __init__(
        self,
        *,
        table_pairs: Sequence[tuple[str, str]] | None = None,
        sample_cap: int = 5000,
        window_days: int = 90,
    ) -> None:
        self._table_pairs = (
            tuple(table_pairs)
            if table_pairs is not None
            else DEFAULT_CALIBRATION_TABLES
        )
        self._sample_cap = int(sample_cap)
        self._window_days = int(window_days)

    async def _read_samples(
        self, task_type: str,
    ) -> tuple[list[tuple[float, bool]], list[tuple[str, str, float, bool]]]:
        """Read raw (raw_conf, correct) tuples from review history.

        Returns ``(fit_tuples, audit_tuples)`` where the audit tuples
        carry the extra ``(outcome_kind, verdict, raw_conf, correct)``
        fields the :class:`CalibrationScoreSample` audit trail needs.
        The task_type argument scopes the persisted audit rows; the
        fit set aggregates every accept/reject sample the sweep tables
        expose (per-task-type routing metadata is not on the review
        row itself, so the aggregated feed IS the per-model
        calibration signal).
        """
        del task_type  # audit tuples are stamped with the task_type upstream
        cutoff = datetime.now(UTC) - timedelta(days=self._window_days)
        fit: list[tuple[float, bool]] = []
        audit: list[tuple[str, str, float, bool]] = []
        for outcome_table, review_table in self._table_pairs:
            samples = await _read_samples_from_table_pair(
                outcome_table, review_table,
                cutoff=cutoff, sample_cap=self._sample_cap,
            )
            for sample in samples:
                if sample.verdict not in {_VOTE_APPROVE, _VOTE_REJECT}:
                    continue
                correct = sample.verdict == _VOTE_APPROVE
                fit.append((float(sample.confidence), correct))
                audit.append((
                    sample.outcome_kind, sample.verdict,
                    float(sample.confidence), correct,
                ))
        return fit, audit

    async def _persist_audit(
        self,
        task_type: str,
        audit: Iterable[tuple[str, str, float, bool]],
    ) -> int:
        """Insert :class:`CalibrationScoreSample` rows for the fit set.

        The rows are non-authoritative -- they exist so a later replay
        can rebuild the exact fit set that produced a version row.
        Failures are logged and swallowed: the fit run itself is
        allowed to succeed even when the audit-trail write blows up
        (best-effort, matches the sweep-side isolation posture).
        """
        rows: list[CalibrationScoreSample] = []
        for outcome_kind, _verdict, raw_conf, correct in audit:
            rows.append(CalibrationScoreSample(
                task_type=task_type,
                outcome_kind=outcome_kind,
                model_id="",
                raw_confidence=raw_conf,
                correct=correct,
            ))
        if not rows:
            return 0
        try:
            async with async_session_scope() as session:
                for row in rows:
                    session.add(row)
                await session.commit()
        except (RuntimeError, ValueError, TypeError, OSError) as exc:
            _log.warning(
                "CalibrationTrainer: audit-trail write failed for "
                "task_type=%s (%s); fit continues",
                task_type, type(exc).__name__, exc_info=exc,
            )
            return 0
        return len(rows)

    async def fit_and_propose(
        self,
        task_type: str,
        *,
        actor: str = "platform.calibration_trainer",
    ) -> CalibratorVersionRecord:
        """Read history, fit both methods, persist a candidate row.

        Raises :class:`ValueError` when ``task_type`` is empty; a fit
        run with no ``task_type`` scope is a misconfiguration
        (candidate rows key on it for the active loader).
        """
        if not task_type.strip():
            raise ValueError("task_type must be non-empty")

        fit_samples, audit = await self._read_samples(task_type)
        sample_count = len(fit_samples)

        ece_before = _ece_of(fit_samples, None)
        best_method = CALIBRATOR_METHOD_TEMPERATURE
        best_calibrator = Calibrator.from_identity()
        best_ece = ece_before

        for method in (
            CALIBRATOR_METHOD_ISOTONIC, CALIBRATOR_METHOD_TEMPERATURE,
        ):
            candidate = Calibrator.fit(fit_samples, method)
            candidate_ece = _ece_of(fit_samples, candidate)
            # Tie-breaker: prefer temperature (single scalar, cheaper +
            # more robust to overfitting on a tiny fit set) over isotonic
            # when the ECE gap is within the epsilon.
            if candidate_ece + 1e-9 < best_ece or (
                abs(candidate_ece - best_ece) < 1e-9
                and method == CALIBRATOR_METHOD_TEMPERATURE
                and best_method != CALIBRATOR_METHOD_TEMPERATURE
            ):
                best_method = method
                best_calibrator = candidate
                best_ece = candidate_ece

        await self._persist_audit(task_type, audit)

        params = best_calibrator.to_params()
        row = CalibratorVersionRecord(
            task_type=task_type,
            method=best_method,
            params_json=json.dumps(params, sort_keys=True),
            ece_before=ece_before,
            ece_after=best_ece,
            sample_count=sample_count,
            status=CALIBRATOR_STATUS_CANDIDATE,
            actor=actor,
        )
        async with async_session_scope() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
        _log.info(
            "CalibrationTrainer: persisted candidate id=%s task_type=%s "
            "method=%s ece_before=%.4f ece_after=%.4f n=%d",
            row.id, task_type, best_method,
            ece_before, best_ece, sample_count,
        )
        return row


async def load_active_calibrator(task_type: str) -> Calibrator | None:
    """Return the active :class:`Calibrator` for ``task_type`` or ``None``.

    Cached in-process for :data:`_ACTIVE_CACHE_TTL_S` seconds so the
    gate's per-call read costs no more than one atomic dict lookup
    inside the window. ``None`` is a first-class cached value: a
    task_type with no active row still hits the cache instead of
    firing a DB round-trip on every LLM call.
    """
    if not task_type:
        return None
    now = time.monotonic()
    cached = _ACTIVE_CACHE.get(task_type)
    if cached is not None and (now - cached[0]) < _ACTIVE_CACHE_TTL_S:
        return cached[1]

    async with _ACTIVE_CACHE_LOCK:
        cached = _ACTIVE_CACHE.get(task_type)
        if cached is not None and (now - cached[0]) < _ACTIVE_CACHE_TTL_S:
            return cached[1]
        try:
            async with async_session_scope() as session:
                stmt = (
                    select(CalibratorVersionRecord)
                    .where(
                        CalibratorVersionRecord.task_type == task_type,
                        CalibratorVersionRecord.status
                        == CALIBRATOR_STATUS_ACTIVE,
                    )
                    .order_by(
                        CalibratorVersionRecord.created_at.desc(),  # type: ignore[attr-defined]
                    )
                    .limit(1)
                )
                row = (await session.exec(stmt)).first()
        except (OSError, RuntimeError, ValueError) as exc:
            _log.warning(
                "load_active_calibrator: DB read failed for task_type=%s "
                "(%s); returning raw-passthrough",
                task_type, type(exc).__name__, exc_info=exc,
            )
            return None
        calibrator: Calibrator | None
        if row is None:
            calibrator = None
        else:
            try:
                params = json.loads(row.params_json or "{}")
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                _log.warning(
                    "load_active_calibrator: params_json for id=%s malformed "
                    "(%s); returning raw-passthrough",
                    row.id, type(exc).__name__, exc_info=exc,
                )
                calibrator = None
            else:
                calibrator = Calibrator.from_params(params)
        _ACTIVE_CACHE[task_type] = (now, calibrator)
        return calibrator


def _invalidate_active_cache(task_type: str | None = None) -> None:
    """Drop cached active calibrators.

    Called at the end of :func:`promote_calibrator` so a promotion
    takes effect on the next gate read without waiting out the TTL.
    ``None`` clears every task type -- used by tests.
    """
    if task_type is None:
        _ACTIVE_CACHE.clear()
        return
    _ACTIVE_CACHE.pop(task_type, None)


async def _resolve_promotion_quorum() -> int:
    """Read ``platform.agent_promotion_quorum`` via ConfigRegistry.

    Env -> cache -> DB -> :class:`PlatformConfigSchema` default. Any
    resolver failure falls back to the schema default so a bad DB row
    cannot silently disable the quorum gate. Values below zero clamp
    to zero (eval-only gate).
    """
    default = PlatformConfigSchema().agent_promotion_quorum
    try:
        raw = await ConfigRegistry().get(
            "platform", "agent_promotion_quorum",
        )
    except (OSError, RuntimeError, ValueError, TypeError):
        return default
    if raw is None:
        return default
    try:
        threshold = int(raw)
    except (TypeError, ValueError):
        return default
    return max(0, threshold)


async def promote_calibrator(
    version_id: str,
    *,
    actor: str,
    quorum_approver_ids: Sequence[str],
) -> CalibratorVersionRecord:
    """Flip ``version_id`` to active behind the eval + quorum gate.

    Two gates, both must clear:

    1. ECE-improvement: the candidate row's ``ece_after`` must be
       strictly lower than the currently-active row's ``ece_after``
       for the same ``task_type``. When no active row exists the
       candidate ships (there is nothing to regress against) -- the
       first promoted calibrator is always the first improvement.
    2. Quorum: ``len(set(quorum_approver_ids))`` (distinct approvers)
       must be at least :func:`_resolve_promotion_quorum`. Two
       identical actor strings count as one approver -- same rule the
       RFC-10 lifecycle promotion applies.

    Raises :class:`CalibratorPromotionError` on either gate miss with
    the specific gap named; the row is left untouched. On success:
    the candidate flips to :data:`CALIBRATOR_STATUS_ACTIVE`, the prior
    active row (if any) flips to :data:`CALIBRATOR_STATUS_SUPERSEDED`
    with ``superseded_by`` pointing at the new row, and the
    in-process active cache is invalidated for the task_type so the
    next gate read sees the new row.
    """
    if not version_id:
        raise CalibratorPromotionError("version_id must be non-empty")

    async with async_session_scope() as session:
        # Issue #202: FOR UPDATE on the candidate + active rows so
        # two concurrent promoters for the same task_type cannot
        # both pass the eval gate and both flip ACTIVE. The second
        # promoter blocks on the row lock, then re-reads the (now
        # SUPERSEDED) candidate status and raises the "not
        # candidate" gap instead of double-activating.
        candidate = (await session.exec(
            select(CalibratorVersionRecord)
            .where(CalibratorVersionRecord.id == version_id)
            .with_for_update(),
        )).first()
        if candidate is None:
            raise CalibratorPromotionError(
                f"calibrator version {version_id!r} not found",
            )
        if candidate.status == CALIBRATOR_STATUS_ACTIVE:
            # Idempotent: already promoted, nothing to do.
            return candidate
        if candidate.status != CALIBRATOR_STATUS_CANDIDATE:
            raise CalibratorPromotionError(
                f"calibrator version {version_id!r} is "
                f"{candidate.status!r}, not candidate",
            )

        # Gate 1: eval improvement. FOR UPDATE on the active row
        # (issue #202) pairs with the candidate lock above so both
        # rows this promotion touches are held for the whole
        # transaction; a concurrent promoter for the same task_type
        # blocks here rather than racing the flip below.
        active_stmt = (
            select(CalibratorVersionRecord)
            .where(
                CalibratorVersionRecord.task_type == candidate.task_type,
                CalibratorVersionRecord.status == CALIBRATOR_STATUS_ACTIVE,
            )
            .with_for_update()
        )
        current_active = (await session.exec(active_stmt)).first()
        if current_active is not None and not (
            candidate.ece_after + 1e-9 < current_active.ece_after
        ):
            raise CalibratorPromotionError(
                "ece_no_improvement: candidate ece_after "
                f"{candidate.ece_after:.4f} does not beat active "
                f"{current_active.ece_after:.4f} for task_type="
                f"{candidate.task_type!r}",
            )

        # Gate 2: quorum.
        distinct = {a for a in quorum_approver_ids if a}
        required = await _resolve_promotion_quorum()
        if len(distinct) < required:
            raise CalibratorPromotionError(
                f"quorum_insufficient: {len(distinct)} distinct approver(s) "
                f"< required {required} for task_type="
                f"{candidate.task_type!r}",
            )

        # Both gates cleared. Flip the rows.
        if current_active is not None:
            current_active.status = CALIBRATOR_STATUS_SUPERSEDED
            current_active.superseded_by = candidate.id
            session.add(current_active)
        candidate.status = CALIBRATOR_STATUS_ACTIVE
        candidate.actor = actor or candidate.actor
        session.add(candidate)
        await session.commit()
        await session.refresh(candidate)

    _invalidate_active_cache(candidate.task_type)
    _log.info(
        "promote_calibrator: activated id=%s task_type=%s ece=%.4f "
        "(prev active=%s)",
        candidate.id, candidate.task_type, candidate.ece_after,
        current_active.id if current_active is not None else "none",
    )
    return candidate
