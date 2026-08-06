"""Periodic calibration proposal sweep (RFC-08 step 2 -- wiring).

Aggregates recent accept/reject review history per ``outcome_kind``
across the module-owned investigation-outcome + review tables and turns
it into versioned :class:`CalibrationProposalRecord` rows via
:class:`CalibrationProposer`.

Contract: PROPOSAL, NEVER APPLICATION. The sweep only writes rows into
``eval_calibration_proposals`` (migration 097). No live threshold value
is mutated -- promoting a proposal's ``after_threshold`` into the
module's runtime confidence gate is a separate, gated admin action that
must reference :class:`CalibrationProposalRecord` in the same body per
honesty audit rule 57 (``unversioned_config_promotion``). No such admin
route ships in this codebase yet; when it lands it will read the most
recent ACTIVE row and update the module's ``ConfigRegistry`` entry.

Wired as an :class:`AutomationAction` in
:func:`aila.platform.automation.maintenance.register_maintenance_actions`
so an operator schedules the cadence via the standard automation
surface (``POST /automation/schedules`` with
``action_id='platform.calibration_proposer_sweep'``). Until scheduled,
the registration alone does not run the sweep -- mirroring the
``platform.tool_storage_prune`` model.

Not decorated with :func:`@platform_task` per the runner-owned bare-
callable path (DESIGN section 3.6 in
``platform/automation/maintenance.py``) and to avoid the ``__name__``
collision documented in CLAUDE.md common mistake 19.
"""
from __future__ import annotations

__all__ = [
    "CalibrationSweepReport",
    "CalibratorTrainerSweepReport",
    "DEFAULT_CALIBRATION_TABLES",
    "run_calibration_sweep",
    "run_calibrator_trainer_sweep",
]

import logging
from datetime import UTC, datetime, timedelta
from typing import TypedDict

import sqlalchemy.exc
from sqlalchemy import text
from sqlmodel import select

from aila.platform.contracts.enums import OutcomeConfidence
from aila.platform.eval.calibration import (
    CALIBRATION_STATUS_ACTIVE,
    CalibrationProposalRecord,
    CalibrationProposer,
    CalibrationSample,
)
from aila.storage.database import async_session_scope

_log = logging.getLogger(__name__)


# Enum-to-float bridge for :class:`OutcomeConfidence`. Mirrors the
# module-side ``_ENUM_CONFIDENCE`` constant in
# ``aila.modules.vr.masvs.verdict_mapper`` so a sample the platform
# sweep synthesises carries the same float the MASVS mapper feeds when
# the same outcome hits its finding-confidence floor. Duplicated (not
# imported) because platform code MUST NOT import from ``aila.modules.*``
# (docs/GOLDEN_RULES.md #5 -- ownership boundary).
_ENUM_CONFIDENCE_FLOAT: dict[str, float] = {
    OutcomeConfidence.EXACT.value: 1.0,
    OutcomeConfidence.STRONG.value: 0.85,
    OutcomeConfidence.MEDIUM.value: 0.6,
    OutcomeConfidence.CAVEATED.value: 0.3,
    OutcomeConfidence.UNKNOWN.value: 0.6,
}

# Concrete ``(outcome_table, review_table)`` pairs the sweep aggregates
# by default. Every entry MUST be a platform-known module table; the
# raw-SQL join below interpolates the names into a :func:`text` string
# via f-string, so the allowlist is the primary safety layer.
# ``_is_safe_table_name`` is the second-order gate that refuses anything
# but a plain snake_case identifier -- a rogue caller cannot slip a
# payload past by rearranging the allowlist.
DEFAULT_CALIBRATION_TABLES: tuple[tuple[str, str], ...] = (
    ("vr_investigation_outcomes", "vr_outcome_reviews"),
    ("malware_investigation_outcomes", "malware_outcome_reviews"),
    ("forensics_investigation_outcomes", "forensics_outcome_reviews"),
)

# Character set accepted by the table-name gate below. Snake_case
# identifiers only; explicit dash/space/dot rejection keeps the surface
# tight.
_SAFE_TABLE_CHARS: frozenset[str] = frozenset(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789_",
)

# Defaults for the tunable knobs. Kept as module constants so the
# ``action_kwargs_json`` shape below stays small (operator only sets a
# knob when overriding the default). ``_DEFAULT_THRESHOLD`` matches
# ``_FINDING_CONFIDENCE_FLOOR`` in the MASVS verdict mapper -- the
# platform's canonical "worth reporting" floor for a finding.
_DEFAULT_WINDOW_DAYS: int = 30
_DEFAULT_SAMPLE_CAP: int = 5000
_DEFAULT_MIN_EVIDENCE: int = 10
_DEFAULT_MARGIN: float = 0.05
_DEFAULT_THRESHOLD: float = 0.6

_ACTOR: str = "platform.calibration_sweep"

# Isolation tuple for the sweep's failure modes. Same posture as
# :func:`aila.platform.tools.pruner.prune_tool_storage`: any realistic
# infra fault on the read / propose / persist path is captured so a
# single kind's failure does not abort the whole sweep. Bare
# ``except Exception`` is banned by honesty audit rule 33; every
# reachable failure class is enumerated. BaseException-only subclasses
# (``KeyboardInterrupt``, ``SystemExit``, ``asyncio.CancelledError``)
# propagate on purpose so a shutdown is not swallowed.
_SWEEP_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    TimeoutError,
    RuntimeError,
    ValueError,
    TypeError,
    KeyError,
    AttributeError,
    LookupError,
    ArithmeticError,
    ConnectionError,
)


class CalibrationSweepReport(TypedDict):
    """Structured result of one ``run_calibration_sweep`` invocation.

    Every field is always populated (0 when a half was empty) so
    downstream consumers can rely on the shape without ``.get`` guards.
    ``errors`` names the failed stage plus the exception class -- full
    tracebacks land in the worker log via ``_log.warning(exc_info=exc)``.
    """

    kinds_seen: int
    samples_read: int
    proposals_persisted: int
    kinds_below_min_evidence: int
    errors: list[str]


def _is_safe_table_name(name: str) -> bool:
    """Reject anything but a plain snake_case identifier.

    Guards the raw-SQL interpolation below. Table names are code-owned
    (the ``DEFAULT_CALIBRATION_TABLES`` allowlist or an
    ``action_kwargs_json`` override written by an admin), but the guard
    makes the SQL construction site self-contained: a rogue caller
    cannot slip a payload past by reaching around the allowlist.
    """
    if not name or len(name) > 64:
        return False
    return all(c in _SAFE_TABLE_CHARS for c in name)


def _confidence_to_float(raw: str | None) -> float:
    """Map an :class:`OutcomeConfidence` string to a ``[0, 1]`` float.

    Unknown / null strings fall back to :data:`_DEFAULT_THRESHOLD` so a
    sparsely-populated ``confidence`` column doesn't discard the sample
    outright -- the proposer still sees the vote and the accept/reject
    axis of the signal even if the numeric axis is missing.
    """
    if raw is None:
        return _DEFAULT_THRESHOLD
    return _ENUM_CONFIDENCE_FLOAT.get(raw.lower(), _DEFAULT_THRESHOLD)


def _coerce_int(raw: object, default: int) -> int:
    """Best-effort int cast for schedule-supplied kwargs.

    Missing / null / non-numeric values fall back to ``default`` so a
    hand-edited ``action_kwargs_json`` cannot crash the sweep.
    """
    if raw is None:
        return default
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


def _coerce_float(raw: object, default: float) -> float:
    """Best-effort float cast, same policy as :func:`_coerce_int`."""
    if raw is None:
        return default
    try:
        return float(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def _coerce_pairs(
    raw: object,
) -> tuple[tuple[str, str], ...]:
    """Validate an operator-supplied ``table_pairs`` override.

    Accepts a list of ``[outcome_table, review_table]`` two-tuples;
    rejects anything else so the default allowlist stays authoritative
    on a malformed override.
    """
    if not isinstance(raw, list) or not raw:
        return DEFAULT_CALIBRATION_TABLES
    out: list[tuple[str, str]] = []
    for pair in raw:
        if not isinstance(pair, (list, tuple)) or len(pair) != 2:
            continue
        outcome_table, review_table = str(pair[0]), str(pair[1])
        if _is_safe_table_name(outcome_table) and _is_safe_table_name(
            review_table,
        ):
            out.append((outcome_table, review_table))
    return tuple(out) if out else DEFAULT_CALIBRATION_TABLES


async def _current_threshold(outcome_kind: str) -> float:
    """Look up the current in-production threshold for ``outcome_kind``.

    Resolution order:
      1. Most-recent ACTIVE :class:`CalibrationProposalRecord`
         ``after_threshold`` for this kind -- the sweep converges on its
         own history over successive ticks.
      2. Fall back to :data:`_DEFAULT_THRESHOLD` (0.6) when no proposal
         has ever been written for this kind.

    Kept side-effect-free so the proposer's per-kind ``propose`` call
    stays cheap; the proposer invokes this once per outcome_kind per
    tick.
    """
    try:
        async with async_session_scope() as session:
            stmt = (
                select(CalibrationProposalRecord)
                .where(
                    CalibrationProposalRecord.outcome_kind == outcome_kind,
                    CalibrationProposalRecord.status
                    == CALIBRATION_STATUS_ACTIVE,
                )
                .order_by(
                    CalibrationProposalRecord.created_at.desc(),  # type: ignore[attr-defined]
                )
                .limit(1)
            )
            row = (await session.exec(stmt)).first()
    except _SWEEP_ERRORS as exc:
        _log.warning(
            "calibration_sweep: current-threshold lookup failed for "
            "kind=%s (%s) -- defaulting to %.3f",
            outcome_kind, type(exc).__name__, _DEFAULT_THRESHOLD,
            exc_info=exc,
        )
        return _DEFAULT_THRESHOLD
    if row is None:
        return _DEFAULT_THRESHOLD
    return float(row.after_threshold)


async def _read_samples_from_table_pair(
    outcome_table: str,
    review_table: str,
    *,
    cutoff: datetime,
    sample_cap: int,
) -> list[CalibrationSample]:
    """Read approve/reject samples from one ``(outcome, review)`` pair.

    Joins the review row's vote to the outcome row's ``outcome_kind``
    and ``confidence`` so each returned :class:`CalibrationSample`
    carries the outcome's confidence at the time of the vote. Rows
    whose review ``created_at`` is older than ``cutoff`` are excluded.
    Result is capped at ``sample_cap`` most-recent rows per pair so a
    single very active table cannot blow the sweep's memory budget.
    """
    if not (
        _is_safe_table_name(outcome_table)
        and _is_safe_table_name(review_table)
    ):
        _log.warning(
            "calibration_sweep: refusing unsafe table names "
            "outcome=%r review=%r -- skipping pair",
            outcome_table, review_table,
        )
        return []

    # Table names are code-owned (DEFAULT_CALIBRATION_TABLES + the
    # snake_case gate above); vote filter and cutoff/cap are bound
    # parameters. f-string interpolation into text() is intentional and
    # safe here.
    sql = text(
        f"SELECT o.outcome_kind, r.vote, o.confidence "
        f"FROM {review_table} r "
        f"JOIN {outcome_table} o ON o.id = r.outcome_id "
        f"WHERE r.vote IN ('approve', 'reject') "
        f"AND r.created_at >= :cutoff "
        f"ORDER BY r.created_at DESC "
        f"LIMIT :cap"
    )

    try:
        async with async_session_scope() as session:
            rows = (await session.execute(
                sql, {"cutoff": cutoff, "cap": int(sample_cap)},
            )).all()
    except _SWEEP_ERRORS as exc:
        _log.warning(
            "calibration_sweep: sample read failed for %s/%s (%s)",
            outcome_table, review_table, type(exc).__name__,
            exc_info=exc,
        )
        return []

    out: list[CalibrationSample] = []
    for kind, vote, confidence in rows:
        if not kind or not vote:
            continue
        out.append(CalibrationSample(
            outcome_kind=str(kind),
            verdict=str(vote),
            confidence=_confidence_to_float(
                str(confidence) if confidence is not None else None,
            ),
        ))
    return out


async def run_calibration_sweep(**kwargs: object) -> CalibrationSweepReport:
    """Aggregate recent review history and persist calibration proposals.

    Called by :class:`AutomationRunner` when an operator has scheduled
    ``platform.calibration_proposer_sweep``. The runner injects
    ``target_name`` / ``execution_context`` kwargs, both swallowed here.

    ``action_kwargs_json`` on the schedule row MAY carry:

    * ``table_pairs``: ``list[[outcome_table, review_table]]`` override
      of :data:`DEFAULT_CALIBRATION_TABLES`. Names that fail the
      snake_case gate are silently dropped and the default allowlist is
      used if none survive.
    * ``window_days``: recent-review window (int > 0); default 30.
    * ``sample_cap``: max rows read per pair (int > 0); default 5000.
    * ``min_evidence``: minimum samples per kind before a proposal is
      allowed (int > 0); default 10. Passed to :class:`CalibrationProposer`.
    * ``margin``: additive raise / subtractive drop distance
      (float > 0); default 0.05. Passed to :class:`CalibrationProposer`.

    Each stage isolates its own failures: a table read that fails does
    not stop later pairs, a ``propose`` that fails does not stop later
    kinds, and a ``persist`` that fails does not stop later kinds. The
    sweep NEVER raises; the returned :class:`CalibrationSweepReport`
    carries the error trail so the schedule's ``last_run_result``
    snapshot is self-describing.
    """
    # runner-injected metadata; not used here beyond swallowing so the
    # bare-callable path (kwargs -> **kwargs) doesn't reject unknown
    # keys on this handler.
    _ = kwargs.pop("target_name", None)
    _ = kwargs.pop("execution_context", None)

    pairs = _coerce_pairs(kwargs.get("table_pairs"))
    window_days = _coerce_int(kwargs.get("window_days"), _DEFAULT_WINDOW_DAYS)
    sample_cap = _coerce_int(kwargs.get("sample_cap"), _DEFAULT_SAMPLE_CAP)
    min_evidence = _coerce_int(
        kwargs.get("min_evidence"), _DEFAULT_MIN_EVIDENCE,
    )
    margin = _coerce_float(kwargs.get("margin"), _DEFAULT_MARGIN)

    cutoff = datetime.now(UTC) - timedelta(days=window_days)

    report: CalibrationSweepReport = {
        "kinds_seen": 0,
        "samples_read": 0,
        "proposals_persisted": 0,
        "kinds_below_min_evidence": 0,
        "errors": [],
    }

    all_samples: list[CalibrationSample] = []
    for outcome_table, review_table in pairs:
        samples = await _read_samples_from_table_pair(
            outcome_table, review_table,
            cutoff=cutoff, sample_cap=sample_cap,
        )
        if not samples:
            # An empty read is either "no traffic in window" (no error)
            # or a failure already logged inside the helper; either way
            # the sweep continues to the next pair.
            continue
        all_samples.extend(samples)

    report["samples_read"] = len(all_samples)
    kinds = {s.outcome_kind for s in all_samples}
    report["kinds_seen"] = len(kinds)

    if not kinds:
        _log.info(
            "calibration_sweep: no accept/reject samples in %d-day window",
            window_days,
        )
        return report

    proposer = CalibrationProposer(
        current_threshold_provider=_current_threshold,
        min_evidence=min_evidence,
        margin=margin,
    )

    for kind in sorted(kinds):
        try:
            proposal = await proposer.propose(kind, all_samples)
        except _SWEEP_ERRORS as exc:
            _log.warning(
                "calibration_sweep: propose failed for kind=%s (%s)",
                kind, type(exc).__name__, exc_info=exc,
            )
            report["errors"].append(f"propose:{kind}:{type(exc).__name__}")
            continue
        if proposal is None:
            report["kinds_below_min_evidence"] += 1
            continue
        try:
            await proposer.persist(proposal, actor=_ACTOR)
        except _SWEEP_ERRORS as exc:
            _log.warning(
                "calibration_sweep: persist failed for kind=%s (%s)",
                kind, type(exc).__name__, exc_info=exc,
            )
            report["errors"].append(f"persist:{kind}:{type(exc).__name__}")
            continue
        report["proposals_persisted"] += 1

    _log.info(
        "calibration_sweep completed kinds=%d samples=%d persisted=%d "
        "below_min_evidence=%d errors=%d",
        report["kinds_seen"], report["samples_read"],
        report["proposals_persisted"], report["kinds_below_min_evidence"],
        len(report["errors"]),
    )
    return report


# ---------------------------------------------------------------------------
# RFC-08 Tier D: calibrator trainer sweep (contract C6 fit path).
#
# Complements ``run_calibration_sweep`` (which writes threshold
# CalibrationProposalRecord rows) by fitting a per-task_type
# CalibratorVersionRecord candidate via CalibrationTrainer. Kept in
# this file so both sweeps share the DEFAULT_CALIBRATION_TABLES /
# _read_samples_from_table_pair machinery -- the trainer reuses the
# same accept/reject history the proposer sees.
# ---------------------------------------------------------------------------


class CalibratorTrainerSweepReport(TypedDict):
    """Structured result of one ``run_calibrator_trainer_sweep`` invocation."""

    task_types_requested: int
    versions_persisted: int
    errors: list[str]


_TRAINER_ACTOR: str = "platform.calibrator_trainer_sweep"


def _coerce_task_types(raw: object) -> tuple[str, ...]:
    """Validate an operator-supplied ``task_types`` override.

    The trainer needs an explicit list of task types (the accept/reject
    review row itself carries no task_type field, so the sweep cannot
    infer them). Empty override -> empty tuple; the sweep no-ops in
    that case and reports it in ``errors`` so the operator sees
    "nothing was fit" instead of a silent success.
    """
    if not isinstance(raw, list) or not raw:
        return ()
    out: list[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            continue
        candidate = entry.strip()
        if candidate and len(candidate) <= 64:
            out.append(candidate)
    return tuple(out)


async def run_calibrator_trainer_sweep(
    **kwargs: object,
) -> CalibratorTrainerSweepReport:
    """Fit a candidate calibrator per requested ``task_type``.

    ``action_kwargs_json`` on the schedule row MAY carry:

    * ``task_types``: ``list[str]`` of task types to fit. REQUIRED -
      the trainer has no way to enumerate task types from the review
      history itself. An empty / missing list makes the sweep a no-op
      and adds a ``"no_task_types"`` entry to ``errors``.
    * ``sample_cap``: max samples per (outcome, review) pair.
    * ``window_days``: recent-review window (int > 0); default 90.

    Every fit stays best-effort + isolated: a failure fitting one
    task_type does not stop the next. The sweep NEVER raises; the
    returned report carries the error trail.
    """
    # Deferred import: :mod:`aila.platform.eval.calibrator` imports back
    # into this module for ``_read_samples_from_table_pair``, so a
    # module-scope import would form a circular reference at load time.
    from aila.platform.eval.calibrator import CalibrationTrainer

    _ = kwargs.pop("target_name", None)
    _ = kwargs.pop("execution_context", None)

    task_types = _coerce_task_types(kwargs.get("task_types"))
    sample_cap = _coerce_int(kwargs.get("sample_cap"), _DEFAULT_SAMPLE_CAP)
    window_days = _coerce_int(kwargs.get("window_days"), 90)

    report: CalibratorTrainerSweepReport = {
        "task_types_requested": len(task_types),
        "versions_persisted": 0,
        "errors": [],
    }
    if not task_types:
        _log.info(
            "calibrator_trainer_sweep: no task_types supplied; no-op",
        )
        report["errors"].append("no_task_types")
        return report

    trainer = CalibrationTrainer(
        sample_cap=sample_cap, window_days=window_days,
    )
    for task_type in task_types:
        try:
            await trainer.fit_and_propose(
                task_type=task_type, actor=_TRAINER_ACTOR,
            )
        except _SWEEP_ERRORS as exc:
            _log.warning(
                "calibrator_trainer_sweep: fit failed for task_type=%s (%s)",
                task_type, type(exc).__name__, exc_info=exc,
            )
            report["errors"].append(f"fit:{task_type}:{type(exc).__name__}")
            continue
        report["versions_persisted"] += 1

    _log.info(
        "calibrator_trainer_sweep completed requested=%d persisted=%d errors=%d",
        report["task_types_requested"], report["versions_persisted"],
        len(report["errors"]),
    )
    return report
