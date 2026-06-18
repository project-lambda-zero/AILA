"""StageTracker — durable per-stage status mutator for target analysis.

Usage:

    from aila.modules.vr.contracts.target_stages import StageName
    from aila.modules.vr.services.stage_tracker import StageTracker, StageAlreadyDone

    async def ingest_target(target_id: str):
        try:
            async with StageTracker(target_id, StageName.INGESTION,
                                    stage_timeout_s=14400) as tracker:
                handles = await do_actual_ingest(...)
                await tracker.record_output(
                    handles_json=json.dumps(handles),
                    primary_language=lang,
                )
        except StageAlreadyDone:
            # Stage was already DONE — idempotent skip. Caller can
            # safely return without redoing the work.
            return
        # On any other exception inside `async with`, the tracker
        # automatically marks the stage FAILED with the exception
        # message before the exception propagates upward.

Semantics:

  - Entering the context loads the target row, inspects the stage's
    current status, and:
      * DONE      → raises StageAlreadyDone (caller decides to skip)
      * RUNNING within stage_timeout_s → raises StageInFlight
      * RUNNING past stage_timeout_s   → resets to RUNNING with new
        started_at + incremented attempts (operator-resume / reaper)
      * PENDING / FAILED → transitions to RUNNING with attempts+1

  - Exiting normally → state=DONE, completed_at=now, error=None.
  - Exiting via exception → state=FAILED, error=type(exc).__name__:
    str(exc), completed_at=now. Exception re-propagates.

  - Every commit also recomputes and writes the rolled-up
    `analysis_state` enum so legacy consumers (UI fields, queries)
    keep working without refactor.

  - Optional `record_output(**columns)` lets the caller persist
    work-product columns (mcp_handles_json, capability_profile_json,
    function_ranking, primary_language) inside the same transaction
    that flips the stage to DONE. Without this, partial work could
    be lost if the worker dies between writing the output and
    flipping the stage.
"""
from __future__ import annotations

import logging
from datetime import UTC, timedelta
from typing import Any

from sqlalchemy import update as _update
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.modules.vr.contracts.target import AnalysisState
from aila.modules.vr.contracts.target_stages import (
    StageName,
    StageState,
    StageStatus,
    TargetAnalysisStages,
    roll_up_overall_state,
)
from aila.modules.vr.db_models import VRTargetRecord
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = [
    "StageTracker",
    "StageAlreadyDoneError",
    "StageInFlightError",
    "StageTrackerError",
    "load_target_stages",
    "save_target_stages",
    "reap_stuck_stages",
]

_log = logging.getLogger(__name__)


# Default per-stage timeouts. The longest is ingestion at 4h, set to
# match TargetAnalysisService's existing _POLL_TIMEOUT_SECONDS, so
# operators with monorepo-scale targets (chromium, firefox) don't get
# pre-empted by the reaper mid-flight.
_DEFAULT_TIMEOUTS: dict[StageName, float] = {
    StageName.INGESTION: 14400.0,
    StageName.CAPABILITY_PROFILE: 1800.0,
    StageName.FUNCTION_RANKING: 1800.0,  # 30 min  covers cold-CSR firefox-scale rank + retry slack
    # Android stages — PRD §C-20 + F-3. Numbers sized for the operator-
    # observable upper bound of each tool: apktool on a 200 MB APK
    # ~5 min; jadx on the same ~15 min; audit-mcp Trailmark + Semble
    # build over a 10k-class jadx Java tree can take 30-60 min (parse
    # cache is cold on the very first ingestion of each APK); androguard
    # summary always under 1 min; MobSF static scan can run 10-30 min
    # depending on the rule set and the APK's library count.
    StageName.APK_DECODE: 600.0,
    StageName.JADX_DECOMPILE: 900.0,
    StageName.REACT_NATIVE_EXTRACT: 900.0,
    StageName.INDEX_DECOMPILED: 3600.0,
    StageName.STATIC_SUMMARY: 300.0,
    StageName.MOBSF_SCAN: 1800.0,
}

# fix §117 — runtime asserts at each lookup site (see __init__ and
# reap_stuck_stages below) fail loudly in the worker log on the first
# call against an unregistered stage. The previous import-time check
# only fired during module load; a stage added without a timeout entry
# would now blow up the worker that picks up the first task for it,
# which is the operator-visible event we actually want to alert on.


# ─────────────────────────────────────────────────────────────────────
# Exceptions
# ─────────────────────────────────────────────────────────────────────


class StageTrackerError(Exception):
    """Base for stage tracker errors."""


class StageAlreadyDoneError(StageTrackerError):
    """Raised on context-enter when the stage is already DONE.

    Catch this to short-circuit work in idempotent re-runs:

        try:
            async with StageTracker(...) as t:
                ...
        except StageAlreadyDone:
            return
    """


class StageInFlightError(StageTrackerError):
    """Raised on context-enter when another worker is currently running
    this stage (RUNNING state, within the configured stage_timeout_s).

    Callers should NOT retry immediately — wait for the in-flight
    worker to finish, OR run the reaper to free a truly-stuck stage.
    """


# ─────────────────────────────────────────────────────────────────────
# Read / write helpers
# ─────────────────────────────────────────────────────────────────────


def parse_stages(stages_json: str | None) -> TargetAnalysisStages:
    """Decode the JSON column into the typed contract.

    Tolerates None / empty-string / '{}' (returns a fresh struct with
    all stages PENDING) so callers don't have to special-case the
    pre-migration default value.
    """
    if not stages_json or stages_json == "{}":
        return TargetAnalysisStages()
    return TargetAnalysisStages.model_validate_json(stages_json)



async def load_target_stages(target_id: str) -> TargetAnalysisStages:
    """Read-only convenience — load stages without entering a tracker."""
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            _select(VRTargetRecord).where(VRTargetRecord.id == target_id),
        )).first()
        if row is None:
            raise StageTrackerError(f"target {target_id} not found")
        return parse_stages(row.analysis_stages_json)


def _apply_stages_to_row(
    row: VRTargetRecord,
    stages: TargetAnalysisStages,
    extra_columns: dict[str, Any] | None = None,
) -> None:
    """Mutate `row` in place to persist `stages` + recompute the rolled-up
    `analysis_state` enum. Does NOT commit; caller owns the UoW.

    Extracted so callers that already hold a `SELECT FOR UPDATE` row
    inside their own transaction (e.g. `StageTracker.__aenter__`) can
    reuse the same write path as `save_target_stages` without spawning
    a second UoW.
    """
    rolled = roll_up_overall_state(stages)
    failing = [
        (name, s.error) for name, s in stages.all_stages()
        if s.state == StageState.FAILED and s.error
    ]
    rolled_message = (
        f"{failing[0][0].value}: {failing[0][1]}" if failing else None
    )
    now = utc_now()
    row.analysis_stages_json = stages.model_dump_json()
    row.analysis_state = rolled.value
    row.analysis_state_message = rolled_message

    # Derived timestamps: the EARLIEST started_at across stages is the
    # analysis_started_at; the LATEST completed_at across done stages
    # is the analysis_completed_at.
    starts = [s.started_at for _, s in stages.all_stages() if s.started_at]
    if starts:
        row.analysis_started_at = min(starts)
    completes = [s.completed_at for _, s in stages.all_stages() if s.completed_at]
    if completes:
        row.analysis_completed_at = max(completes)

    if extra_columns:
        for col, value in extra_columns.items():
            setattr(row, col, value)

    row.updated_at = now


async def save_target_stages(
    target_id: str,
    stages: TargetAnalysisStages,
    *,
    extra_columns: dict[str, Any] | None = None,
) -> None:
    """Write back the stages struct + recompute the rolled-up enum.

    Also stamps `analysis_state_message` from the most-recent failing
    stage's error so the legacy single-column UI surface still shows
    a useful one-liner.

    `extra_columns` lets the caller write work-product columns in the
    SAME transaction that flips the stage state — eliminating the
    crash-window between persisting work output and recording the
    state transition.
    """
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            _select(VRTargetRecord).where(VRTargetRecord.id == target_id),
        )).first()
        if row is None:
            raise StageTrackerError(f"target {target_id} not found")
        _apply_stages_to_row(row, stages, extra_columns)
        uow.session.add(row)
        await uow.session.commit()


# ─────────────────────────────────────────────────────────────────────
# StageTracker — the main context manager
# ─────────────────────────────────────────────────────────────────────


class StageTracker:
    """Async context manager that wraps a single-stage execution.

    See module docstring for usage. Construction does not touch the
    DB; entering the context does.
    """

    def __init__(
        self,
        target_id: str,
        stage: StageName,
        *,
        stage_timeout_s: float | None = None,
    ) -> None:
        self.target_id = target_id
        self.stage = stage
        # fix §117 — fail loudly in the worker log on first use of a
        # stage missing from _DEFAULT_TIMEOUTS; never silently fall back
        # to a 30-min cap that would mask drift in production.
        if stage_timeout_s is not None:
            self.stage_timeout_s = stage_timeout_s
        else:
            if stage not in _DEFAULT_TIMEOUTS:
                raise RuntimeError(
                    f"stage_tracker: no _DEFAULT_TIMEOUTS entry for {stage!r}; "
                    "add one to _DEFAULT_TIMEOUTS in services/stage_tracker.py",
                )
            self.stage_timeout_s = _DEFAULT_TIMEOUTS[stage]
        self._extra_columns: dict[str, Any] = {}
        self._stages: TargetAnalysisStages | None = None

    async def __aenter__(self) -> StageTracker:
        # fix §320 — SELECT FOR UPDATE on the target row so two workers
        # racing through __aenter__ serialize on the row lock; the loser
        # observes RUNNING (or DONE) and raises StageInFlight instead of
        # both writing RUNNING and double-running the stage.
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord)
                .where(VRTargetRecord.id == self.target_id)
                .with_for_update(),
            )).first()
            if row is None:
                raise StageTrackerError(f"target {self.target_id} not found")
            stages = parse_stages(row.analysis_stages_json)
            current = stages.get(self.stage)

            if current.state == StageState.DONE:
                raise StageAlreadyDoneError(
                    f"target {self.target_id} stage {self.stage.value} is already DONE",
                )

            if current.state == StageState.RUNNING:
                # Is the other in-flight worker still within its timeout
                # window? If yes, refuse to enter (StageInFlight). If no,
                # take over (operator-resume / post-crash recovery).
                started = current.started_at
                now = utc_now()
                if started is not None:
                    # SQL persisted timestamps come back as naive on some
                    # backends; UTC-coerce so the comparison is stable.
                    if started.tzinfo is None:
                        started = started.replace(tzinfo=UTC)
                    stale_threshold = now - timedelta(seconds=self.stage_timeout_s)
                    if started > stale_threshold:
                        raise StageInFlightError(
                            f"target {self.target_id} stage {self.stage.value} is "
                            f"already RUNNING since {started.isoformat()} "
                            f"(within {self.stage_timeout_s}s timeout)",
                        )
                    _log.warning(
                        "stage_tracker: %s/%s was RUNNING for %.0fs (> %.0fs timeout) — "
                        "taking over (attempt %d)",
                        self.target_id, self.stage.value,
                        (now - started).total_seconds(),
                        self.stage_timeout_s,
                        current.attempts + 1,
                    )
                # else: RUNNING without started_at — broken row, just take over

            # Transition to RUNNING with incremented attempt counter,
            # writing inside the same UoW that holds the row lock.
            new_status = StageStatus(
                state=StageState.RUNNING,
                started_at=utc_now(),
                completed_at=None,
                attempts=current.attempts + 1,
                error=None,
            )
            stages.set(self.stage, new_status)
            _apply_stages_to_row(row, stages)
            uow.session.add(row)
            await uow.session.commit()

        self._stages = stages
        return self

    async def __aexit__(self, _exc_type, exc, _tb) -> bool:
        # fix §321 — re-read under SELECT FOR UPDATE so the reaper and
        # __aexit__ serialize on the row lock. If the reaper claimed
        # this stage (FAILED with the `reaper:` prefix that
        # `reap_stuck_stages` writes) while the work was in-flight,
        # honor the reaper's verdict: the in-memory result is lost
        # (acceptable) and we do NOT overwrite the FAILED row.
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                _select(VRTargetRecord)
                .where(VRTargetRecord.id == self.target_id)
                .with_for_update(),
            )).first()
            if row is None:
                raise StageTrackerError(f"target {self.target_id} not found")
            stages = parse_stages(row.analysis_stages_json)
            current = stages.get(self.stage)
            now = utc_now()

            if (
                current.state == StageState.FAILED
                and current.error is not None
                and current.error.startswith("reaper:")
            ):
                _log.warning(
                    "stage_tracker: %s/%s was reaped while in-flight (%r); "
                    "honoring reaper verdict and discarding in-memory result",
                    self.target_id, self.stage.value, current.error,
                )
                # Returning False propagates the work exception (if any);
                # the reaper already persisted FAILED so we leave the row
                # untouched.
                return False

            if exc is None:
                new_status = StageStatus(
                    state=StageState.DONE,
                    started_at=current.started_at,
                    completed_at=now,
                    attempts=current.attempts,
                    error=None,
                )
            else:
                err_msg = f"{type(exc).__name__}: {exc}"
                # Truncate long error messages so a single huge stack
                # trace doesn't blow up the JSON column.
                new_status = StageStatus(
                    state=StageState.FAILED,
                    started_at=current.started_at,
                    completed_at=now,
                    attempts=current.attempts,
                    error=err_msg[:800],
                )

            stages.set(self.stage, new_status)
            try:
                _apply_stages_to_row(
                    row, stages,
                    extra_columns=self._extra_columns or None,
                )
                uow.session.add(row)
                await uow.session.commit()
            except (SQLAlchemyError, OSError, RuntimeError) as save_exc:
                # fix §322 — if the work itself succeeded (exc is None)
                # but the state-commit failed, the caller MUST know:
                # otherwise they treat the stage as DONE while the DB
                # still says RUNNING and the next worker double-runs the
                # work. If the work already raised, keep the swallow so
                # the original exception still propagates as the more
                # informative root cause.
                _log.error(
                    "stage_tracker: failed to commit stage status for %s/%s: %s",
                    self.target_id, self.stage.value, save_exc,
                    exc_info=True,
                )
                if exc is None:
                    raise

        # Returning False/None propagates the exception; True swallows.
        # Never swallow — caller wants to know.
        return False

    def record_output(self, **extra_columns: Any) -> None:
        """Queue work-product columns to be written in the same commit
        that flips the stage to DONE.

        Example: tracker.record_output(
            mcp_handles_json=json.dumps(handles),
            primary_language="rust",
        )

        Columns must exist on VRTargetRecord. Multiple calls before
        __aexit__ merge.
        """
        self._extra_columns.update(extra_columns)


# ─────────────────────────────────────────────────────────────────────
# Reaper — flips stuck RUNNING stages to FAILED:timeout
# ─────────────────────────────────────────────────────────────────────


async def reap_stuck_stages() -> int:
    """Find target rows with any RUNNING stage past its timeout, flip
    those stages to FAILED with a `timeout` error message.

    Returns the number of stages reaped. Intended to be called from
    the periodic worker cron (1-minute interval is fine — each call
    is a single SELECT for candidates + one targeted UPDATE per
    offending row, each in its own UoW).
    """
    # fix §325 — snapshot candidate ids in a short read-only UoW, then
    # process each row in its OWN UoW. Previously a single deferred
    # commit at the end of the loop meant one bad row dropped every
    # other staged mutation; now each row commits (or rolls back)
    # independently.
    async with UnitOfWork() as uow:
        candidates = (await uow.session.exec(
            _select(VRTargetRecord.id).where(
                # fix §116 / §324 — broaden the scan to every state
                # whose rolled-up value can hide a stuck RUNNING stage.
                # AnalysisState only has 4 values (PENDING / INGESTING /
                # READY / FAILED); RUNNING stages roll up to INGESTING
                # unless a sibling stage is FAILED (in which case the row
                # rolls up to FAILED and the previous reaper missed the
                # stuck stage entirely). PENDING/READY cannot host a
                # RUNNING stage so they stay out of the scan.
                VRTargetRecord.analysis_state.in_([
                    AnalysisState.INGESTING.value,
                    AnalysisState.FAILED.value,
                ]),
            )
            # fix §119 — cap per-pass work. With 10k stuck rows in one
            # pass the reaper would hold a transaction for minutes and
            # block legitimate __aenter__/__aexit__ row locks; bound it
            # to 200 and let the next cron tick drain the rest.
            .limit(200),
        )).all()

    reaped = 0
    # fix §118 — collect every per-row failure and log each; previously
    # the first raise aborted the whole pass and stuck rows past the
    # failure point waited for the next cron tick (or forever, if the
    # same row reliably blew up).
    failures: list[tuple[str, BaseException]] = []
    for target_id in candidates:
        try:
            async with UnitOfWork() as uow:
                row = (await uow.session.exec(
                    _select(VRTargetRecord).where(VRTargetRecord.id == target_id),
                )).first()
                if row is None:
                    # Target deleted between scan and per-row UoW — skip.
                    continue
                # fix §323 — snapshot the row's stages BEFORE any
                # mutation so the UPDATE below carries an optimistic-
                # concurrency WHERE clause keyed on
                # analysis_stages_json. If __aexit__ legitimately
                # completed the stage (or another reaper pass already
                # flipped it) between our SELECT and our UPDATE, the
                # JSON string differs and the UPDATE matches zero rows
                # — the legitimate write survives and we back off.
                original_stages_json = row.analysis_stages_json
                stages = parse_stages(original_stages_json)
                mutated = False
                now = utc_now()
                row_reaped = 0
                for stage_name, status in stages.all_stages():
                    if status.state != StageState.RUNNING:
                        continue
                    # fix §117 — same runtime guard as StageTracker.__init__;
                    # an unregistered stage drift surfaces in the reaper log
                    # instead of silently inheriting the 30-min cap.
                    if stage_name not in _DEFAULT_TIMEOUTS:
                        raise RuntimeError(
                            f"stage_tracker.reaper: no _DEFAULT_TIMEOUTS entry "
                            f"for {stage_name!r}; add one to _DEFAULT_TIMEOUTS",
                        )
                    timeout_s = _DEFAULT_TIMEOUTS[stage_name]
                    started = status.started_at
                    if started is None:
                        continue
                    if started.tzinfo is None:
                        started = started.replace(tzinfo=UTC)
                    age = (now - started).total_seconds()
                    if age <= timeout_s:
                        continue
                    _log.warning(
                        "stage_tracker.reaper: target=%s stage=%s RUNNING for %.0fs (> %.0fs) — marking FAILED:timeout",
                        row.id, stage_name.value, age, timeout_s,
                    )
                    stages.set(stage_name, StageStatus(
                        state=StageState.FAILED,
                        started_at=status.started_at,
                        completed_at=now,
                        attempts=status.attempts,
                        error=f"reaper: RUNNING for {age:.0f}s (> {timeout_s:.0f}s timeout); resume to retry",
                    ))
                    mutated = True
                    row_reaped += 1
                if not mutated:
                    continue

                rolled = roll_up_overall_state(stages)
                new_stages_json = stages.model_dump_json()
                # fix §118 — when several stages fail in one reap pass,
                # concatenate every failure into the legacy single-column
                # analysis_state_message instead of silently dropping all
                # but the first. Operators reading the legacy column now
                # see every stage that timed out, in stage iteration order,
                # capped at 800 chars to match the per-stage error budget.
                reaped_msgs = [
                    f"{name.value}: {s.error}"
                    for name, s in stages.all_stages()
                    if s.state == StageState.FAILED and s.error
                ]
                values: dict[str, Any] = {
                    "analysis_stages_json": new_stages_json,
                    "analysis_state": rolled.value,
                    "updated_at": now,
                }
                if reaped_msgs:
                    values["analysis_state_message"] = " | ".join(reaped_msgs)[:800]

                # Expunge the ORM-loaded row so the optimistic UPDATE
                # below is the single source of truth; otherwise
                # SQLAlchemy may flush the in-memory `row` and clobber
                # our explicit values.
                uow.session.expunge(row)

                upd_stmt = (
                    _update(VRTargetRecord)
                    .where(VRTargetRecord.id == target_id)
                    .where(VRTargetRecord.analysis_stages_json == original_stages_json)
                    .values(**values)
                    .returning(VRTargetRecord.id)
                )
                upd_result = await uow.session.execute(upd_stmt)
                if upd_result.first() is None:
                    _log.info(
                        "stage_tracker.reaper: target=%s stages mutated between "
                        "SELECT and UPDATE — backing off (legitimate writer wins)",
                        target_id,
                    )
                    await uow.session.rollback()
                    continue
                await uow.session.commit()
                reaped += row_reaped
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            # fix §118 — log AND collect; the next row still gets a
            # chance. The collected list drives the post-loop summary
            # log so an operator scanning the worker log sees how many
            # rows survived a bad cron tick.
            _log.error(
                "stage_tracker.reaper: failed to reap target=%s: %s",
                target_id, exc,
                exc_info=True,
            )
            failures.append((target_id, exc))

    if failures:
        _log.warning(
            "stage_tracker.reaper: %d/%d rows failed to reap this pass "
            "(reaped=%d stages across surviving rows)",
            len(failures), len(candidates), reaped,
        )
    return reaped
