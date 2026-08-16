"""Unified recovery-service surface for investigation recovery.

Owns eligibility, per-row classification, AND execution for both
investigation-recovery strategies. The two strategies that used to live
in :mod:`aila.platform.services.stall_recovery` and
:mod:`aila.platform.services.stuck_healer` now dispatch through a single
:meth:`PlatformRecoveryService.recover` entrypoint keyed on the
classified :class:`RecoveryStrategy`; a single periodic sweep
(:meth:`PlatformRecoveryService.sweep`) fetches every candidate once,
classifies, and dispatches. The two pre-lift module-level entrypoints
(``sweep_stalled_investigations`` / ``sweep_stuck_investigations``)
stay as thin back-compat wrappers filtered to their strategy so callers
that already import them keep working unchanged.

Split rationale (why two strategies, one dispatcher)
----------------------------------------------------

The two execution paths do different work per row and cannot be merged
into one path without dropping guarantees:

* :attr:`RecoveryStrategy.STALL_REENQUEUE` -- handles ``created`` /
  ``running`` / ``stalled`` rows past the idle threshold with no live
  ``taskrecord``. Execution is a rate-limited fan-out submit through
  the module's plain ``submit_fn``: one task per active branch, or one
  inv-level submit for kinds that own their own branch lifecycle.
  Cursor state is intentionally ignored at eligibility time.
* :attr:`RecoveryStrategy.STUCK_HEAL` -- handles the narrower ``running``
  rows that ALSO have no resumable ``workflow_state_cursor``. Execution
  is the full :func:`reenqueue_investigation` four-source-of-truth
  reset (cancel stale tasks, wipe crashed cursors, reset row to
  CREATED, commit, submit fresh) plus a durable ``kind='recovery'``
  ledger event via :func:`ResilienceLayer.emit_recovery_event`
  (RFC-07 #31 criterion 6).

The RATE MODEL is also strategy-specific: STALL caps total task
submits per tick (default 6, env-tunable), STUCK caps investigations
healed per tick (default 5, config-tunable). The unified sweep tracks
both counters independently so each strategy's tuning knobs still
apply.

Mutual exclusion (issue #121) runs through
:func:`aila.platform.services.recovery_claim.try_claim_recovery`
unchanged. Every per-row execution -- STALL or STUCK -- claims before
its submit, so cross-strategy and cross-process races stay neutralized.
The unified sweep also processes STUCK candidates first and skips any
inv already healed by STUCK when it walks the STALL candidates, so
the same tick never runs both strategies against the same row.

Public surface
--------------

* :data:`NON_RESUMABLE_CURSOR_STATES` -- shared cursor sentinel set the
  stuck-healer eligibility SELECT filters on.
* :data:`LIVE_TASK_STATUSES` -- ``taskrecord.status`` values that make
  a row ineligible for BOTH strategies.
* :class:`RecoveryStrategy` -- names the two execution paths.
* :class:`RecoveryCandidate`, :class:`RecoveryOutcome`,
  :class:`StallBinding`, :class:`StuckBinding`, :class:`RecoveryBinding`,
  :class:`StallRecoveryResult`, :class:`StuckHealSummary`,
  :class:`UnifiedRecoveryResult` -- dataclasses used by the unified
  dispatcher and the back-compat wrappers.
* :class:`PlatformRecoveryService` -- namespace holding the shared
  eligibility SELECTs, the row classifier, the atomic claim
  primitives, and the unified :meth:`recover` /
  :meth:`sweep` dispatchers.
"""
from __future__ import annotations

import enum
import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text as _sql_text
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.config_base import ModuleConfigReader
from aila.platform.services.investigation_lifecycle import (
    ReenqueueInvestigationError,
    reenqueue_investigation,
)
from aila.platform.services.recovery_claim import try_claim_recovery
from aila.platform.services.resilience import get_default_resilience_layer
from aila.storage.database import async_session_scope

__all__ = [
    "CONFIG_KEY_IDLE_GRACE_S",
    "CONFIG_KEY_MAX_HEALS_PER_TICK",
    "DEFAULT_STALL_IDLE_MIN",
    "DEFAULT_STALL_RATE_PER_TICK",
    "DEFAULT_STUCK_IDLE_GRACE_S",
    "DEFAULT_STUCK_MAX_HEALS_PER_TICK",
    "LIVE_TASK_STATUSES",
    "NON_RESUMABLE_CURSOR_STATES",
    "PlatformRecoveryService",
    "RecoveryBinding",
    "RecoveryCandidate",
    "RecoveryOutcome",
    "RecoveryStrategy",
    "StallBinding",
    "StallRecoveryResult",
    "StuckBinding",
    "StuckHealSummary",
    "SubmitFn",
    "SubmitOneFn",
    "UnifiedRecoveryResult",
]

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# Cursor states that count as NON-resumable for the stuck-healer path.
# Terminal engine states plus the ``__paused__`` operator sentinel. Kept
# in sync with :data:`aila.platform.tasks.state_reconciler._TERMINAL_CURSOR_STATES`
# (the reconciler owns the resumable side); the healer runs when the
# reconciler cannot -- either the cursor is absent or it is one of
# these non-resumable values.
NON_RESUMABLE_CURSOR_STATES: tuple[str, ...] = (
    "__crashed__",
    "__failed__",
    "__cancelled__",
    "__succeeded__",
    "__paused__",
)

# ``taskrecord.status`` values that make an investigation ineligible for
# every recovery sweep: an in-flight task is either about to make
# progress or about to be reaped by the task-level state reconciler.
LIVE_TASK_STATUSES: tuple[str, ...] = ("queued", "running", "waiting")

# STALL_REENQUEUE defaults. Idle threshold at 15 minutes is wider than
# any legitimate turn timing observed in worker logs. Rate cap at 6
# submits per tick fits one full 6-persona VR investigation fan-out
# without risking a 40 RPM LLM provider's steady-state budget. Env-var
# overrides: ``<PREFIX>_IDLE_MIN`` and ``<PREFIX>_LIMIT``.
DEFAULT_STALL_IDLE_MIN: int = 15
DEFAULT_STALL_RATE_PER_TICK: int = 6

# STUCK_HEAL defaults + config keys. Generous idle grace so a legitimately
# slow turn is never mistaken for a stall; small per-tick cap so a mass
# zombie backlog does not saturate the task queue in one tick.
# ``ModuleConfigReader`` resolves the operator overrides via
# ``ConfigRegistry`` (env -> DB); the code default matches each module's
# ``config_schema.py`` field default.
CONFIG_KEY_IDLE_GRACE_S = "stuck_healer_idle_grace_s"
CONFIG_KEY_MAX_HEALS_PER_TICK = "stuck_healer_max_heals_per_tick"
DEFAULT_STUCK_IDLE_GRACE_S: int = 600
DEFAULT_STUCK_MAX_HEALS_PER_TICK: int = 5

# Reserved sentinel for "no branch_id, inv-level enqueue" path. Used in
# submit-log lines only -- never sent to the queue.
_INV_LEVEL = "__inv_level__"


# ---------------------------------------------------------------------------
# Callable types
# ---------------------------------------------------------------------------

# STALL_REENQUEUE per-branch submitter. Args: (kind, inv_id,
# branch_id_or_None, team_id_or_None). Returns None (submitted task_id
# is unused, but the type keeps ARQ signature compatibility).
SubmitFn = Callable[
    [str, str, str | None, str | None],
    Awaitable[None],
]

# STUCK_HEAL atomic single-submit primitive matching
# ``reenqueue_investigation``'s ``submit_one`` contract. Args:
# (inv_id, branch_id_or_None). Returns None.
SubmitOneFn = Callable[[str, str | None], Awaitable[None]]


# ---------------------------------------------------------------------------
# Strategy classifier
# ---------------------------------------------------------------------------


class RecoveryStrategy(enum.StrEnum):
    """Which recovery path applies to an eligible row.

    ``STALL_REENQUEUE`` -- direct rate-limited submit (fan-out per active
    branch, or one inv-level submit for single-submit kinds).

    ``STUCK_HEAL`` -- full :func:`reenqueue_investigation` reset plus a
    durable resilience recovery event.

    Both paths dispatch through :meth:`PlatformRecoveryService.recover`;
    the sweep entrypoint fans them out per candidate.
    """

    STALL_REENQUEUE = "stall_reenqueue"
    STUCK_HEAL = "stuck_heal"


# ---------------------------------------------------------------------------
# Bindings + results (data)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StallBinding:
    """Everything the :attr:`RecoveryStrategy.STALL_REENQUEUE` path needs.

    ``idle_minutes`` / ``rate_per_tick`` default to ``None`` -- the sweep
    then reads ``<env_prefix>_IDLE_MIN`` / ``<env_prefix>_LIMIT`` with
    the module-level defaults as the fallback.
    """

    submit_fn: SubmitFn
    sweepable_kinds: tuple[str, ...]
    single_submit_kinds: tuple[str, ...]
    env_prefix: str
    branches_table: str
    idle_minutes: int | None = None
    rate_per_tick: int | None = None


@dataclass(frozen=True)
class StuckBinding:
    """Everything the :attr:`RecoveryStrategy.STUCK_HEAL` path needs.

    ``idle_grace_s`` / ``max_heals_per_tick`` default to ``None`` -- the
    sweep then resolves them via :class:`ModuleConfigReader` against the
    ``<module_id>`` namespace with the module-level defaults as the
    fallback.

    ``branch_model`` + ``branch_status_active`` control
    :func:`reenqueue_investigation`'s fan-out: ``None`` submits once (VR
    style, setup respawns branches); a branch model submits one task per
    active branch (malware style).
    """

    inv_model: type[Any]
    running_status_values: tuple[str, ...]
    fn_path_pattern: str
    module_id: str
    submit_one: SubmitOneFn
    branch_model: type[Any] | None = None
    branch_status_active: str | None = None
    inv_timestamp_column: str = "updated_at"
    idle_grace_s: int | None = None
    max_heals_per_tick: int | None = None


@dataclass(frozen=True)
class RecoveryBinding:
    """Unified binding both strategies read from.

    A module supplies whichever branches it wires; the other side may be
    ``None``. The unified sweep skips absent strategies (and the
    back-compat wrappers set only one side, matching pre-lift behavior).
    """

    investigations_table: str
    stall: StallBinding | None = None
    stuck: StuckBinding | None = None


@dataclass
class RecoveryCandidate:
    """One row selected by an eligibility SELECT, classified.

    ``strategy`` is the classifier's decision (also equals the SELECT
    that surfaced this row when the sweep is filtered).

    STALL-specific fields (``kind``, ``status``, ``team_id``,
    ``seen_updated_at``) are populated for
    :attr:`RecoveryStrategy.STALL_REENQUEUE` candidates.
    STUCK-specific fields (``seen_timestamp``) for
    :attr:`RecoveryStrategy.STUCK_HEAL`.
    """

    inv_id: str
    strategy: RecoveryStrategy
    kind: str | None = None
    status: str | None = None
    team_id: str | None = None
    seen_updated_at: datetime | None = None
    seen_timestamp: datetime | None = None


@dataclass
class RecoveryOutcome:
    """Outcome of one :meth:`PlatformRecoveryService.recover` call."""

    inv_id: str
    strategy: RecoveryStrategy
    # "recovered" -- at least one submit landed (STALL) or the full
    # reenqueue+journal pair succeeded (STUCK).
    # "skipped_race" -- another sweep tick beat this caller to the claim.
    # "skipped_error" -- reenqueue / re-enqueue helper failed (STUCK) or
    # the atomic stalled->running flip failed transport-wise (STALL).
    # "no_op" -- the classifier returned no strategy (row moved between
    # SELECT and dispatch) or the row vanished.
    status: str
    submits: int = 0
    kind: str | None = None


@dataclass
class StallRecoveryResult:
    """Outcome of one STALL sweep pass (pre-lift shape preserved)."""

    examined: int = 0
    """Investigation rows that matched STALL eligibility (before branch fan-out)."""

    enqueued: int = 0
    """Number of ``task_queue.submit`` calls actually performed."""

    skipped_rate_cap: int = 0
    """Eligible rows whose entire branch fan-out would push us over the
    rate cap. Counted at row granularity (not branch); informs operator
    how much backlog remains."""

    by_kind_enqueued: dict[str, int] = field(default_factory=dict)
    """Per-kind count of submits."""

    investigations_recovered: list[str] = field(default_factory=list)
    """Investigation IDs that produced at least one submit this tick."""


@dataclass
class StuckHealSummary:
    """Outcome of one STUCK sweep pass; ``as_dict`` matches pre-lift shape."""

    examined: int = 0
    healed: int = 0
    ids: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "examined": self.examined,
            "healed": self.healed,
            "ids": list(self.ids),
        }


@dataclass
class UnifiedRecoveryResult:
    """Aggregated outcome of one unified sweep.

    Contains both strategy sub-results plus the per-candidate outcome
    stream. Back-compat wrappers pull ``.stall`` or ``.stuck.as_dict()``
    to return the pre-lift shape.
    """

    stall: StallRecoveryResult = field(default_factory=StallRecoveryResult)
    stuck: StuckHealSummary = field(default_factory=StuckHealSummary)
    outcomes: list[RecoveryOutcome] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers -- shared by the two execution paths
# ---------------------------------------------------------------------------


def _env_int(key: str, default: int) -> int:
    """Coerce an env-var override to a positive int; log + default on error."""
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        _log.warning(
            "recovery_service: %s is not an int (%r), using default=%d",
            key, raw, default,
        )
        return default


async def _resolve_int_config(
    module_id: str, key: str, default: int,
) -> int:
    """Resolve a positive int config value with a code-default fallback.

    ``ModuleConfigReader.get_int`` coerces ``ConfigRegistry.get``'s value.
    An UNSET key (no env / no DB override) yields None -> ``int(None)``
    raises ``TypeError``: that is the NORMAL path (the code default equals
    the schema value), logged at DEBUG so a per-tick sweep does not spam
    the worker log. A MALFORMED override (a non-numeric DB / env value)
    raises ``ValueError``: that is a real operator misconfiguration and is
    logged at WARNING. Either way the conservative code default is used.
    """
    reader = ModuleConfigReader(module_id)
    try:
        value = await reader.get_int(key)
    except TypeError:
        _log.debug(
            "recovery_service: config %s/%s unset; using default=%d",
            module_id, key, default,
        )
        return default
    except ValueError as exc:
        _log.warning(
            "recovery_service: config %s/%s malformed (%s); using default=%d",
            module_id, key, exc, default,
        )
        return default
    if value <= 0:
        _log.warning(
            "recovery_service: config %s/%s=%d is non-positive; using default=%d",
            module_id, key, value, default,
        )
        return default
    return value


async def _fetch_active_branches(
    *,
    branches_table: str,
    inv_id: str,
) -> list[str]:
    """Return active-branch ids for an investigation (STALL fan-out helper)."""
    stmt = _sql_text(
        f"""
        SELECT id::text AS id
        FROM {branches_table}
        WHERE investigation_id = :inv
          AND status = 'active'
        ORDER BY created_at
        """,
    ).bindparams(inv=inv_id)
    async with async_session_scope() as session:
        return [
            r["id"]
            for r in (await session.execute(stmt)).mappings().all()
        ]


async def _safe_submit(
    submit: SubmitFn,
    inv_kind: str,
    inv_id: str,
    branch_id: str | None,
    team_id: str | None,
    result: StallRecoveryResult,
) -> bool:
    """Call ``submit_fn`` with narrow-exception logging.

    A submit failure (Redis blip, ARQ serialization, dedup race) MUST
    NOT abort the sweep. Log, continue. Returns ``True`` when the submit
    landed and the result counters were mutated.
    """
    try:
        await submit(inv_kind, inv_id, branch_id, team_id)
    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
        _log.warning(
            "recovery_service: submit failed inv=%s kind=%s branch=%s err=%s",
            inv_id, inv_kind, branch_id or _INV_LEVEL, exc,
        )
        return False
    result.enqueued += 1
    result.by_kind_enqueued[inv_kind] = (
        result.by_kind_enqueued.get(inv_kind, 0) + 1
    )
    if inv_id not in result.investigations_recovered:
        result.investigations_recovered.append(inv_id)
    return True


# ---------------------------------------------------------------------------
# Execution -- one strategy per helper
# ---------------------------------------------------------------------------


async def _execute_stall(
    *,
    investigations_table: str,
    binding: StallBinding,
    candidate: RecoveryCandidate,
    result: StallRecoveryResult,
    remaining_cap: int,
) -> RecoveryOutcome:
    """Run one STALL_REENQUEUE row.

    Preserves the pre-lift stall_recovery guarantees exactly:

    * ``status='stalled'`` rows: atomic ``stalled -> running`` flip is
      both the operational fix AND the recovery claim.
    * Non-stalled eligible rows: compare-and-set on ``updated_at`` is
      the recovery claim.
    * A losing claim skips this row and defers to the winner.
    * Fan-out is capped by ``remaining_cap`` -- the loop stops mid
      branch list without recording ``skipped_rate_cap`` (that count
      lives at the sweep level, per-row).
    * ``bypass_dedup=True`` is a module submitter detail, unchanged.
    """
    inv_id = candidate.inv_id
    inv_kind = candidate.kind or ""
    inv_status = candidate.status or "running"
    team_id = candidate.team_id
    seen_updated_at = candidate.seen_updated_at

    if inv_status == "stalled":
        flip = await PlatformRecoveryService.try_stalled_status_flip(
            investigations_table=investigations_table,
            inv_id=inv_id,
        )
        if flip is None:
            return RecoveryOutcome(
                inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
                status="skipped_error", kind=inv_kind,
            )
        if not flip:
            _log.info(
                "recovery_service[stall]: inv=%s stalled->running flip "
                "lost to concurrent claim; skipping",
                inv_id,
            )
            return RecoveryOutcome(
                inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
                status="skipped_race", kind=inv_kind,
            )
        _log.info(
            "recovery_service[stall]: flipped stalled->running inv=%s",
            inv_id,
        )
    else:
        # Non-stalled eligible row: bump updated_at as the claim.
        # Compare-and-set on ``updated_at = seen_updated_at`` so racers
        # observing the same SELECT window converge on exactly one
        # winner. ``seen_updated_at`` was captured at SELECT time.
        if seen_updated_at is None:
            _log.warning(
                "recovery_service[stall]: inv=%s missing seen_updated_at; "
                "cannot claim, skipping",
                inv_id,
            )
            return RecoveryOutcome(
                inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
                status="skipped_error", kind=inv_kind,
            )
        if not await PlatformRecoveryService.try_claim(
            inv_table=investigations_table,
            timestamp_column="updated_at",
            inv_id=inv_id,
            seen_timestamp=seen_updated_at,
        ):
            _log.info(
                "recovery_service[stall]: inv=%s lost claim to concurrent "
                "recovery sweep; skipping",
                inv_id,
            )
            return RecoveryOutcome(
                inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
                status="skipped_race", kind=inv_kind,
            )

    submits = 0

    if inv_kind in binding.single_submit_kinds:
        # Single inv-level submit; the submitter routes this kind to a
        # task body that owns its own branch lifecycle.
        if remaining_cap <= 0:
            return RecoveryOutcome(
                inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
                status="no_op", kind=inv_kind,
            )
        if await _safe_submit(
            binding.submit_fn, inv_kind, inv_id, None, team_id, result,
        ):
            submits = 1
        return RecoveryOutcome(
            inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
            status="recovered" if submits else "skipped_error",
            submits=submits, kind=inv_kind,
        )

    branches = await _fetch_active_branches(
        branches_table=binding.branches_table, inv_id=inv_id,
    )
    if not branches:
        # status=created investigations that never spawned, OR
        # status=running investigations whose every branch terminated
        # but the inv-level rollup didn't fire. Either way the inv-
        # level submit lets the setup state re-evaluate.
        if remaining_cap <= 0:
            return RecoveryOutcome(
                inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
                status="no_op", kind=inv_kind,
            )
        if await _safe_submit(
            binding.submit_fn, inv_kind, inv_id, None, team_id, result,
        ):
            submits = 1
        return RecoveryOutcome(
            inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
            status="recovered" if submits else "skipped_error",
            submits=submits, kind=inv_kind,
        )

    # Fan out one submit per active branch. STOP at ``remaining_cap``
    # mid-fan-out; partial recovery is fine, next tick continues.
    for branch_id in branches:
        if submits >= remaining_cap:
            break
        if await _safe_submit(
            binding.submit_fn, inv_kind, inv_id, branch_id, team_id, result,
        ):
            submits += 1

    return RecoveryOutcome(
        inv_id=inv_id, strategy=RecoveryStrategy.STALL_REENQUEUE,
        status="recovered" if submits else "skipped_error",
        submits=submits, kind=inv_kind,
    )


async def _execute_stuck(
    *,
    investigations_table: str,
    binding: StuckBinding,
    candidate: RecoveryCandidate,
) -> RecoveryOutcome:
    """Run one STUCK_HEAL row.

    Preserves the pre-lift stuck_healer guarantees exactly:

    * Timestamp compare-and-set claim (issue #121 mutual exclusion).
    * Full :func:`reenqueue_investigation` four-source-of-truth reset:
      cancel stale ``taskrecord`` rows, wipe ``__crashed__``
      ``workflow_state_cursor`` rows, reset the row to ``CREATED``,
      commit, submit fresh worker task(s).
    * Best-effort ``kind='recovery'`` ledger event via
      :func:`ResilienceLayer.emit_recovery_event` after a successful
      re-enqueue (RFC-07 #31 audit trail).
    * A per-row failure logs and yields ``skipped_error`` -- the sweep
      continues with the next id.
    """
    inv_id = candidate.inv_id
    seen_ts = candidate.seen_timestamp

    if seen_ts is None:
        _log.warning(
            "recovery_service[stuck][%s]: inv=%s missing seen_timestamp; "
            "cannot claim, skipping",
            binding.module_id, inv_id,
        )
        return RecoveryOutcome(
            inv_id=inv_id, strategy=RecoveryStrategy.STUCK_HEAL,
            status="skipped_error",
        )

    if not await PlatformRecoveryService.try_claim(
        inv_table=investigations_table,
        timestamp_column=binding.inv_timestamp_column,
        inv_id=inv_id,
        seen_timestamp=seen_ts,
    ):
        _log.info(
            "recovery_service[stuck][%s]: inv=%s lost claim to concurrent "
            "recovery sweep; skipping",
            binding.module_id, inv_id,
        )
        return RecoveryOutcome(
            inv_id=inv_id, strategy=RecoveryStrategy.STUCK_HEAL,
            status="skipped_race",
        )

    try:
        await reenqueue_investigation(
            inv_id,
            inv_model=binding.inv_model,
            fn_path_pattern=binding.fn_path_pattern,
            submit_one=binding.submit_one,
            branch_model=binding.branch_model,
            branch_status_active=binding.branch_status_active,
        )
    except ReenqueueInvestigationError as exc:
        # Investigation row vanished between SELECT and lock. Log and
        # skip; the next tick's SELECT will not surface it again.
        _log.info(
            "recovery_service[stuck][%s]: inv=%s no longer present: %s",
            binding.module_id, inv_id, exc,
        )
        return RecoveryOutcome(
            inv_id=inv_id, strategy=RecoveryStrategy.STUCK_HEAL,
            status="no_op",
        )
    except (SQLAlchemyError, OSError, RuntimeError, ValueError) as exc:
        _log.warning(
            "recovery_service[stuck][%s]: re-enqueue failed inv=%s err=%s",
            binding.module_id, inv_id, exc,
        )
        return RecoveryOutcome(
            inv_id=inv_id, strategy=RecoveryStrategy.STUCK_HEAL,
            status="skipped_error",
        )

    # Journal the heal AFTER a successful re-enqueue. The signal inside
    # emit_recovery_event always fires; the durable ledger append is
    # best-effort inside the same call so a journal failure never rolls
    # the heal back.
    resilience = get_default_resilience_layer()
    await resilience.emit_recovery_event(
        investigation_id=inv_id,
        action="stuck_reenqueue",
        detail={
            "module_id": binding.module_id,
            "reason": "running_no_task_no_cursor",
        },
        source="stuck_healer",
    )
    return RecoveryOutcome(
        inv_id=inv_id, strategy=RecoveryStrategy.STUCK_HEAL,
        status="recovered", submits=1,
    )


# ---------------------------------------------------------------------------
# Service surface
# ---------------------------------------------------------------------------


class PlatformRecoveryService:
    """Unified eligibility, classification, AND execution surface.

    Every method is a ``staticmethod`` so this class is a stable
    namespace, never an object with state. Callers reach it as
    ``PlatformRecoveryService.<method>`` -- no factory, no injection.
    """

    # Re-export shared constants on the class surface so callers that
    # already import ``PlatformRecoveryService`` do not need a second
    # import to reach the sentinel tuples.
    NON_RESUMABLE_CURSOR_STATES = NON_RESUMABLE_CURSOR_STATES
    LIVE_TASK_STATUSES = LIVE_TASK_STATUSES

    # ---- Row classifier ------------------------------------------------

    @staticmethod
    def classify(
        *,
        status: str,
        has_live_task: bool,
        has_resumable_cursor: bool,
        stall_sweepable_statuses: tuple[str, ...] = (
            "created", "running", "stalled",
        ),
        stuck_running_statuses: tuple[str, ...] = ("running",),
    ) -> RecoveryStrategy | None:
        """Name the recovery strategy that applies to this row.

        Precedence (matches the pre-lift behavior when the two sweeps
        raced on the same row):

        * A live in-flight ``taskrecord`` blocks every sweep -> ``None``.
        * A ``running`` row with no resumable cursor matches
          ``STUCK_HEAL`` (the narrower zombie the reconciler cannot
          recover).
        * Otherwise ``created`` / ``running`` / ``stalled`` matches
          ``STALL_REENQUEUE`` (the broader Cancelled-error backstop).
        * Anything else -> ``None`` (paused / cancelled / completed /
          failed / abandoned rows are operator terminals or belong to
          another sweep).
        """
        if has_live_task:
            return None
        if (
            status in stuck_running_statuses
            and not has_resumable_cursor
        ):
            return RecoveryStrategy.STUCK_HEAL
        if status in stall_sweepable_statuses:
            return RecoveryStrategy.STALL_REENQUEUE
        return None

    # ---- Eligibility SELECTs -------------------------------------------

    @staticmethod
    async def fetch_stall_candidates(
        *,
        investigations_table: str,
        sweepable_kinds: tuple[str, ...],
        cutoff: datetime,
        limit: int,
    ) -> list[dict[str, Any]]:
        """SELECT rows eligible for :attr:`RecoveryStrategy.STALL_REENQUEUE`.

        Returns rows whose::

            status IN ('created', 'running', 'stalled')
            AND pause_reason IS NULL
            AND kind = ANY(:kinds)
            AND (status = 'stalled' OR updated_at < :cutoff)
            AND NO in-flight ``taskrecord`` references this inv

        Cursor state is intentionally NOT filtered here: a running row
        whose task died still needs recovery even if its cursor is
        resumable (the task-level reconciler owns the resumable-cursor
        path, but it only runs when a taskrecord still exists).

        The ``investigations_table`` identifier is a trusted module
        constant interpolated into the SQL body -- Postgres disallows
        bind parameters for identifiers.
        """
        stmt = _sql_text(
            f"""
            SELECT inv.id::text AS id,
                   inv.kind AS kind,
                   inv.status AS status,
                   inv.team_id::text AS team_id,
                   inv.updated_at AS updated_at
            FROM {investigations_table} inv
            WHERE inv.status IN ('created', 'running', 'stalled')
              AND inv.pause_reason IS NULL
              AND inv.kind = ANY(:kinds)
              AND (inv.status = 'stalled' OR inv.updated_at < :cutoff)
              AND NOT EXISTS (
                  SELECT 1
                  FROM taskrecord t
                  WHERE t.kwargs_json::jsonb->>'investigation_id'
                        = inv.id::text
                    AND t.status = ANY(:live_task_statuses)
              )
            ORDER BY inv.updated_at ASC
            LIMIT :limit
            """,
        ).bindparams(
            kinds=list(sweepable_kinds),
            cutoff=cutoff,
            live_task_statuses=list(LIVE_TASK_STATUSES),
            limit=limit,
        )
        async with async_session_scope() as session:
            return [
                dict(r)
                for r in (await session.execute(stmt)).mappings().all()
            ]

    @staticmethod
    async def fetch_stuck_candidates(
        *,
        investigations_table: str,
        running_status_values: tuple[str, ...],
        inv_timestamp_column: str,
        cutoff: datetime,
        limit: int,
    ) -> list[tuple[str, datetime]]:
        """SELECT rows eligible for :attr:`RecoveryStrategy.STUCK_HEAL`.

        Returns ``(id, timestamp)`` pairs whose::

            status = ANY(:running_values)
            AND <inv_timestamp_column> < :cutoff
            AND NO in-flight ``taskrecord`` references this inv
            AND NO ``workflow_state_cursor`` for this inv is resumable

        The paired timestamp is the caller's compare-and-set guard for
        :func:`try_claim_recovery` so the mutual exclusion with the
        stall sweep needs no second SELECT round-trip.

        Both identifiers (table name + timestamp column) are trusted
        module constants -- see ``fetch_stall_candidates`` for the
        identifier-interpolation rationale.
        """
        stmt = _sql_text(
            f"""
            SELECT inv.id::text AS id,
                   inv.{inv_timestamp_column} AS seen_ts
            FROM {investigations_table} inv
            WHERE inv.status = ANY(:running_values)
              AND inv.{inv_timestamp_column} < :cutoff
              AND NOT EXISTS (
                  SELECT 1
                  FROM taskrecord t
                  WHERE t.kwargs_json::jsonb->>'investigation_id'
                        = inv.id::text
                    AND t.status = ANY(:live_task_statuses)
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM workflow_state_cursor c
                  WHERE c.investigation_id = inv.id::text
                    AND c.current_state <> ALL(:non_resumable_states)
              )
            ORDER BY inv.{inv_timestamp_column} ASC
            LIMIT :lim
            """,
        ).bindparams(
            running_values=list(running_status_values),
            cutoff=cutoff,
            live_task_statuses=list(LIVE_TASK_STATUSES),
            non_resumable_states=list(NON_RESUMABLE_CURSOR_STATES),
            lim=limit,
        )
        async with async_session_scope() as session:
            return [
                (r["id"], r["seen_ts"])
                for r in (await session.execute(stmt)).mappings().all()
            ]

    # ---- Claim primitives ---------------------------------------------

    @staticmethod
    async def try_claim(
        *,
        inv_table: str,
        timestamp_column: str,
        inv_id: str,
        seen_timestamp: datetime,
    ) -> bool:
        """Compare-and-set on the row's timestamp column.

        Thin passthrough to
        :func:`aila.platform.services.recovery_claim.try_claim_recovery`
        so callers that reach the service surface do not also need a
        second import. The primitive itself is unchanged (issue #121
        mutual exclusion contract is preserved verbatim).
        """
        return await try_claim_recovery(
            inv_table=inv_table,
            timestamp_column=timestamp_column,
            inv_id=inv_id,
            seen_timestamp=seen_timestamp,
        )

    @staticmethod
    async def try_stalled_status_flip(
        *,
        investigations_table: str,
        inv_id: str,
    ) -> bool | None:
        """Atomic ``status='stalled' -> 'running'`` flip.

        Returns ``True`` when this caller flipped the row (owns the
        recovery), ``False`` when a concurrent racer beat us to the
        flip (skip this tick), and ``None`` on a transport-layer error
        (also skip -- the caller logs and continues). The
        ``WHERE status='stalled'`` clause matches at most one racer, so
        ``rowcount == 1`` is the winning-claim signal.

        Only relevant to :attr:`RecoveryStrategy.STALL_REENQUEUE` rows
        whose ``status='stalled'`` -- the stalled state needs its
        status flipped before the setup handler will accept a fresh
        submit, and the flip itself doubles as the mutual-exclusion
        claim for that path.
        """
        stmt = _sql_text(
            f"""
            UPDATE {investigations_table}
            SET status = 'running',
                updated_at = NOW()
            WHERE id = :inv_id
              AND status = 'stalled'
            """,
        ).bindparams(inv_id=inv_id)
        try:
            async with async_session_scope() as session:
                result = await session.execute(stmt)
                await session.commit()
        except (OSError, RuntimeError, SQLAlchemyError):
            _log.warning(
                "recovery_service: stalled->running flip failed inv=%s",
                inv_id, exc_info=True,
            )
            return None
        return bool(result.rowcount or 0)

    # ---- Unified dispatcher -------------------------------------------

    @staticmethod
    async def recover(
        *,
        binding: RecoveryBinding,
        candidate: RecoveryCandidate,
        remaining_cap: int = 1,
        stall_result: StallRecoveryResult | None = None,
    ) -> RecoveryOutcome:
        """Run one row through its classified strategy.

        Explicit strategy dispatch on ``candidate.strategy``:

        * :attr:`RecoveryStrategy.STALL_REENQUEUE` -- calls
          :func:`_execute_stall` (rate-limited fan-out submit, atomic
          claim). Requires ``binding.stall``. Accepts ``remaining_cap``
          (max submits this row may perform before the sweep-level rate
          cap is exhausted) and mutates ``stall_result`` in place.
        * :attr:`RecoveryStrategy.STUCK_HEAL` -- calls
          :func:`_execute_stuck` (four-source-of-truth reset + ledger
          event). Requires ``binding.stuck``.

        Callers that use ``recover`` directly (outside a sweep) can pass
        ``remaining_cap=1`` for a single submit and ignore
        ``stall_result``; a fresh :class:`StallRecoveryResult` is created
        internally so counters do not leak into the caller's state.
        """
        strategy = candidate.strategy
        if strategy is RecoveryStrategy.STALL_REENQUEUE:
            if binding.stall is None:
                msg = (
                    "PlatformRecoveryService.recover: STALL_REENQUEUE "
                    "candidate but binding.stall is None"
                )
                raise ValueError(msg)
            return await _execute_stall(
                investigations_table=binding.investigations_table,
                binding=binding.stall,
                candidate=candidate,
                result=stall_result or StallRecoveryResult(),
                remaining_cap=remaining_cap,
            )
        if strategy is RecoveryStrategy.STUCK_HEAL:
            if binding.stuck is None:
                msg = (
                    "PlatformRecoveryService.recover: STUCK_HEAL "
                    "candidate but binding.stuck is None"
                )
                raise ValueError(msg)
            return await _execute_stuck(
                investigations_table=binding.investigations_table,
                binding=binding.stuck,
                candidate=candidate,
            )
        msg = f"PlatformRecoveryService.recover: unknown strategy {strategy!r}"
        raise ValueError(msg)

    # ---- Unified sweep ------------------------------------------------

    @staticmethod
    async def sweep(
        *,
        binding: RecoveryBinding,
        only_strategy: RecoveryStrategy | None = None,
    ) -> UnifiedRecoveryResult:
        """Fetch every candidate, classify, dispatch.

        One periodic sweep for both strategies. The two pre-lift
        entrypoints (``sweep_stalled_investigations`` /
        ``sweep_stuck_investigations``) are thin wrappers that call this
        with ``only_strategy`` set; a module that wires BOTH strategies
        can register this callable directly for a single per-tick sweep
        that fetches both candidate sets in the same run.

        Processing order when both strategies are active:

        1. STUCK candidates first -- the narrower zombie whose recovery
           (``reenqueue_investigation``) also cancels stale taskrecords
           that would confuse a subsequent STALL submit.
        2. STALL candidates second, skipping any inv id already healed
           by STUCK in this tick. Race is already neutralized by
           :func:`try_claim_recovery`; the explicit skip is a clarity
           guard and saves one round-trip per overlap row.

        Rate limits stay per-strategy:

        * STALL: ``rate_per_tick`` caps total task submits (branch fan-
          out counts) -- default 6, env ``<PREFIX>_LIMIT``.
        * STUCK: ``max_heals_per_tick`` caps investigations healed --
          default 5, config ``stuck_healer_max_heals_per_tick``.

        Failure modes stay per-row: an eligibility-SELECT SQLAlchemy
        error inside one strategy is logged and that strategy's slice
        contributes zero this tick; the other strategy still runs.
        """
        summary = UnifiedRecoveryResult()

        want_stall = (
            binding.stall is not None
            and only_strategy is not RecoveryStrategy.STUCK_HEAL
        )
        want_stuck = (
            binding.stuck is not None
            and only_strategy is not RecoveryStrategy.STALL_REENQUEUE
        )

        stall_rows, stall_cap = await _prepare_stall_fetch(
            binding=binding, want_stall=want_stall, summary=summary,
        )
        stuck_pairs, stuck_cap = await _prepare_stuck_fetch(
            binding=binding, want_stuck=want_stuck, summary=summary,
        )

        healed_ids: set[str] = set()

        # STUCK first (precedence). Per-inv cap already applied by the
        # SELECT ``LIMIT :lim``; no mid-loop cap check needed.
        if want_stuck and binding.stuck is not None and stuck_pairs:
            for inv_id, seen_ts in stuck_pairs:
                candidate = RecoveryCandidate(
                    inv_id=inv_id,
                    strategy=RecoveryStrategy.STUCK_HEAL,
                    seen_timestamp=seen_ts,
                )
                outcome = await PlatformRecoveryService.recover(
                    binding=binding, candidate=candidate,
                )
                summary.outcomes.append(outcome)
                if outcome.status == "recovered":
                    summary.stuck.healed += 1
                    summary.stuck.ids.append(inv_id)
                    healed_ids.add(inv_id)

            if summary.stuck.healed:
                _log.info(
                    "recovery_service[stuck][%s]: examined=%d healed=%d ids=%s",
                    binding.stuck.module_id, summary.stuck.examined,
                    summary.stuck.healed, summary.stuck.ids,
                )

        # STALL second, skipping any inv already healed by STUCK.
        if want_stall and binding.stall is not None and stall_rows:
            for row in stall_rows:
                inv_id = row["id"]
                if inv_id in healed_ids:
                    continue
                if summary.stall.enqueued >= stall_cap:
                    # Per-investigation skip count (not per-branch).
                    # One inv that would have produced 6 submits still
                    # counts as 1.
                    summary.stall.skipped_rate_cap += 1
                    continue

                inv_status = row.get("status", "running")
                # Sanity: the SELECT already applied the sweepable-kind
                # and status filters, but the classifier is where the
                # unified eligibility contract lives -- run it so a
                # future SELECT edit cannot silently diverge from the
                # platform decision. Cursor state is not consulted at
                # the SELECT level for this path;
                # ``has_resumable_cursor=True`` routes running-with-
                # cursor rows to STALL_REENQUEUE rather than STUCK_HEAL,
                # matching pre-lift behavior.
                strategy = PlatformRecoveryService.classify(
                    status=inv_status,
                    has_live_task=False,
                    has_resumable_cursor=True,
                )
                if strategy is not RecoveryStrategy.STALL_REENQUEUE:
                    continue

                candidate = RecoveryCandidate(
                    inv_id=inv_id,
                    strategy=RecoveryStrategy.STALL_REENQUEUE,
                    kind=row["kind"],
                    status=inv_status,
                    team_id=row["team_id"],
                    seen_updated_at=row["updated_at"],
                )
                remaining = stall_cap - summary.stall.enqueued
                outcome = await PlatformRecoveryService.recover(
                    binding=binding,
                    candidate=candidate,
                    remaining_cap=remaining,
                    stall_result=summary.stall,
                )
                summary.outcomes.append(outcome)

            if summary.stall.enqueued or summary.stall.skipped_rate_cap:
                _log.info(
                    "recovery_service[stall]: examined=%d enqueued=%d "
                    "skipped_rate_cap=%d by_kind=%s recovered=%d",
                    summary.stall.examined, summary.stall.enqueued,
                    summary.stall.skipped_rate_cap,
                    dict(summary.stall.by_kind_enqueued),
                    len(summary.stall.investigations_recovered),
                )

        # Silence unused-variable warning: stuck_cap is derived for
        # logging symmetry with stall_cap; the SELECT LIMIT does the
        # cap job for STUCK so nothing after this point reads it.
        del stuck_cap

        return summary


async def _prepare_stall_fetch(
    *,
    binding: RecoveryBinding,
    want_stall: bool,
    summary: UnifiedRecoveryResult,
) -> tuple[list[dict[str, Any]], int]:
    """Resolve STALL knobs, run the SELECT, populate ``summary.stall``.

    Returns ``(rows, cap)``. ``rows`` is empty when the strategy is
    disabled / SELECT failed / cap is non-positive; ``cap`` is 0 in
    those cases so the caller's ``enqueued >= cap`` check always
    short-circuits.
    """
    if not want_stall or binding.stall is None:
        return [], 0
    b = binding.stall
    idle = b.idle_minutes if b.idle_minutes is not None else _env_int(
        f"{b.env_prefix}_IDLE_MIN", DEFAULT_STALL_IDLE_MIN,
    )
    cap = b.rate_per_tick if b.rate_per_tick is not None else _env_int(
        f"{b.env_prefix}_LIMIT", DEFAULT_STALL_RATE_PER_TICK,
    )
    if cap <= 0:
        _log.warning(
            "recovery_service[stall]: rate_per_tick=%d <= 0; skipping tick",
            cap,
        )
        return [], 0
    cutoff = datetime.now(UTC) - timedelta(minutes=idle)
    # Over-fetch eligible rows so the loop has headroom when some rows
    # turn out to have zero active branches (creates 1 submit each,
    # not the per-row average). Capped at ``max(cap*3, 30)`` to keep
    # the SELECT bounded under unusual backlog conditions.
    try:
        rows = await PlatformRecoveryService.fetch_stall_candidates(
            investigations_table=binding.investigations_table,
            sweepable_kinds=b.sweepable_kinds,
            cutoff=cutoff,
            limit=max(cap * 3, 30),
        )
    except SQLAlchemyError as exc:
        _log.warning(
            "recovery_service[stall]: eligibility SELECT failed: %s", exc,
        )
        return [], 0
    summary.stall.examined = len(rows)
    return rows, cap


async def _prepare_stuck_fetch(
    *,
    binding: RecoveryBinding,
    want_stuck: bool,
    summary: UnifiedRecoveryResult,
) -> tuple[list[tuple[str, datetime]], int]:
    """Resolve STUCK knobs, run the SELECT, populate ``summary.stuck``.

    Returns ``(pairs, cap)``. Same short-circuit contract as
    :func:`_prepare_stall_fetch`.
    """
    if not want_stuck or binding.stuck is None:
        return [], 0
    b = binding.stuck
    grace_s = b.idle_grace_s if b.idle_grace_s is not None else (
        await _resolve_int_config(
            b.module_id, CONFIG_KEY_IDLE_GRACE_S, DEFAULT_STUCK_IDLE_GRACE_S,
        )
    )
    cap = b.max_heals_per_tick if b.max_heals_per_tick is not None else (
        await _resolve_int_config(
            b.module_id, CONFIG_KEY_MAX_HEALS_PER_TICK,
            DEFAULT_STUCK_MAX_HEALS_PER_TICK,
        )
    )
    if cap <= 0:
        _log.warning(
            "recovery_service[stuck][%s]: max_heals_per_tick=%d <= 0; "
            "skipping tick",
            b.module_id, cap,
        )
        return [], 0
    cutoff = datetime.now(UTC) - timedelta(seconds=grace_s)
    try:
        pairs = await PlatformRecoveryService.fetch_stuck_candidates(
            investigations_table=binding.investigations_table,
            running_status_values=b.running_status_values,
            inv_timestamp_column=b.inv_timestamp_column,
            cutoff=cutoff,
            limit=cap,
        )
    except SQLAlchemyError as exc:
        _log.warning(
            "recovery_service[stuck][%s]: eligibility SELECT failed: %s",
            b.module_id, exc,
        )
        return [], 0
    summary.stuck.examined = len(pairs)
    return pairs, cap
