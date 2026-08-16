"""Router negative-feedback consumer (issue #161 consumer half).

The auto-steering write path in
:mod:`aila.platform.agents.auto_steering` populates
``router_negative_example`` (migration 128) with one row per steering
fire -- a ground-truth routing failure signal
``(task_shape, model, tool, rule_fired)``. This module is the
consumer half:

* :func:`retune_router_from_negatives` -- the nightly automation
  handler. Drains new ``router_negative_example`` rows above the
  ``platform.routing_negative_hwm`` config high-water mark, aggregates
  them by ``(task_shape, model, tool)`` into ``router_hard_negative``
  (migration 129), and advances the HWM. Idempotent; a repeat tick
  with nothing new is a bounded no-op.

* :func:`augment_history_provider_with_hard_negatives` -- the
  learner-facing hook. Wraps a
  :data:`aila.platform.eval.routing_learner.HistoryProvider` so every
  ``recommend`` call unions the module's real outcome-review samples
  with synthetic REJECT :class:`RoutingSample` rows derived from the
  aggregate. Consumed through the RoutingLearner's existing
  sample-based scoring surface -- no learner-side changes needed.
  Wiring at :mod:`aila.platform.workflows.investigation_setup_base`
  is gated by ``platform.routing_negative_feedback_enabled`` (default
  False) so an operator can accrue the aggregate independently of
  activating the fold.

Contract notes:

* The retune action is registered by
  :func:`aila.platform.automation.maintenance.register_maintenance_actions`
  under ``action_id="platform.routing_negative_retune"``. Registration
  alone does not run it; :mod:`aila.platform.automation.seed_schedules`
  seeds a default-DISABLED schedule so an operator activates the tick
  cadence via ``PATCH /automation/schedules``.

* The augmenter treats aggregate rows as ``target_kind``-agnostic
  broadcast negatives: the source ``router_negative_example`` schema
  does not carry ``target_kind``, so every synthetic sample is stamped
  with the caller's queried ``target_kind`` at fold time. This is
  intentional -- a tool that repeatedly needed steering intervention
  is a hard negative for any target_kind that would route to it. Real
  outcome-review samples continue to carry their own ``target_kind``
  from the module tables; the fold does not override them.

* The synthetic samples use ``task_type=tool`` (the tool key
  ``"{server_id}.{tool_name}"``) and ``cost_usd=0.0``. When the
  learner scores task_types via
  ``approval_rate - cost_weight * normalized_cost``, an aggregate
  bucket with hit_count>=``min_evidence`` collapses to
  ``approval_rate=0`` for its task_type. See
  :meth:`RoutingLearner.recommend_from_history` for the aggregation.

* Each synthetic sample emits ``min(hit_count, _MAX_SYNTHETIC_PER_ROW)``
  copies so a runaway bucket (thousands of steering fires on one tool)
  cannot inflate the learner's in-memory sample list past a bounded
  per-row ceiling. The learner reads ``approval_rate`` off the group,
  so more than the min-evidence floor of REJECTs adds no scoring
  signal -- the cap is a memory guard, not a scoring knob.

Remaining follow-up (out of scope for this slice, see issue #161):

* A/B evaluation of the re-tuned router vs the pre-fold baseline. The
  aggregate + the fold hook land here; comparing routing choices
  before/after fold-on requires a shadow-report harness against the
  investigation_setup call path and is deferred.
"""
from __future__ import annotations

__all__ = [
    "RETUNE_ACTION_ID",
    "RouterNegativeRetuneReport",
    "augment_history_provider_with_hard_negatives",
    "retune_router_from_negatives",
]

import logging
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime
from typing import TypedDict

import sqlalchemy.exc
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlmodel import func as _sqlfunc
from sqlmodel import select

from aila.platform.contracts import utc_now
from aila.platform.eval.routing_learner import (
    HistoryProvider,
    RoutingSample,
)
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    RouterHardNegativeRecord,
    RouterNegativeExampleRecord,
)
from aila.storage.registry import ConfigRegistry

_log = logging.getLogger(__name__)

# Automation action id -- referenced by
# ``aila.platform.automation.maintenance.register_maintenance_actions``
# and ``aila.platform.automation.seed_schedules._DEFAULT_DISABLED_SCHEDULES``.
# Kept as a module constant so a rename here fails the register / seed
# call sites at import time rather than silently splitting the id.
RETUNE_ACTION_ID: str = "platform.routing_negative_retune"

# ConfigRegistry key holding the ISO-8601 UTC high-water-mark timestamp.
# Registered as a static field on
# :class:`aila.platform.config.PlatformConfigSchema`; the config layer
# resolves env -> DB -> schema-default so an operator can rewind the
# HWM with ``PUT /config/platform/routing_negative_hwm`` (or env
# ``AILA_PLATFORM_ROUTING_NEGATIVE_HWM``) without touching the aggregate.
_HWM_CONFIG_NS: str = "platform"
_HWM_CONFIG_KEY: str = "routing_negative_hwm"

# Row cap per retune tick. The source table is unindexed on
# ``created_at`` alone (it has ``ix_router_negative_example_created_at``)
# so a window scan is cheap, but an accrued backlog after a long
# schedule-disabled period could be huge. 5000 matches the
# ``_HISTORY_ROW_CAP`` cap in ``routing_history.py`` -- one tick drains
# 5000 rows, subsequent ticks catch up on the remainder. Operators can
# override via the ``retune_source_cap`` schedule kwarg below.
_DEFAULT_SOURCE_CAP: int = 5000

# Synthetic-sample cap per aggregate row at fold time. Bounded so a
# single runaway bucket (10k+ hits on one tool) cannot dominate the
# learner's in-memory sample list. The learner's approval_rate score
# saturates once the min_evidence floor is crossed with all-REJECT
# samples, so more copies add no scoring signal -- the cap is a
# memory guard, not a scoring knob.
_MAX_SYNTHETIC_PER_ROW: int = 25

# Cost stamp on every synthetic REJECT sample. Zero because the source
# corpus does not carry a per-fire cost. The learner's normalized_cost
# term multiplies by the group's mean_cost, so 0 for an all-REJECT
# synthetic group contributes ``approval_rate=0 - cost_weight * 0 = 0``
# (a strict hard negative). Real outcome-review samples continue to
# supply their real cost via the base provider.
_SYNTHETIC_COST_USD: float = 0.0

# NULL-model sentinel. The auto-steering write path does not plumb
# the routed model, so most source rows land with ``model=NULL``.
# The aggregate normalises to ``''`` so the unique constraint dedupes
# cleanly (Postgres treats NULL as distinct, which would let multiple
# ``model=NULL`` rows for the same tool sneak past the aggregate).
_MODEL_SENTINEL: str = ""
_TOOL_SENTINEL: str = ""


# Isolation tuple for the retune sweep. Same posture as the calibration
# / retrieval / shadow sweeps in ``maintenance.py``: every realistic
# infra fault on the read / aggregate / persist / HWM-update path is
# captured so one failure does not abort the whole tick. Bare ``except
# Exception`` is banned by honesty audit rule 33.
_RETUNE_ERRORS: tuple[type[BaseException], ...] = (
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

# Isolation tuple for the augmenter's per-recommend query. Wider than
# the retune sweep because a fold-time failure MUST degrade to the
# base provider's samples rather than raise into the setup path. The
# investigation_setup call site catches the recommend failure and
# falls back to the full panel; we prefer to never reach that path
# just because a synthetic-negative query hiccuped.
_AUGMENT_ERRORS: tuple[type[BaseException], ...] = (
    sqlalchemy.exc.SQLAlchemyError,
    OSError,
    TimeoutError,
    RuntimeError,
    ValueError,
    TypeError,
    LookupError,
    ConnectionError,
)


class RouterNegativeRetuneReport(TypedDict):
    """Structured result of one ``retune_router_from_negatives`` tick.

    Every field is always populated (0 when a stage was empty) so
    downstream consumers can rely on the shape without ``.get`` guards.
    ``errors`` names the failed stage plus the exception class -- full
    tracebacks land in the worker log via ``_log.warning(exc_info=exc)``.
    """

    source_rows_read: int
    buckets_upserted: int
    hwm_before: str
    hwm_after: str
    errors: list[str]


def _parse_hwm(raw: str | None) -> datetime:
    """Parse the HWM config value into a UTC datetime.

    Empty / missing / malformed -> epoch (``1970-01-01T00:00:00+00:00``)
    so the first tick after enabling the schedule drains every accrued
    row. A malformed value logs a warning but never raises: the retune
    action's contract is "advance forward or stay flat", not "crash on
    bad state".
    """
    if not raw or not raw.strip():
        return datetime.fromtimestamp(0, tz=UTC)
    try:
        parsed = datetime.fromisoformat(raw.strip())
    except (TypeError, ValueError):
        _log.warning(
            "routing_negative_retune: malformed HWM %r; treating as epoch",
            raw,
        )
        return datetime.fromtimestamp(0, tz=UTC)
    if parsed.tzinfo is None:
        # Legacy tz-naive value; assume UTC rather than blindly
        # aware-ifying to the runner's local tz.
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _coerce_int(raw: object, default: int) -> int:
    """Best-effort int cast for schedule-supplied kwargs.

    Mirrors the same helper used by the calibration / retrieval sweeps
    so bad operator input degrades to the default rather than raising.
    """
    if raw is None:
        return default
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


async def retune_router_from_negatives(
    **kwargs: object,
) -> RouterNegativeRetuneReport:
    """Drain new ``router_negative_example`` rows into the aggregate.

    Called by :class:`AutomationRunner` when an operator has enabled
    the default-disabled ``platform.routing_negative_retune`` schedule.
    Runner-injected metadata (``target_name`` / ``execution_context``)
    is swallowed so the bare-callable ``**kwargs`` path does not reject
    unknown keys.

    ``action_kwargs_json`` on the schedule row MAY carry:

    * ``retune_source_cap``: max source rows drained per tick
      (int > 0); default 5000. Bounds the per-tick memory footprint
      when catching up on a long backlog; subsequent ticks continue
      draining beyond the cap.

    Behaviour:

    1. Read the current HWM via :class:`ConfigRegistry`.
    2. SELECT the oldest ``retune_source_cap`` rows from
       ``router_negative_example`` with ``created_at > HWM``, ordered
       ASC so the HWM advances monotonically.
    3. Aggregate in-memory by ``(task_shape, model_or_sentinel,
       tool_or_sentinel)`` and UPSERT one row per bucket into
       ``router_hard_negative``, incrementing ``hit_count`` and
       advancing ``last_seen_at`` on conflict.
    4. Advance the HWM to the max ``created_at`` observed.

    Idempotent: a repeat tick with nothing new is a bounded no-op
    (empty SELECT -> zero UPSERTs -> HWM unchanged). Every stage
    isolates its own failures; the tick NEVER raises, and the returned
    report captures the error trail so the schedule's
    ``last_run_result`` snapshot is self-describing.
    """
    # Runner-injected metadata -- swallowed so the bare-callable path
    # doesn't reject the unknown keys.
    _ = kwargs.pop("target_name", None)
    _ = kwargs.pop("execution_context", None)

    source_cap = _coerce_int(
        kwargs.get("retune_source_cap"), _DEFAULT_SOURCE_CAP,
    )

    report: RouterNegativeRetuneReport = {
        "source_rows_read": 0,
        "buckets_upserted": 0,
        "hwm_before": "",
        "hwm_after": "",
        "errors": [],
    }

    registry = ConfigRegistry()
    try:
        raw_hwm = await registry.get(_HWM_CONFIG_NS, _HWM_CONFIG_KEY)
    except _RETUNE_ERRORS as exc:
        _log.warning(
            "routing_negative_retune: HWM read failed (%s); treating as epoch",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"hwm_read:{type(exc).__name__}")
        raw_hwm = None

    hwm = _parse_hwm(raw_hwm if isinstance(raw_hwm, str) else None)
    report["hwm_before"] = hwm.isoformat()

    # Aggregate keyed by (task_shape, model_sentinel, tool_sentinel).
    # Value is (hit_count, max_created_at) so the UPSERT knows both
    # what to increment and where to advance last_seen_at.
    buckets: dict[tuple[str, str, str], tuple[int, datetime]] = {}
    max_created_at: datetime = hwm

    try:
        async with async_session_scope() as session:
            stmt = (
                select(RouterNegativeExampleRecord)
                .where(RouterNegativeExampleRecord.created_at > hwm)
                .order_by(RouterNegativeExampleRecord.created_at.asc())
                .limit(source_cap)
            )
            rows = (await session.exec(stmt)).all()
    except _RETUNE_ERRORS as exc:
        _log.warning(
            "routing_negative_retune: source read failed (%s); no advance",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"source_read:{type(exc).__name__}")
        report["hwm_after"] = report["hwm_before"]
        return report

    report["source_rows_read"] = len(rows)

    for row in rows:
        task_shape = (row.task_shape or "").strip()
        if not task_shape:
            # Corpus write path always populates task_shape; a blank is
            # a schema violation, skip it rather than folding an empty
            # bucket into the aggregate.
            continue
        model = (row.model or _MODEL_SENTINEL).strip() or _MODEL_SENTINEL
        tool = (row.tool or _TOOL_SENTINEL).strip() or _TOOL_SENTINEL
        key = (task_shape, model, tool)
        existing = buckets.get(key)
        if existing is None:
            buckets[key] = (1, row.created_at)
        else:
            prior_count, prior_seen = existing
            buckets[key] = (
                prior_count + 1,
                max(prior_seen, row.created_at),
            )
        if row.created_at > max_created_at:
            max_created_at = row.created_at

    if not buckets:
        # No new rows above the HWM -- no aggregate writes, HWM stays
        # exactly where it was. Log at INFO so an operator watching the
        # schedule's last_run_result sees the successful no-op.
        report["hwm_after"] = report["hwm_before"]
        _log.info(
            "routing_negative_retune: no new source rows above hwm=%s",
            report["hwm_before"],
        )
        return report

    # UPSERT one row per bucket. Postgres INSERT ... ON CONFLICT lets
    # us do this in a single statement per bucket; batching in Python
    # is fine (buckets is bounded by source_cap distinct combos).
    # Uses ``session.execute`` (not ``.exec``) because ``pg_insert``
    # is a raw SQLAlchemy Core statement -- matches the pattern in
    # ``aila.platform.llm.idempotency_cache.store_response`` and
    # ``aila.platform.services.ledger.append_general``.
    upserted = 0
    now = utc_now()
    try:
        async with async_session_scope() as session:
            for (task_shape, model, tool), (hits, seen_at) in buckets.items():
                insert_stmt = pg_insert(
                    RouterHardNegativeRecord.__table__,
                ).values(
                    task_shape=task_shape,
                    model=model,
                    tool=tool,
                    hit_count=hits,
                    first_seen_at=now,
                    last_seen_at=seen_at,
                )
                # ON CONFLICT on the (task_shape, model, tool) unique
                # constraint: increment hit_count by the new tick's
                # count and advance last_seen_at to the newer of the
                # existing value or this tick's max.
                upsert_stmt = insert_stmt.on_conflict_do_update(
                    constraint="uq_router_hard_negative_shape_model_tool",
                    set_={
                        "hit_count": (
                            RouterHardNegativeRecord.__table__.c.hit_count
                            + insert_stmt.excluded.hit_count
                        ),
                        "last_seen_at": _sqlfunc.greatest(
                            RouterHardNegativeRecord.__table__.c.last_seen_at,
                            insert_stmt.excluded.last_seen_at,
                        ),
                    },
                )
                await session.execute(upsert_stmt)
                upserted += 1
            await session.commit()
    except _RETUNE_ERRORS as exc:
        _log.warning(
            "routing_negative_retune: aggregate upsert failed (%s); "
            "HWM not advanced",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"aggregate_upsert:{type(exc).__name__}")
        report["hwm_after"] = report["hwm_before"]
        return report

    report["buckets_upserted"] = upserted

    new_hwm_str = max_created_at.astimezone(UTC).isoformat()
    try:
        await registry.set(
            _HWM_CONFIG_NS, _HWM_CONFIG_KEY, new_hwm_str,
        )
        report["hwm_after"] = new_hwm_str
    except _RETUNE_ERRORS as exc:
        # Aggregate is already persisted; a HWM write failure means the
        # next tick will re-drain the same rows and the UPSERT will
        # simply double-count them into hit_count. That is a real
        # over-count risk, so surface it as an error even though the
        # tick itself made forward progress on the aggregate.
        _log.warning(
            "routing_negative_retune: HWM write failed (%s); next tick "
            "will re-fold the same source rows",
            type(exc).__name__, exc_info=exc,
        )
        report["errors"].append(f"hwm_write:{type(exc).__name__}")
        report["hwm_after"] = report["hwm_before"]

    _log.info(
        "routing_negative_retune completed source_rows=%d buckets_upserted=%d "
        "hwm=%s errors=%d",
        report["source_rows_read"], report["buckets_upserted"],
        report["hwm_after"], len(report["errors"]),
    )
    return report


async def _load_synthetic_negatives(
    target_kind: str,
) -> Sequence[RoutingSample]:
    """Return synthetic REJECT samples for the queried target_kind.

    One aggregate row -> ``min(hit_count, _MAX_SYNTHETIC_PER_ROW)``
    identical :class:`RoutingSample` rows with ``task_type=tool_key``
    (or ``task_type=task_shape`` when tool is the sentinel), so the
    learner's per-task_type grouping sees them as a distinct bucket
    of pure REJECTs. Returns an empty sequence on any failure so the
    augmenter degrades to the base provider's samples untouched.
    """
    samples: list[RoutingSample] = []
    try:
        async with async_session_scope() as session:
            stmt = select(RouterHardNegativeRecord)
            rows = (await session.exec(stmt)).all()
    except _AUGMENT_ERRORS as exc:
        _log.warning(
            "routing_negative_feedback: aggregate read failed "
            "target_kind=%s (%s); folding zero synthetic negatives",
            target_kind, type(exc).__name__, exc_info=exc,
        )
        return []

    for row in rows:
        # Prefer the tool key as the synthetic task_type; fall back to
        # task_shape when tool was the sentinel (auto_steering fires
        # that carry no tool identifier -- non-tool steering rules
        # like dispatch-stall escalation).
        tool_key = row.tool if row.tool != _TOOL_SENTINEL else ""
        synthetic_task_type = tool_key or row.task_shape
        if not synthetic_task_type:
            continue
        copies = min(max(int(row.hit_count), 1), _MAX_SYNTHETIC_PER_ROW)
        for _ in range(copies):
            samples.append(
                RoutingSample(
                    target_kind=target_kind,
                    task_type=synthetic_task_type,
                    verdict="reject",
                    cost_usd=_SYNTHETIC_COST_USD,
                ),
            )
    return samples


def augment_history_provider_with_hard_negatives(
    base_provider: HistoryProvider,
) -> HistoryProvider:
    """Wrap a routing history provider so it unions synthetic REJECTs.

    Every call to the returned provider queries
    ``router_hard_negative`` for the queried ``target_kind`` and
    unions the aggregate-derived synthetic REJECT samples with the
    base provider's real outcome-review samples. The unioned stream
    goes into :meth:`RoutingLearner.recommend_from_history` unchanged;
    no learner-side wiring is needed.

    Failure isolation:

    * A base-provider raise propagates unchanged -- the base provider
      is the caller's authoritative source; a fault there is not
      something the augmenter should paper over.
    * An aggregate-side raise degrades to zero synthetic samples so
      the fold never turns a healthy base-provider recommend into a
      failed one.

    The wrapping is a pure function of the base provider; the returned
    coroutine holds no per-instance state. Safe to cache the wrapped
    provider on a module binding once at boot.
    """

    async def _wrapped(target_kind: str) -> Sequence[RoutingSample]:
        base_samples = await base_provider(target_kind)
        synthetic = await _load_synthetic_negatives(target_kind)
        if not synthetic:
            return base_samples
        # Union in a fresh list so we never mutate the base provider's
        # returned sequence (some providers cache).
        return list(base_samples) + list(synthetic)

    return _wrapped


# Re-exported type alias for callers that want to reference the
# provider shape without pulling the eval package directly.
NegativeHistoryProvider = Callable[[str], Awaitable[Sequence[RoutingSample]]]
