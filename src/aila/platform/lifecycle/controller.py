"""RFC-10 agent lifecycle control plane: stage machine + journal.

``AgentLifecycleController`` composes the RFC-08 ``EvalRunner`` (scoring)
and the RFC-09 ``PromptVersionStore`` (immutable versions + alias flips)
and adds a stage-guarded append-only journal on top. Callers move a
version through ``built`` to ``evaluated`` to ``approved`` to
``production``, or back to a prior production version via ``rollback``.
The controller decides whether an alias flip is allowed; the actual
flip stays owned by the version store, which records its own audit row
alongside ours.

The four primary entry points are ``evaluate``, ``approve``, ``promote``
and ``rollback``. Each writes exactly one ``LifecycleTransitionRecord``
row and returns it. ``evaluate`` delegates scoring to the runner with
``auto_promote=False`` so the runner never flips ``production`` behind
the controller's back; only ``promote`` may do that, and only when the
most recent evaluated transition for the (key, version) pair carries a
passing verdict AND at least ``platform.agent_promotion_quorum`` distinct
actor strings appear on ``approved`` rows for that same (key, version).
The RFC-10 acceptance criterion 1 ("cannot reach production without
passing the eval gate AND a quorum approval") is enforced here; the
RFC-08 eval-runner ``auto_promote`` fast path stays admin-opt-in and
rides the eval-only gate by design, not through this controller.
"""
from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass

from sqlmodel import func, select

from aila.platform.config import PlatformConfigSchema
from aila.platform.contracts._common import utc_now
from aila.platform.eval.runner import EvalRunner
from aila.platform.lifecycle.assignments import (
    AssignmentKind,
    AssignmentState,
    LifecycleCanaryAssignment,
)
from aila.platform.lifecycle.models import (
    LifecycleStage,
    LifecycleTransitionRecord,
)
from aila.platform.prompts.version_store import PromptVersionStore
from aila.storage.database import async_session_scope
from aila.storage.registry import ConfigRegistry

__all__ = [
    "PRODUCTION_ALIAS",
    "AgentLifecycleController",
    "CanaryHoldSignal",
    "CanarySignalOutcome",
    "CohortRoute",
    "StageTransitionError",
]

_log = logging.getLogger(__name__)

PRODUCTION_ALIAS = "production"


class StageTransitionError(RuntimeError):
    """Raised when a caller asks for a stage move the guard forbids.

    Four cases fire this: ``approve`` on a (key, version) with no prior
    passing ``evaluated`` transition; ``promote`` without a prior passing
    ``evaluated`` transition; ``promote`` with fewer distinct approvers
    than ``platform.agent_promotion_quorum`` demands; and ``rollback``
    with no prior production transition and no explicit ``target_version``.
    In every case the alias is left untouched.
    """


class AgentLifecycleController:
    """Own the stage machine + journal on top of eval + prompt-version-store.

    Constructor accepts optional ``eval_runner`` and ``version_store``
    collaborators so tests may inject shared instances. Passing neither
    is the production path: the controller wires a fresh
    ``PromptVersionStore`` and hands it to a fresh ``EvalRunner`` so
    baseline resolution and alias flips route through the same store.
    """

    def __init__(
        self,
        *,
        eval_runner: EvalRunner | None = None,
        version_store: PromptVersionStore | None = None,
    ) -> None:
        self._store = version_store or PromptVersionStore()
        self._runner = eval_runner or EvalRunner(self._store)

    async def evaluate(
        self,
        *,
        key: str,
        version: str,
        benchmark_id: str,
        actor: str = "",
    ) -> LifecycleTransitionRecord:
        """Score ``version`` against ``benchmark_id`` and journal a transition.

        Delegates to ``EvalRunner.run`` with ``auto_promote=False``. The
        eval verdict, referenced eval run id, and the full report
        payload land in ``metrics_snapshot_json`` on the resulting
        transition row so ``promote`` can gate on the verdict without
        replaying the scoring. ``from_stage`` is ``built`` on the
        first-ever evaluate for the (key, version) pair; a re-eval
        preserves whatever the version's most recent ``to_stage`` was
        (typically ``evaluated``).
        """
        run = await self._runner.run(
            key=key,
            candidate_version=version,
            benchmark_id=benchmark_id,
            auto_promote=False,
            actor=actor,
        )
        prior_to_stage = await self._latest_stage(key=key, version=version)
        from_stage = (
            prior_to_stage
            if prior_to_stage is not None
            else LifecycleStage.BUILT.value
        )
        snapshot: dict[str, object] = {
            "verdict": run.verdict,
            "eval_run_id": run.id,
            "benchmark_id": run.benchmark_id,
            "candidate_version": run.candidate_version,
            "baseline_version": run.baseline_version,
            "report": json.loads(run.report_json),
        }
        _log.info(
            "lifecycle.evaluate key=%s version=%s verdict=%s from_stage=%s",
            key, version, run.verdict, from_stage,
        )
        return await self._journal(
            key=key,
            version=version,
            from_stage=from_stage,
            to_stage=LifecycleStage.EVALUATED.value,
            actor=actor,
            reason=f"eval benchmark_id={benchmark_id}",
            metrics_snapshot_json=json.dumps(snapshot),
        )

    async def approve(
        self,
        *,
        key: str,
        version: str,
        actor: str = "",
        reason: str = "",
    ) -> LifecycleTransitionRecord:
        """Journal a quorum approval for (key, version) after eval passed.

        Guard: the most recent ``evaluated`` transition for (key, version)
        must carry ``verdict == 'pass'`` in its metrics snapshot -- the
        same query shape ``promote`` uses. Raises ``StageTransitionError``
        otherwise; no journal row is written. On success, records an
        ``evaluated`` to ``approved`` transition; ``actor`` becomes one
        of the distinct approvers ``promote`` later counts against
        ``platform.agent_promotion_quorum``. Two rows with the same
        ``actor`` string count as one approver, so a single reviewer
        cannot lift the quorum by re-signing.
        """
        evidence = await self._passing_evaluate(key=key, version=version)
        if evidence is None:
            raise StageTransitionError(
                f"cannot approve key={key!r} version={version!r}: "
                "no prior passing 'evaluated' transition on record",
            )
        snapshot: dict[str, object] = {
            "eval_run_id": evidence.get("eval_run_id"),
            "verdict": evidence.get("verdict"),
        }
        _log.info(
            "lifecycle.approve key=%s version=%s actor=%s",
            key, version, actor,
        )
        return await self._journal(
            key=key,
            version=version,
            from_stage=LifecycleStage.EVALUATED.value,
            to_stage=LifecycleStage.APPROVED.value,
            actor=actor,
            reason=reason,
            metrics_snapshot_json=json.dumps(snapshot),
        )

    async def promote(
        self,
        *,
        key: str,
        version: str,
        actor: str = "",
        reason: str = "",
    ) -> LifecycleTransitionRecord:
        """Flip the production alias to ``version`` when both gates allow.

        Two-part guard, enforcing the RFC-10 acceptance criterion
        ("eval gate AND quorum approval"):

        1. The most recent ``evaluated`` transition for (key, version)
           must carry ``verdict == 'pass'`` in its metrics snapshot.
        2. The number of DISTINCT actor strings on ``approved``
           transitions for the same (key, version) must be at least
           ``platform.agent_promotion_quorum`` (default 1).

        Either check failing raises ``StageTransitionError`` with the
        specific gap named; the alias is not touched because the version
        store call sits after both checks. On success, records an
        ``evaluated`` to ``production`` transition that packs the passing
        eval run id and the observed approver count into the metrics
        snapshot so the journal answers "who and what greenlit this?"
        without replaying anything.
        """
        evidence = await self._passing_evaluate(key=key, version=version)
        if evidence is None:
            raise StageTransitionError(
                f"cannot promote key={key!r} version={version!r}: "
                "no prior passing 'evaluated' transition on record",
            )
        threshold = await self._resolve_quorum_threshold()
        approver_count = await self._distinct_approver_count(
            key=key, version=version,
        )
        if approver_count < threshold:
            raise StageTransitionError(
                f"cannot promote key={key!r} version={version!r}: "
                f"quorum not met -- {approver_count} distinct approver(s) "
                f"on record, {threshold} required",
            )
        flip_reason = reason or "lifecycle promote"
        await self._store.set_alias(
            key, PRODUCTION_ALIAS, version,
            actor=actor,
            reason=flip_reason,
        )
        snapshot: dict[str, object] = {
            "eval_run_id": evidence.get("eval_run_id"),
            "verdict": evidence.get("verdict"),
            "approver_count": approver_count,
            "quorum_threshold": threshold,
        }
        _log.info(
            "lifecycle.promote key=%s version=%s actor=%s approvers=%d",
            key, version, actor, approver_count,
        )
        return await self._journal(
            key=key,
            version=version,
            from_stage=LifecycleStage.EVALUATED.value,
            to_stage=LifecycleStage.PRODUCTION.value,
            actor=actor,
            reason=reason,
            metrics_snapshot_json=json.dumps(snapshot),
        )

    async def rollback(
        self,
        *,
        key: str,
        version: str,
        actor: str = "",
        reason: str = "",
        target_version: str | None = None,
    ) -> LifecycleTransitionRecord:
        """Flip the production alias back to a prior production version.

        When ``target_version`` is None, resolves it as the most recent
        ``lifecycle_transitions`` row with ``to_stage='production'``
        whose ``version`` differs from ``version`` (the version being
        rolled back). Raises ``StageTransitionError`` when no such prior
        transition exists and no explicit target was supplied; the alias
        is not touched. Records a ``production`` to ``rolled_back``
        transition on the rolled-back version, with the restored target
        version in the metrics snapshot.
        """
        target = target_version or await self._prior_production_version(
            key=key, current_version=version,
        )
        if target is None:
            raise StageTransitionError(
                f"cannot rollback key={key!r} version={version!r}: "
                "no prior production transition on record and no "
                "target_version supplied",
            )
        flip_reason = reason or f"lifecycle rollback from {version}"
        await self._store.set_alias(
            key, PRODUCTION_ALIAS, target,
            actor=actor,
            reason=flip_reason,
        )
        snapshot: dict[str, object] = {"rolled_back_to": target}
        _log.info(
            "lifecycle.rollback key=%s version=%s target=%s actor=%s",
            key, version, target, actor,
        )
        return await self._journal(
            key=key,
            version=version,
            from_stage=LifecycleStage.PRODUCTION.value,
            to_stage=LifecycleStage.ROLLED_BACK.value,
            actor=actor,
            reason=reason,
            metrics_snapshot_json=json.dumps(snapshot),
        )

    async def list_transitions(
        self, key: str, *, limit: int = 100,
    ) -> list[LifecycleTransitionRecord]:
        """Return lifecycle transitions for ``key`` newest first, bounded by ``limit``."""
        if limit <= 0:
            raise ValueError("limit must be positive")
        async with async_session_scope() as session:
            rows = (await session.exec(
                select(LifecycleTransitionRecord)
                .where(LifecycleTransitionRecord.key == key)
                .order_by(LifecycleTransitionRecord.created_at.desc())
                .limit(limit)
            )).all()
        return list(rows)

    async def _journal(
        self,
        *,
        key: str,
        version: str,
        from_stage: str,
        to_stage: str,
        actor: str,
        reason: str,
        metrics_snapshot_json: str | None,
    ) -> LifecycleTransitionRecord:
        record = LifecycleTransitionRecord(
            key=key,
            version=version,
            from_stage=from_stage,
            to_stage=to_stage,
            actor=actor,
            reason=reason,
            metrics_snapshot_json=metrics_snapshot_json,
        )
        async with async_session_scope() as session:
            session.add(record)
            await session.commit()
            await session.refresh(record)
        return record

    async def _latest_stage(
        self, *, key: str, version: str,
    ) -> str | None:
        async with async_session_scope() as session:
            row = (await session.exec(
                select(LifecycleTransitionRecord)
                .where(
                    LifecycleTransitionRecord.key == key,
                    LifecycleTransitionRecord.version == version,
                )
                .order_by(LifecycleTransitionRecord.created_at.desc())
                .limit(1)
            )).first()
        if row is None:
            return None
        return row.to_stage

    async def _passing_evaluate(
        self, *, key: str, version: str,
    ) -> dict[str, object] | None:
        async with async_session_scope() as session:
            row = (await session.exec(
                select(LifecycleTransitionRecord)
                .where(
                    LifecycleTransitionRecord.key == key,
                    LifecycleTransitionRecord.version == version,
                    LifecycleTransitionRecord.to_stage
                    == LifecycleStage.EVALUATED.value,
                )
                .order_by(LifecycleTransitionRecord.created_at.desc())
                .limit(1)
            )).first()
        if row is None or row.metrics_snapshot_json is None:
            return None
        payload = json.loads(row.metrics_snapshot_json)
        if not isinstance(payload, dict):
            return None
        if payload.get("verdict") != "pass":
            return None
        return payload

    async def _prior_production_version(
        self, *, key: str, current_version: str,
    ) -> str | None:
        async with async_session_scope() as session:
            rows = (await session.exec(
                select(LifecycleTransitionRecord)
                .where(
                    LifecycleTransitionRecord.key == key,
                    LifecycleTransitionRecord.to_stage
                    == LifecycleStage.PRODUCTION.value,
                )
                .order_by(LifecycleTransitionRecord.created_at.desc())
                .limit(20)
            )).all()
        for row in rows:
            if row.version != current_version:
                return row.version
        return None

    async def _distinct_approver_count(
        self, *, key: str, version: str,
    ) -> int:
        """Count DISTINCT ``actor`` strings on ``approved`` transitions.

        Two rows with the same ``actor`` count as one approver -- the
        gate the RFC-10 acceptance criterion demands ("same actor twice
        does not satisfy"). Runs as a single ``count(distinct ...)`` on
        the journal so the check stays O(1) round trips regardless of
        how many re-approvals a version has accumulated.
        """
        async with async_session_scope() as session:
            row = (await session.exec(
                select(func.count(func.distinct(
                    LifecycleTransitionRecord.actor,
                )))
                .where(
                    LifecycleTransitionRecord.key == key,
                    LifecycleTransitionRecord.version == version,
                    LifecycleTransitionRecord.to_stage
                    == LifecycleStage.APPROVED.value,
                )
            )).one()
        # Async session.exec returns the scalar directly for a single-
        # column select; guard for a tuple wrapper the driver may emit.
        if isinstance(row, tuple):
            row = row[0]
        return int(row or 0)

    async def _resolve_quorum_threshold(self) -> int:
        """Read ``platform.agent_promotion_quorum`` via ConfigRegistry.

        Env -> cache -> DB row -> :class:`PlatformConfigSchema` default,
        with a schema-default fallback if the registry itself raises or
        returns a non-integer -- a bad DB row must not silently disable
        the quorum. Values below zero clamp to zero (eval-only gate)
        because a negative threshold has no coherent meaning.
        """
        default_threshold = PlatformConfigSchema().agent_promotion_quorum
        try:
            raw = await ConfigRegistry().get(
                "platform", "agent_promotion_quorum",
            )
        except (OSError, RuntimeError, ValueError, TypeError):
            return default_threshold
        if raw is None:
            return default_threshold
        try:
            threshold = int(raw)
        except (TypeError, ValueError):
            return default_threshold
        if threshold < 0:
            return 0
        return threshold

    async def shadow(
        self,
        *,
        key: str,
        version: str,
        actor: str = "",
        reason: str = "",
    ) -> LifecycleTransitionRecord:
        """Register ``version`` as the active shadow for ``key``.

        Guard: the (key, version) pair must already have a passing
        ``evaluated`` transition on record; a shadow that never cleared
        the eval gate would poison the off-path comparison it exists to
        run. Raises ``StageTransitionError`` otherwise. On success,
        supersedes any prior active shadow row for the key (there is
        exactly one active shadow per key at a time) and writes an
        ``evaluated``-or-``approved`` to ``shadow`` transition to the
        journal so a later inspection sees who registered the shadow
        and when.
        """
        evidence = await self._passing_evaluate(key=key, version=version)
        if evidence is None:
            raise StageTransitionError(
                f"cannot shadow key={key!r} version={version!r}: "
                "no prior passing 'evaluated' transition on record",
            )
        prior_stage = await self._latest_stage(
            key=key, version=version,
        ) or LifecycleStage.EVALUATED.value
        await self._supersede_active_assignments(
            key=key, kind=AssignmentKind.SHADOW.value,
        )
        await self._insert_assignment(
            key=key,
            kind=AssignmentKind.SHADOW.value,
            version=version,
            cohort_percent=None,
            actor=actor,
            reason=reason,
        )
        snapshot: dict[str, object] = {
            "assignment_kind": AssignmentKind.SHADOW.value,
            "eval_run_id": evidence.get("eval_run_id"),
            "verdict": evidence.get("verdict"),
        }
        _log.info(
            "lifecycle.shadow key=%s version=%s actor=%s",
            key, version, actor,
        )
        return await self._journal(
            key=key,
            version=version,
            from_stage=prior_stage,
            to_stage=LifecycleStage.SHADOW.value,
            actor=actor,
            reason=reason,
            metrics_snapshot_json=json.dumps(snapshot),
        )

    async def canary(
        self,
        *,
        key: str,
        version: str,
        cohort_percent: int,
        actor: str = "",
        reason: str = "",
    ) -> LifecycleTransitionRecord:
        """Register ``version`` as the active canary for ``key``.

        Guard: the (key, version) pair must already have a live active
        shadow row (a canary that never ran off-path first has no diff
        history to reason about), AND ``cohort_percent`` must sit in
        ``[1, 100]`` (0 means "route nothing" -- callers who want that
        should rollback instead; 101+ is nonsensical). Raises
        ``StageTransitionError`` on either miss.

        On success, supersedes any prior active canary row for the key
        and writes a ``shadow`` to ``canary`` transition to the journal
        with the cohort_percent packed into the metrics snapshot. The
        assignment row is what ``resolve_version_for_investigation``
        reads to route a hashed cohort of new investigations to the
        candidate; the production alias is not flipped.
        """
        if cohort_percent < 1 or cohort_percent > 100:
            raise StageTransitionError(
                f"cannot canary key={key!r} version={version!r}: "
                f"cohort_percent={cohort_percent} outside [1, 100]",
            )
        shadow_row = await self._active_assignment(
            key=key, kind=AssignmentKind.SHADOW.value,
        )
        if shadow_row is None or shadow_row.version != version:
            raise StageTransitionError(
                f"cannot canary key={key!r} version={version!r}: "
                "no active shadow on record for this (key, version)",
            )
        await self._supersede_active_assignments(
            key=key, kind=AssignmentKind.CANARY.value,
        )
        await self._insert_assignment(
            key=key,
            kind=AssignmentKind.CANARY.value,
            version=version,
            cohort_percent=cohort_percent,
            actor=actor,
            reason=reason,
        )
        snapshot: dict[str, object] = {
            "assignment_kind": AssignmentKind.CANARY.value,
            "cohort_percent": cohort_percent,
        }
        _log.info(
            "lifecycle.canary key=%s version=%s cohort_percent=%d actor=%s",
            key, version, cohort_percent, actor,
        )
        return await self._journal(
            key=key,
            version=version,
            from_stage=LifecycleStage.SHADOW.value,
            to_stage=LifecycleStage.CANARY.value,
            actor=actor,
            reason=reason,
            metrics_snapshot_json=json.dumps(snapshot),
        )

    async def promote_from_canary(
        self,
        *,
        key: str,
        version: str,
        actor: str = "",
        reason: str = "",
    ) -> LifecycleTransitionRecord:
        """Promote an active canary to production via the same eval+quorum gate.

        Thin wrapper: the RFC-10 acceptance criterion is that promotion
        from canary still enforces the eval + quorum gate exactly like a
        cold promote. Delegates to :meth:`promote` (which owns both
        checks) and, on success, supersedes the active canary row for
        the key so the router stops splitting cohorts. Raises whatever
        ``promote`` raises when the gate blocks.
        """
        record = await self.promote(
            key=key, version=version, actor=actor, reason=reason,
        )
        await self._supersede_active_assignments(
            key=key, kind=AssignmentKind.CANARY.value,
        )
        return record

    async def record_canary_signal(
        self,
        *,
        key: str,
        drift: float,
        cost: float,
        actor: str = "canary_monitor",
    ) -> CanarySignalOutcome:
        """Feed one drift + cost sample into the canary hold gate.

        Reads the active canary for ``key``; a no-op returns
        ``fired=False`` with ``reason='no_active_canary'`` when no
        active canary is on record. When either observed value exceeds
        the matching ceiling (``platform.agent_canary_drift_ceiling``,
        ``platform.agent_canary_cost_ceiling_usd``, with ``0.0``
        disabling that half), the assignment row is flipped to
        ``held`` in the same transaction that stamps the breach into
        ``last_signal_json``, a ``canary`` to ``held`` transition is
        journaled, and a WARN log records the breach payload so an
        operator alert path (RFC-07 monitor) sees the signal. Returns
        the outcome envelope so callers can surface the hold to their
        own UI without re-reading the DB.
        """
        canary_row = await self._active_assignment(
            key=key, kind=AssignmentKind.CANARY.value,
        )
        if canary_row is None:
            return CanarySignalOutcome(
                fired=False,
                reason="no_active_canary",
                signal=None,
                transition=None,
            )
        drift_ceiling, cost_ceiling = await self._resolve_signal_ceilings()
        drift_breach = drift_ceiling > 0.0 and drift > drift_ceiling
        cost_breach = cost_ceiling > 0.0 and cost > cost_ceiling
        signal = CanaryHoldSignal(
            key=key,
            version=canary_row.version,
            drift=float(drift),
            cost=float(cost),
            drift_ceiling=drift_ceiling,
            cost_ceiling=cost_ceiling,
            drift_breach=drift_breach,
            cost_breach=cost_breach,
        )
        if not (drift_breach or cost_breach):
            return CanarySignalOutcome(
                fired=False,
                reason="within_ceilings",
                signal=signal,
                transition=None,
            )
        await self._hold_assignment(
            assignment_id=canary_row.id, signal=signal,
        )
        snapshot: dict[str, object] = {
            "assignment_kind": AssignmentKind.CANARY.value,
            "cohort_percent": canary_row.cohort_percent,
            "drift": signal.drift,
            "cost": signal.cost,
            "drift_ceiling": signal.drift_ceiling,
            "cost_ceiling": signal.cost_ceiling,
            "drift_breach": signal.drift_breach,
            "cost_breach": signal.cost_breach,
        }
        _log.warning(
            "lifecycle.canary_hold key=%s version=%s drift=%.4f cost=%.4f "
            "drift_breach=%s cost_breach=%s",
            key, canary_row.version, signal.drift, signal.cost,
            signal.drift_breach, signal.cost_breach,
        )
        transition = await self._journal(
            key=key,
            version=canary_row.version,
            from_stage=LifecycleStage.CANARY.value,
            to_stage=LifecycleStage.HELD.value,
            actor=actor,
            reason="canary drift/cost breach",
            metrics_snapshot_json=json.dumps(snapshot),
        )
        return CanarySignalOutcome(
            fired=True,
            reason="held",
            signal=signal,
            transition=transition,
        )

    async def active_shadow(
        self, key: str,
    ) -> LifecycleCanaryAssignment | None:
        """Return the row the router considers the active shadow for ``key``.

        ``None`` when no shadow is on record for the key; the caller
        treats that as "no comparison to run". A held or superseded row
        never matches -- the assignment story is single-row-per-kind by
        construction.
        """
        return await self._active_assignment(
            key=key, kind=AssignmentKind.SHADOW.value,
        )

    async def active_canary(
        self, key: str,
    ) -> LifecycleCanaryAssignment | None:
        """Return the row the router considers the active canary for ``key``.

        ``None`` when no canary is on record OR the last canary is
        ``held`` -- either way, ``resolve_version_for_investigation``
        stops splitting cohorts and hands production to every turn.
        """
        return await self._active_assignment(
            key=key, kind=AssignmentKind.CANARY.value,
        )

    async def resolve_version_for_investigation(
        self, *, key: str, investigation_id: str,
    ) -> CohortRoute:
        """Route a new investigation deterministically to canary or production.

        The bucket is a stable hash of ``investigation_id`` mod 100; a
        bucket below ``cohort_percent`` resolves the canary version and
        the rest resolves the production alias. The same
        ``investigation_id`` therefore always lands in the same bucket
        -- routing a turn mid-run to a different version would poison
        the transcript. When no active canary is on record OR the
        active canary is ``held``, every investigation resolves
        production; the shadow is never routed to real traffic (its
        assignment exists for off-path comparison).

        Returns a ``CohortRoute`` carrying the resolved version, the
        selected bucket, and whether the route landed on the canary
        cohort. The prompt version store still owns the final body
        lookup; the caller passes the returned version into
        ``PromptVersionStore.resolve`` (or its own resolver) to fetch
        the actual prompt text.
        """
        canary = await self._active_assignment(
            key=key, kind=AssignmentKind.CANARY.value,
        )
        production_pointer = await self._store.resolve(
            key, alias=PRODUCTION_ALIAS,
        )
        production_version = (
            production_pointer.version
            if production_pointer is not None
            else None
        )
        bucket = _cohort_bucket(investigation_id)
        if canary is None or canary.cohort_percent is None:
            return CohortRoute(
                key=key,
                version=production_version,
                bucket=bucket,
                on_canary=False,
                canary_version=None,
                production_version=production_version,
                cohort_percent=None,
            )
        cohort = int(canary.cohort_percent)
        on_canary = bucket < cohort
        resolved = canary.version if on_canary else production_version
        return CohortRoute(
            key=key,
            version=resolved,
            bucket=bucket,
            on_canary=on_canary,
            canary_version=canary.version,
            production_version=production_version,
            cohort_percent=cohort,
        )

    async def _active_assignment(
        self, *, key: str, kind: str,
    ) -> LifecycleCanaryAssignment | None:
        async with async_session_scope() as session:
            row = (await session.exec(
                select(LifecycleCanaryAssignment)
                .where(
                    LifecycleCanaryAssignment.key == key,
                    LifecycleCanaryAssignment.kind == kind,
                    LifecycleCanaryAssignment.state
                    == AssignmentState.ACTIVE.value,
                )
                .order_by(LifecycleCanaryAssignment.created_at.desc())
                .limit(1)
            )).first()
        return row

    async def _supersede_active_assignments(
        self, *, key: str, kind: str,
    ) -> None:
        now = utc_now()
        async with async_session_scope() as session:
            rows = (await session.exec(
                select(LifecycleCanaryAssignment)
                .where(
                    LifecycleCanaryAssignment.key == key,
                    LifecycleCanaryAssignment.kind == kind,
                    LifecycleCanaryAssignment.state
                    == AssignmentState.ACTIVE.value,
                )
            )).all()
            for row in rows:
                row.state = AssignmentState.SUPERSEDED.value
                row.updated_at = now
                session.add(row)
            await session.commit()

    async def _insert_assignment(
        self,
        *,
        key: str,
        kind: str,
        version: str,
        cohort_percent: int | None,
        actor: str,
        reason: str,
    ) -> LifecycleCanaryAssignment:
        row = LifecycleCanaryAssignment(
            key=key,
            kind=kind,
            version=version,
            cohort_percent=cohort_percent,
            state=AssignmentState.ACTIVE.value,
            actor=actor,
            reason=reason,
        )
        async with async_session_scope() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
        return row

    async def _hold_assignment(
        self, *, assignment_id: str, signal: CanaryHoldSignal,
    ) -> None:
        now = utc_now()
        async with async_session_scope() as session:
            row = (await session.exec(
                select(LifecycleCanaryAssignment)
                .where(LifecycleCanaryAssignment.id == assignment_id)
            )).first()
            if row is None:
                return
            row.state = AssignmentState.HELD.value
            row.updated_at = now
            row.last_signal_json = json.dumps(signal.as_snapshot())
            session.add(row)
            await session.commit()

    async def _resolve_signal_ceilings(self) -> tuple[float, float]:
        """Read canary drift + cost ceilings via ConfigRegistry.

        Env -> cache -> DB row -> :class:`PlatformConfigSchema` default,
        with a schema-default fallback on a registry error or a value
        that does not coerce to float. Negative values clamp to 0.0
        (which disables that half of the gate) because a negative
        ceiling has no coherent meaning here.
        """
        defaults = PlatformConfigSchema()
        drift = await self._resolve_float_config(
            "agent_canary_drift_ceiling", defaults.agent_canary_drift_ceiling,
        )
        cost = await self._resolve_float_config(
            "agent_canary_cost_ceiling_usd",
            defaults.agent_canary_cost_ceiling_usd,
        )
        return drift, cost

    async def _resolve_float_config(
        self, key_name: str, default_value: float,
    ) -> float:
        try:
            raw = await ConfigRegistry().get("platform", key_name)
        except (OSError, RuntimeError, ValueError, TypeError):
            return default_value
        if raw is None:
            return default_value
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return default_value
        if value < 0.0:
            return 0.0
        return value


@dataclass(frozen=True, slots=True)
class CanaryHoldSignal:
    """One drift + cost sample fed into ``record_canary_signal``.

    Carries both the observed values and the ceilings they were checked
    against so an operator inspecting a stored signal sees whether a
    later config change would have kept the canary live. ``as_snapshot``
    renders the payload the assignment row stores under
    ``last_signal_json`` and the journal row stores under
    ``metrics_snapshot_json`` on the canary-to-held transition.
    """

    key: str
    version: str
    drift: float
    cost: float
    drift_ceiling: float
    cost_ceiling: float
    drift_breach: bool
    cost_breach: bool

    def as_snapshot(self) -> dict[str, object]:
        """Render the signal as a JSON-safe snapshot dict."""
        return {
            "key": self.key,
            "version": self.version,
            "drift": self.drift,
            "cost": self.cost,
            "drift_ceiling": self.drift_ceiling,
            "cost_ceiling": self.cost_ceiling,
            "drift_breach": self.drift_breach,
            "cost_breach": self.cost_breach,
            "observed_at": utc_now().isoformat(),
        }


@dataclass(frozen=True, slots=True)
class CanarySignalOutcome:
    """Return envelope for ``record_canary_signal``.

    ``fired`` is True when a hold transition was journaled; the
    ``reason`` string ('no_active_canary', 'within_ceilings', 'held')
    tells the caller which branch fired without re-checking the
    assignment row. ``signal`` is None only when there was no active
    canary to sample against; ``transition`` is None on every
    non-firing branch.
    """

    fired: bool
    reason: str
    signal: CanaryHoldSignal | None
    transition: LifecycleTransitionRecord | None


@dataclass(frozen=True, slots=True)
class CohortRoute:
    """Return envelope for ``resolve_version_for_investigation``.

    ``version`` is what the caller feeds into its prompt-body resolver
    (may be None when no production alias has been set for the key
    yet). ``on_canary`` is True when the bucket landed inside the
    canary cohort; ``bucket`` is the 0..99 slot the investigation id
    hashed into. ``canary_version`` / ``production_version`` /
    ``cohort_percent`` are surfaced so an operator UI can render the
    routing decision without re-reading the assignment table.
    """

    key: str
    version: str | None
    bucket: int
    on_canary: bool
    canary_version: str | None
    production_version: str | None
    cohort_percent: int | None


def _cohort_bucket(investigation_id: str) -> int:
    """Deterministic 0..99 bucket for an investigation id.

    Uses SHA-256 truncated to eight bytes so the same id always lands
    in the same bucket regardless of process or platform (a plain
    ``hash(str)`` is randomized per-process on Python 3.3+ and would
    reroute investigations across restarts). The mod-100 skew from a
    64-bit space is negligible (< 1e-17).
    """
    digest = hashlib.sha256(investigation_id.encode("utf-8")).digest()[:8]
    return int.from_bytes(digest, "big") % 100

