"""RFC-10 agent lifecycle control plane: stage machine + journal.

``AgentLifecycleController`` composes the RFC-08 ``EvalRunner`` (scoring)
and the RFC-09 ``PromptVersionStore`` (immutable versions + alias flips)
and adds a stage-guarded append-only journal on top. Callers move a
version through ``built`` to ``evaluated`` to ``production``, or back
to a prior production version via ``rollback``. The controller decides
whether an alias flip is allowed; the actual flip stays owned by the
version store, which records its own audit row alongside ours.

The three primary entry points are ``evaluate``, ``promote`` and
``rollback``. Each writes exactly one ``LifecycleTransitionRecord``
row and returns it. ``evaluate`` delegates scoring to the runner with
``auto_promote=False`` so the runner never flips ``production`` behind
the controller's back; only ``promote`` may do that, and only when the
most recent evaluated transition for the (key, version) pair carries a
passing verdict.
"""
from __future__ import annotations

import json
import logging

from sqlmodel import select

from aila.platform.eval.runner import EvalRunner
from aila.platform.lifecycle.models import (
    LifecycleStage,
    LifecycleTransitionRecord,
)
from aila.platform.prompts.version_store import PromptVersionStore
from aila.storage.database import async_session_scope

__all__ = [
    "PRODUCTION_ALIAS",
    "AgentLifecycleController",
    "StageTransitionError",
]

_log = logging.getLogger(__name__)

PRODUCTION_ALIAS = "production"


class StageTransitionError(RuntimeError):
    """Raised when a caller asks for a stage move the guard forbids.

    Two cases fire this: ``promote`` without a prior passing
    ``evaluated`` transition on record for the (key, version) pair, and
    ``rollback`` with no prior production transition and no explicit
    ``target_version``. In both cases the alias is left untouched.
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

    async def promote(
        self,
        *,
        key: str,
        version: str,
        actor: str = "",
        reason: str = "",
    ) -> LifecycleTransitionRecord:
        """Flip the production alias to ``version`` when the guard allows.

        Guard: the most recent ``evaluated`` transition for (key, version)
        must carry ``verdict == 'pass'`` in its metrics snapshot. Raises
        ``StageTransitionError`` otherwise; the alias is not touched
        because the version store call comes after the guard check.
        On success, records an ``evaluated`` to ``production`` transition
        that references the passing eval run id.
        """
        evidence = await self._passing_evaluate(key=key, version=version)
        if evidence is None:
            raise StageTransitionError(
                f"cannot promote key={key!r} version={version!r}: "
                "no prior passing 'evaluated' transition on record",
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
        }
        _log.info(
            "lifecycle.promote key=%s version=%s actor=%s",
            key, version, actor,
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
