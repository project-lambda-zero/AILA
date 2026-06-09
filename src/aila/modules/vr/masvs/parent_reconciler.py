"""Lifecycle reconciler for MASVS audit parent investigations.

A MASVS audit fans out into one parent ``VRInvestigationRecord``
(``kind=masvs_audit``) plus N child investigations
(``kind=audit``, each linked via ``parent_investigation_id``). The
dispatcher commits the parent at ``status=CREATED`` and submits each
child to the ``vr`` ARQ queue. Nothing else tracks the batch
lifecycle: without this reconciler the parent sits at ``CREATED``
forever even after every child finishes, leaving the operator UI
(R-4 "Download MASVS report" button, D-5 progress card) unable to
tell when the batch has actually completed.

This reconciler runs every minute via the existing ARQ cron, side
by side with ``investigation_reaper`` and ``branch_reaper`` in
``aila.platform.tasks.worker._run_reaper_block``. Per active batch
parent it counts children grouped by status and applies one of two
atomic transitions:

  ``CREATED  → RUNNING``    once at least one child has progressed
                            past ``CREATED`` (so the operator UI flips
                            to "running" the moment the first worker
                            picks up the queue).
  ``CREATED/RUNNING → COMPLETED``
                            once every child has reached a terminal
                            status (``COMPLETED`` / ``FAILED`` /
                            ``ABANDONED``).

``PAUSED`` children keep the parent in ``RUNNING`` so an operator's
pause-then-resume of one child does not flip the batch into a fake
terminal state. ``PAUSED`` parents themselves are excluded from the
candidate set so an operator-initiated pause of the batch root is
honoured.

Concurrency: both transitions are issued as ``UPDATE ... WHERE
status IN (<expected before>)``. A concurrent operator action that
flipped a parent into ``ABANDONED`` or ``FAILED`` between the
candidate read and the update simply causes the update to match zero
rows; the reconciler does not overwrite human-driven status changes.
``rowcount`` distinguishes a real transition from a lost race.

Defensive: parents with zero visible children are skipped. The
dispatcher commits parent + children atomically, so a zero-child
parent is either an in-flight rollback or a manual stub the
reconciler must not flip into ``COMPLETED`` with nothing underneath.
"""
from __future__ import annotations

import logging
import os

from sqlalchemy import func, select, update
from sqlalchemy.sql.functions import coalesce

from aila.modules.vr._task_queue import default_task_queue
from aila.modules.vr.contracts import InvestigationKind, InvestigationStatus
from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.db_models import VRInvestigationRecord, VRTargetRecord
from aila.modules.vr.workflow.task import run_vr_investigate
from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskRecord
from aila.platform.uow import UnitOfWork

__all__ = ["sweep_masvs_audit_parents"]

_log = logging.getLogger(__name__)

_TERMINAL_STATUSES: frozenset[str] = frozenset(
    (
        InvestigationStatus.COMPLETED.value,
        InvestigationStatus.FAILED.value,
        InvestigationStatus.ABANDONED.value,
    ),
)


def _batch_size() -> int:
    """Read MASVS_AUDIT_BATCH_SIZE env var with safe default.

    Keeps tunable read inline (cheap) instead of cached at import — an
    operator can flip the env between dispatches and the next reconciler
    tick picks up the new value.
    """
    try:
        n = int(os.environ.get("MASVS_AUDIT_BATCH_SIZE", "5"))
    except ValueError:
        n = 5
    return max(1, n)


async def _refill_apk_batches(uow: UnitOfWork) -> int:
    """Top up in-flight slots for every APK MASVS audit parent.

    For each parent whose target is ``android_apk``, ensure no more than
    ``_batch_size()`` children are in-flight (RUNNING / QUEUED) at any
    given moment. When slots are free and CREATED children remain that
    have never been enqueued (no TaskRecord row containing the child id),
    submit the next slice on the ``vr`` queue.

    Returns the total number of children newly enqueued in this tick.

    Why APK-only: source_repo / cve / patch_diff MASVS audits don't strain
    the local LLM proxy (no jadx tree, no 64K-token contexts). APK audits
    OOM'd OmniRoute when 30 streams hit simultaneously — this throttle
    keeps that pressure bounded.

    Why not a column for "enqueued?": adding one needs a migration. The
    TaskRecord JOIN below uses the existing JSONB cmd-line containment
    operator, which is fast enough for the per-parent ≤46-child set we
    sweep once per minute.
    """
    inv = VRInvestigationRecord
    tgt = VRTargetRecord
    tsk = TaskRecord
    batch_size = _batch_size()

    # APK MASVS parents currently in CREATED / RUNNING. Joined to the
    # target row so we can filter on target.kind without a second round
    # trip per parent.
    parent_rows = (
        await uow.session.exec(
            select(inv.id, tgt.id)
            .join(tgt, tgt.id == inv.target_id)
            .where(inv.kind == InvestigationKind.MASVS_AUDIT.value)
            .where(inv.parent_investigation_id.is_(None))
            .where(inv.status.in_((
                InvestigationStatus.CREATED.value,
                InvestigationStatus.RUNNING.value,
            )))
            .where(tgt.kind == TargetKind.ANDROID_APK.value),
        )
    ).all()
    if not parent_rows:
        return 0

    enqueued_total = 0
    queue = default_task_queue()

    for parent_id, _target_id in parent_rows:
        # Count children currently consuming a slot. CREATED counts only
        # when a TaskRecord exists (the child has been enqueued, just not
        # picked up yet); CREATED children with no TaskRecord are the
        # virgin pool we'll draw from.
        in_flight = (
            await uow.session.exec(
                select(func.count(inv.id))
                .where(inv.parent_investigation_id == parent_id)
                .where(inv.status.in_((
                    InvestigationStatus.RUNNING.value,
                    InvestigationStatus.QUEUED.value,
                    InvestigationStatus.PAUSED.value,
                ))),
            )
        ).first() or 0

        # Add CREATED children that ALREADY have a TaskRecord — they're
        # enqueued, just sitting in the queue waiting for a worker. They
        # count toward in_flight so we don't double-enqueue.
        created_with_task = (
            await uow.session.exec(
                select(func.count(inv.id))
                .where(inv.parent_investigation_id == parent_id)
                .where(inv.status == InvestigationStatus.CREATED.value)
                .where(
                    select(tsk.id)
                    .where(tsk.kwargs_json.ilike(
                        func.concat("%", inv.id, "%"),
                    ))
                    .exists(),
                ),
            )
        ).first() or 0
        in_flight += int(created_with_task)

        slots = batch_size - int(in_flight)
        if slots <= 0:
            continue

        # Virgin CREATED children: no TaskRecord for this investigation_id.
        # Order by created_at to enqueue oldest-first (preserves the
        # operator-visible MASVS control id order from the dispatcher).
        virgin = (
            await uow.session.exec(
                select(inv.id)
                .where(inv.parent_investigation_id == parent_id)
                .where(inv.status == InvestigationStatus.CREATED.value)
                .where(
                    ~select(tsk.id)
                    .where(tsk.kwargs_json.ilike(
                        func.concat("%", inv.id, "%"),
                    ))
                    .exists(),
                )
                .order_by(inv.created_at)
                .limit(slots),
            )
        ).all()

        for child_id in virgin:
            try:
                await queue.submit(
                    track="vr",
                    fn=run_vr_investigate,
                    kwargs={"investigation_id": child_id},
                    user_id="system",
                    group_id="system",
                    team_id=None,
                )
                enqueued_total += 1
            except Exception as exc:  # noqa: BLE001 — submission is best-effort
                _log.warning(
                    "masvs batch refill: parent=%s child=%s enqueue failed: %s",
                    parent_id, child_id, exc,
                )
                break  # bail this parent; next tick will retry

    if enqueued_total:
        _log.info(
            "masvs_batch_refill: %d children enqueued across %d parent(s) "
            "(batch_size=%d)",
            enqueued_total, len(parent_rows), batch_size,
        )
    return enqueued_total


async def sweep_masvs_audit_parents() -> dict[str, int]:
    """Reconcile parent status for every active MASVS audit batch.

    Returns a ``{"started": int, "completed": int}`` counter pair
    naming the number of ``CREATED → RUNNING`` and
    ``{CREATED, RUNNING} → COMPLETED`` transitions actually applied
    in this sweep. Both counters are post-rowcount so a lost race
    against a concurrent operator action does not inflate them.
    """
    inv = VRInvestigationRecord

    started = 0
    completed = 0

    async with UnitOfWork() as uow:
        # Top up batch slots before the status-transition pass so a
        # parent that just had a child reach terminal can immediately
        # promote the next CREATED-virgin child in the same tick. The
        # refill is APK-only (see docstring); other target kinds keep
        # the fan-out-all behavior.
        refilled = await _refill_apk_batches(uow)
        # Candidate parents: kind=masvs_audit, parent_investigation_id
        # IS NULL (true batch root), status in {CREATED, RUNNING}. PAUSED
        # parents are intentionally excluded so an operator who paused
        # the batch root keeps control until they resume.
        parent_rows = (
            await uow.session.exec(
                select(inv.id, inv.status)
                .where(inv.kind == InvestigationKind.MASVS_AUDIT.value)
                .where(inv.parent_investigation_id.is_(None))
                .where(
                    inv.status.in_(
                        (
                            InvestigationStatus.CREATED.value,
                            InvestigationStatus.RUNNING.value,
                        ),
                    ),
                ),
            )
        ).all()
        if not parent_rows:
            return {"started": 0, "completed": 0, "refilled": refilled}

        parent_ids = [row[0] for row in parent_rows]
        # One aggregate query covers every candidate batch: child status
        # counts grouped per parent. Avoids N+1 SELECTs for a batch with
        # ~46 children.
        child_rows = (
            await uow.session.exec(
                select(
                    inv.parent_investigation_id,
                    inv.status,
                    func.count(inv.id),
                )
                .where(inv.parent_investigation_id.in_(parent_ids))
                .group_by(inv.parent_investigation_id, inv.status),
            )
        ).all()

        per_parent: dict[str, dict[str, int]] = {}
        for parent_id, child_status, count in child_rows:
            per_parent.setdefault(parent_id, {})[child_status] = int(count)

        now = utc_now()
        any_changes = False

        for parent_id, parent_status in parent_rows:
            buckets = per_parent.get(parent_id)
            if not buckets:
                # Defensive: zero visible children = in-flight rollback
                # or manual stub. Leave alone.
                continue

            total_children = sum(buckets.values())
            terminal_children = sum(
                count
                for status_value, count in buckets.items()
                if status_value in _TERMINAL_STATUSES
            )
            created_children = buckets.get(
                InvestigationStatus.CREATED.value, 0,
            )

            if terminal_children == total_children:
                # Every child terminal → flip parent to COMPLETED.
                # coalesce keeps started_at when already set (the parent
                # transitioned through RUNNING earlier); fills it when
                # the entire batch ran fast enough to skip past RUNNING
                # between cron ticks (rare but real).
                result = await uow.session.exec(
                    update(inv)
                    .where(inv.id == parent_id)
                    .where(
                        inv.status.in_(
                            (
                                InvestigationStatus.CREATED.value,
                                InvestigationStatus.RUNNING.value,
                            ),
                        ),
                    )
                    .values(
                        status=InvestigationStatus.COMPLETED.value,
                        started_at=coalesce(inv.started_at, now),
                        stopped_at=now,
                        updated_at=now,
                    )
                    .execution_options(synchronize_session=False),
                )
                if (getattr(result, "rowcount", 0) or 0) > 0:
                    completed += 1
                    any_changes = True
            elif (
                parent_status == InvestigationStatus.CREATED.value
                and created_children < total_children
            ):
                # At least one child has moved past CREATED but not all
                # are terminal → parent is mid-batch. Flip to RUNNING and
                # stamp started_at on first transition so the wall-clock
                # reaper has an anchor.
                result = await uow.session.exec(
                    update(inv)
                    .where(inv.id == parent_id)
                    .where(inv.status == InvestigationStatus.CREATED.value)
                    .values(
                        status=InvestigationStatus.RUNNING.value,
                        started_at=coalesce(inv.started_at, now),
                        updated_at=now,
                    )
                    .execution_options(synchronize_session=False),
                )
                if (getattr(result, "rowcount", 0) or 0) > 0:
                    started += 1
                    any_changes = True

        if any_changes:
            await uow.commit()

    if started or completed or refilled:
        _log.info(
            "masvs_parent_reconciler: started=%d completed=%d refilled=%d",
            started,
            completed,
            refilled,
        )

    return {"started": started, "completed": completed, "refilled": refilled}
