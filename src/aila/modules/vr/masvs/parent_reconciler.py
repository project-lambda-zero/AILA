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

from sqlalchemy import func, select, update
from sqlalchemy.sql.functions import coalesce

from aila.modules.vr.contracts import InvestigationKind, InvestigationStatus
from aila.modules.vr.db_models import VRInvestigationRecord
from aila.platform.contracts._common import utc_now
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
            return {"started": 0, "completed": 0}

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

    if started or completed:
        _log.info(
            "masvs_parent_reconciler: started=%d completed=%d",
            started,
            completed,
        )

    return {"started": started, "completed": completed}
