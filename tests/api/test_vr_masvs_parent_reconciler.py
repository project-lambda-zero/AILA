"""D-5 — ``sweep_masvs_audit_parents`` rolls parent batch status forward.

The MASVS dispatcher commits the parent ``VRInvestigationRecord``
(``kind=masvs_audit``) at ``status=CREATED`` and never writes to it
again. The reconciler in
``aila.modules.vr.masvs.parent_reconciler`` runs every minute via
the ARQ cron and drives the parent forward as children progress:

  ``CREATED → RUNNING``         once at least one child has moved
                                past ``CREATED``.
  ``CREATED/RUNNING → COMPLETED``
                                once every child has reached a
                                terminal status (``COMPLETED`` /
                                ``FAILED`` / ``ABANDONED``).

The tests below exercise every branch in the decision tree plus the
no-op cases (paused parent, no children, non-MASVS kind) so a future
refactor that loses one of those guards trips a red test.
"""
from __future__ import annotations

import json
from collections.abc import Iterable

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.masvs.parent_reconciler import sweep_masvs_audit_parents
from aila.platform.uow import UnitOfWork


async def _make_target(slug: str) -> str:
    """Insert one workspace + one android_apk target row, return target id."""
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"reconciler {slug}",
            slug=f"masvs-recon-{slug}",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name=f"recon target {slug}",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/example.apk"}),  # noqa: S108
            primary_language=None,
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json="{}",
            status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


async def _make_batch(
    *,
    target_id: str,
    parent_status: InvestigationStatus,
    parent_kind: InvestigationKind = InvestigationKind.MASVS_AUDIT,
    child_statuses: Iterable[InvestigationStatus],
) -> tuple[str, list[str]]:
    """Insert one parent + N children of the given statuses, return ids."""
    async with UnitOfWork() as uow:
        parent = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            kind=parent_kind.value,
            title=f"recon parent {parent_status.value}",
            initial_question="seed",
            status=parent_status.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.masvs_audit",
            cost_budget_usd=100.0,
            secondary_target_refs_json=json.dumps(
                [{"masvs_spec_version": "test"}],
            ),
        )
        uow.session.add(parent)
        await uow.session.flush()
        parent_id = parent.id

        child_ids: list[str] = []
        for index, child_status in enumerate(child_statuses):
            child = VRInvestigationRecord(
                target_id=target_id,
                team_id="admin",
                parent_investigation_id=parent_id,
                kind=InvestigationKind.AUDIT.value,
                title=f"child {index}",
                initial_question="seed",
                status=child_status.value,
                auto_pilot=True,
                strategy_family="vulnerability_research.audit",
                cost_budget_usd=50.0,
            )
            uow.session.add(child)
            await uow.session.flush()
            child_ids.append(child.id)

        await uow.session.commit()
        return parent_id, child_ids


async def _read_parent(parent_id: str) -> VRInvestigationRecord:
    async with UnitOfWork() as uow:
        parent = (
            await uow.session.exec(
                select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == parent_id,
                ),
            )
        ).one()
        return parent


@pytest.mark.asyncio
async def test_parent_with_all_created_children_stays_created(
    test_db: None,
) -> None:
    """No child has progressed → parent stays ``CREATED``, no transition."""
    del test_db
    target_id = await _make_target("all-created")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.CREATED,
        child_statuses=[InvestigationStatus.CREATED] * 3,
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 0, "completed": 0}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.CREATED.value
    assert parent.started_at is None
    assert parent.stopped_at is None


@pytest.mark.asyncio
async def test_parent_flips_to_running_when_first_child_starts(
    test_db: None,
) -> None:
    """One child RUNNING is enough to advance the parent past CREATED."""
    del test_db
    target_id = await _make_target("first-running")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.CREATED,
        child_statuses=[
            InvestigationStatus.RUNNING,
            InvestigationStatus.CREATED,
            InvestigationStatus.CREATED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 1, "completed": 0}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.RUNNING.value
    assert parent.started_at is not None, (
        "Reconciler must stamp started_at on the CREATED → RUNNING "
        "transition so the wall-clock cap reaper has an anchor."
    )
    assert parent.stopped_at is None


@pytest.mark.asyncio
async def test_paused_child_keeps_parent_running(test_db: None) -> None:
    """A child the operator paused mid-flight does not block RUNNING."""
    del test_db
    target_id = await _make_target("paused-child")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.CREATED,
        child_statuses=[
            InvestigationStatus.PAUSED,
            InvestigationStatus.CREATED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 1, "completed": 0}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.RUNNING.value


@pytest.mark.asyncio
async def test_parent_flips_to_completed_when_all_children_terminal(
    test_db: None,
) -> None:
    """All children terminal → parent COMPLETED + stopped_at stamped."""
    del test_db
    target_id = await _make_target("all-done")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.RUNNING,
        child_statuses=[
            InvestigationStatus.COMPLETED,
            InvestigationStatus.COMPLETED,
            InvestigationStatus.COMPLETED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 0, "completed": 1}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.COMPLETED.value
    assert parent.stopped_at is not None
    assert parent.started_at is not None, (
        "started_at must be filled even when the batch ran fast enough "
        "to skip past RUNNING between cron ticks (coalesce path)."
    )


@pytest.mark.asyncio
async def test_failed_and_abandoned_children_count_as_terminal(
    test_db: None,
) -> None:
    """Terminal set is COMPLETED ∪ FAILED ∪ ABANDONED — all flip parent."""
    del test_db
    target_id = await _make_target("mixed-terminal")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.RUNNING,
        child_statuses=[
            InvestigationStatus.COMPLETED,
            InvestigationStatus.FAILED,
            InvestigationStatus.ABANDONED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 0, "completed": 1}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.COMPLETED.value


@pytest.mark.asyncio
async def test_parent_with_mixed_terminal_and_running_stays_running(
    test_db: None,
) -> None:
    """One child still RUNNING blocks the COMPLETED transition."""
    del test_db
    target_id = await _make_target("mid-batch")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.RUNNING,
        child_statuses=[
            InvestigationStatus.COMPLETED,
            InvestigationStatus.RUNNING,
            InvestigationStatus.COMPLETED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 0, "completed": 0}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.RUNNING.value


@pytest.mark.asyncio
async def test_paused_parent_excluded_from_reconciliation(
    test_db: None,
) -> None:
    """Operator pause on the batch root is honoured; no overwrite."""
    del test_db
    target_id = await _make_target("paused-parent")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.PAUSED,
        child_statuses=[
            InvestigationStatus.COMPLETED,
            InvestigationStatus.COMPLETED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 0, "completed": 0}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.PAUSED.value


@pytest.mark.asyncio
async def test_terminal_parent_is_not_touched(test_db: None) -> None:
    """An already-COMPLETED parent must not flip again."""
    del test_db
    target_id = await _make_target("done-parent")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.COMPLETED,
        child_statuses=[
            InvestigationStatus.COMPLETED,
            InvestigationStatus.COMPLETED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 0, "completed": 0}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.COMPLETED.value


@pytest.mark.asyncio
async def test_only_masvs_audit_kind_considered(test_db: None) -> None:
    """``kind=audit`` parents (variant-hunt parent pattern) are ignored."""
    del test_db
    target_id = await _make_target("non-masvs")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.CREATED,
        parent_kind=InvestigationKind.AUDIT,
        child_statuses=[
            InvestigationStatus.RUNNING,
            InvestigationStatus.COMPLETED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 0, "completed": 0}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.CREATED.value


@pytest.mark.asyncio
async def test_zero_child_parent_left_alone(test_db: None) -> None:
    """Defensive: a MASVS parent with no children must NOT flip to COMPLETED."""
    del test_db
    target_id = await _make_target("no-children")
    parent_id, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.CREATED,
        child_statuses=[],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 0, "completed": 0}

    parent = await _read_parent(parent_id)
    assert parent.status == InvestigationStatus.CREATED.value
    assert parent.stopped_at is None


@pytest.mark.asyncio
async def test_multiple_active_batches_reconcile_in_one_sweep(
    test_db: None,
) -> None:
    """Two distinct batches transition independently in a single call."""
    del test_db
    target_id = await _make_target("multi-batch")

    parent_a, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.CREATED,
        child_statuses=[
            InvestigationStatus.RUNNING,
            InvestigationStatus.CREATED,
        ],
    )
    parent_b, _ = await _make_batch(
        target_id=target_id,
        parent_status=InvestigationStatus.RUNNING,
        child_statuses=[
            InvestigationStatus.COMPLETED,
            InvestigationStatus.COMPLETED,
        ],
    )

    counters = await sweep_masvs_audit_parents()
    assert counters == {"started": 1, "completed": 1}

    assert (await _read_parent(parent_a)).status == (
        InvestigationStatus.RUNNING.value
    )
    assert (await _read_parent(parent_b)).status == (
        InvestigationStatus.COMPLETED.value
    )
