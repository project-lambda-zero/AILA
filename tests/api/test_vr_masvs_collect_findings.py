"""R-1 -- :func:`collect_findings` aggregates child outcomes per MASVS group.

The aggregator (R-1) is the read path that turns a completed (or in-flight)
MASVS audit batch into a :class:`MasvsAuditAggregate` for the PDF
renderer (R-2) and the ``GET /vr/targets/{id}/masvs-report`` payload
(R-3). It walks every child investigation under a MASVS audit parent,
projects each child's primary outcome through the S-4 mapping rule
(:func:`child_outcome_to_verdict`), groups verdicts by MASVS control
group, and tallies summary counts.

The tests below cover:

* parent lookup failures (unknown id, wrong kind) → ``ValueError``;
* the four mapping branches end-to-end (FINDING / NOT_APPLICABLE /
  NO_FINDING / INCONCLUSIVE for a child with no primary outcome);
* per-group bucketing across catalog groups;
* summary counts mirror the verdict list;
* spec version pinned on the parent is preserved on the aggregate;
* a child referencing a control id the catalog no longer carries is
  skipped without crashing the aggregate.

The mapping rule itself has its own coverage in
``tests/test_vr_masvs_verdict_mapper.py`` -- these tests only verify the
aggregator wires the inputs and outputs correctly.
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest

from aila.modules.vr.contracts.branch import BranchStatus
from aila.modules.vr.contracts.investigation import (
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.contracts.masvs import MasvsVerdict
from aila.modules.vr.contracts.outcome import OutcomeConfidence, OutcomeKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.masvs.catalog import CATALOG_VERSION, MASVS_CONTROLS
from aila.modules.vr.masvs.models import MasvsGroup, MasvsLevel
from aila.modules.vr.reporting.masvs_report import collect_findings
from aila.platform.uow import UnitOfWork


def _l1_controls_by_group() -> dict[MasvsGroup, str]:
    """Pick one L1 control id per MASVS group for cross-group bucketing tests."""
    out: dict[MasvsGroup, str] = {}
    for control in MASVS_CONTROLS:
        if control.level != MasvsLevel.L1:
            continue
        out.setdefault(control.group, control.id)
    return out


async def _make_target(slug: str) -> str:
    """Insert one workspace + one android_apk target row, return target id."""
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name=f"collect {slug}",
            slug=f"masvs-collect-{slug}",
            description="",
            theme="custom",
            team_id="admin",
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id="admin",
            display_name=f"collect target {slug}",
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


async def _make_parent(
    *,
    target_id: str,
    spec_version: str = CATALOG_VERSION,
    kind: InvestigationKind = InvestigationKind.MASVS_AUDIT,
) -> str:
    """Insert one MASVS audit parent and return its id."""
    async with UnitOfWork() as uow:
        parent = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            kind=kind.value,
            title=f"collect parent {kind.value}",
            initial_question="seed",
            status=InvestigationStatus.RUNNING.value,
            auto_pilot=False,
            strategy_family="vulnerability_research.masvs_audit",
            cost_budget_usd=100.0,
            secondary_target_refs_json=json.dumps(
                [{"masvs_spec_version": spec_version}],
            ),
        )
        uow.session.add(parent)
        await uow.session.commit()
        await uow.session.refresh(parent)
        return parent.id


async def _make_child_with_outcome(
    *,
    parent_id: str,
    target_id: str,
    control_id: str,
    outcome_kind: OutcomeKind | None,
    confidence: OutcomeConfidence = OutcomeConfidence.STRONG,
    payload: dict | None = None,
    spec_version: str = CATALOG_VERSION,
) -> str:
    """Insert one child investigation + primary branch + primary outcome.

    Pass ``outcome_kind=None`` to leave the child with no primary outcome
    (the in-flight / abandoned case the aggregator maps to
    inconclusive(no_primary_outcome)).
    """
    async with UnitOfWork() as uow:
        child = VRInvestigationRecord(
            target_id=target_id,
            team_id="admin",
            parent_investigation_id=parent_id,
            kind=InvestigationKind.AUDIT.value,
            title=f"child {control_id}",
            initial_question="seed",
            status=InvestigationStatus.COMPLETED.value,
            auto_pilot=True,
            strategy_family="vulnerability_research.audit",
            cost_budget_usd=50.0,
            secondary_target_refs_json=json.dumps([
                {
                    "masvs_control_id": control_id,
                    "masvs_spec_version": spec_version,
                },
            ]),
        )
        uow.session.add(child)
        await uow.session.flush()

        branch = VRInvestigationBranchRecord(
            investigation_id=child.id,
            status=BranchStatus.ACTIVE.value,
            fork_reason="primary",
        )
        uow.session.add(branch)
        await uow.session.flush()

        if outcome_kind is not None:
            outcome = VRInvestigationOutcomeRecord(
                investigation_id=child.id,
                branch_id=branch.id,
                outcome_kind=outcome_kind.value,
                payload_json=json.dumps(payload or {}),
                confidence=confidence.value,
                state="dispatched",
            )
            uow.session.add(outcome)
            await uow.session.flush()
            child.primary_outcome_id = outcome.id
            uow.session.add(child)

        await uow.session.commit()
        return child.id


# ---------------------------------------------------------------------------
# Parent-resolution failure modes
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_findings_unknown_parent_raises(test_db: None) -> None:
    """A nonexistent parent id surfaces as ``ValueError`` to the caller."""
    del test_db
    bogus_id = str(uuid4())
    with pytest.raises(ValueError, match=bogus_id):
        await collect_findings(bogus_id)


@pytest.mark.asyncio
async def test_collect_findings_wrong_kind_raises(test_db: None) -> None:
    """A non-MASVS investigation refuses with ``ValueError`` -- defensive guard."""
    del test_db
    target_id = await _make_target("wrong-kind")
    parent_id = await _make_parent(
        target_id=target_id,
        kind=InvestigationKind.AUDIT,
    )

    with pytest.raises(ValueError, match="masvs_audit"):
        await collect_findings(parent_id)


# ---------------------------------------------------------------------------
# Happy path: four verdict kinds in one aggregate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_findings_aggregates_four_verdict_kinds(
    test_db: None,
) -> None:
    """Every S-4 mapping branch reaches the aggregate verbatim.

    Four children fan out under one parent, one per verdict kind:

    * STORAGE control + ``DIRECT_FINDING`` + verifier_report confidence 0.82
      → ``FINDING``.
    * CRYPTO control + ``ASSESSMENT_REPORT`` + payload ``{not_applicable: True}``
      → ``NOT_APPLICABLE``.
    * AUTH control + ``DIRECT_FINDING`` + verifier_report ``refuted``
      → ``NO_FINDING``.
    * NETWORK control with no primary outcome (in-flight child)
      → ``INCONCLUSIVE`` with ``reason='no_primary_outcome'``.

    Asserts the per-group bucketing and summary counts mirror the
    verdict list.
    """
    del test_db
    target_id = await _make_target("four-kinds")
    parent_id = await _make_parent(target_id=target_id)

    picks = _l1_controls_by_group()
    storage_id = picks[MasvsGroup.STORAGE]
    crypto_id = picks[MasvsGroup.CRYPTO]
    auth_id = picks[MasvsGroup.AUTH]
    network_id = picks[MasvsGroup.NETWORK]

    await _make_child_with_outcome(
        parent_id=parent_id,
        target_id=target_id,
        control_id=storage_id,
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={
            "verifier_report": {"verdict": "confirmed", "confidence": 0.82},
        },
    )
    await _make_child_with_outcome(
        parent_id=parent_id,
        target_id=target_id,
        control_id=crypto_id,
        outcome_kind=OutcomeKind.ASSESSMENT_REPORT,
        confidence=OutcomeConfidence.STRONG,
        payload={"not_applicable": True},
    )
    await _make_child_with_outcome(
        parent_id=parent_id,
        target_id=target_id,
        control_id=auth_id,
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={
            "verifier_report": {"verdict": "refuted", "confidence": 0.7},
        },
    )
    await _make_child_with_outcome(
        parent_id=parent_id,
        target_id=target_id,
        control_id=network_id,
        outcome_kind=None,
    )

    aggregate = await collect_findings(parent_id)

    assert aggregate.parent_id == parent_id
    assert aggregate.target_id == target_id
    assert aggregate.masvs_spec_version == CATALOG_VERSION
    assert len(aggregate.verdicts) == 4

    by_control = {v.control_id: v for v in aggregate.verdicts}
    assert by_control[storage_id].verdict == MasvsVerdict.FINDING
    assert by_control[storage_id].confidence == pytest.approx(0.82)
    assert by_control[crypto_id].verdict == MasvsVerdict.NOT_APPLICABLE
    assert by_control[auth_id].verdict == MasvsVerdict.NO_FINDING
    assert by_control[network_id].verdict == MasvsVerdict.INCONCLUSIVE
    assert by_control[network_id].reason == "no_primary_outcome"
    assert by_control[network_id].primary_outcome_id is None

    assert aggregate.summary_counts == {
        MasvsVerdict.FINDING: 1,
        MasvsVerdict.NOT_APPLICABLE: 1,
        MasvsVerdict.NO_FINDING: 1,
        MasvsVerdict.INCONCLUSIVE: 1,
    }

    assert set(aggregate.by_group.keys()) == {
        MasvsGroup.STORAGE,
        MasvsGroup.CRYPTO,
        MasvsGroup.AUTH,
        MasvsGroup.NETWORK,
    }
    for group, bucket in aggregate.by_group.items():
        assert len(bucket) == 1
        assert bucket[0].control_id == picks[group]


# ---------------------------------------------------------------------------
# Catalog drift: child references a control the current catalog lost
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_findings_skips_child_with_unknown_control(
    test_db: None,
) -> None:
    """A child whose control id no longer exists is dropped, not crashed.

    The catalog version is pinned on the parent for traceability. A
    catalog edit that retires a control would leave historical audits
    referencing the dropped id; the aggregator logs a warning and
    skips the verdict rather than fabricating one or raising.
    """
    del test_db
    target_id = await _make_target("unknown-control")
    parent_id = await _make_parent(target_id=target_id)

    picks = _l1_controls_by_group()
    real_id = picks[MasvsGroup.STORAGE]
    fake_id = "MSTG-FAKE-9999"

    await _make_child_with_outcome(
        parent_id=parent_id,
        target_id=target_id,
        control_id=real_id,
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={
            "verifier_report": {"verdict": "confirmed", "confidence": 0.9},
        },
    )
    await _make_child_with_outcome(
        parent_id=parent_id,
        target_id=target_id,
        control_id=fake_id,
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={
            "verifier_report": {"verdict": "confirmed", "confidence": 0.9},
        },
    )

    aggregate = await collect_findings(parent_id)

    assert len(aggregate.verdicts) == 1
    assert aggregate.verdicts[0].control_id == real_id
    assert aggregate.summary_counts == {MasvsVerdict.FINDING: 1}


# ---------------------------------------------------------------------------
# Spec version pinned on parent is preserved on the aggregate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_collect_findings_preserves_parent_spec_version(
    test_db: None,
) -> None:
    """A historical catalog version on the parent survives a current-catalog read.

    The parent stores ``masvs_spec_version`` on
    ``secondary_target_refs_json`` at dispatch time so later catalog
    edits do not silently invalidate a shipped report. The aggregate
    must report that pinned value verbatim -- not the live catalog.
    """
    del test_db
    target_id = await _make_target("pinned-version")
    pinned_version = "legacy-spec-test"
    parent_id = await _make_parent(
        target_id=target_id, spec_version=pinned_version,
    )
    picks = _l1_controls_by_group()
    await _make_child_with_outcome(
        parent_id=parent_id,
        target_id=target_id,
        control_id=picks[MasvsGroup.STORAGE],
        outcome_kind=OutcomeKind.DIRECT_FINDING,
        confidence=OutcomeConfidence.STRONG,
        payload={
            "verifier_report": {"verdict": "confirmed", "confidence": 0.9},
        },
        spec_version=pinned_version,
    )

    aggregate = await collect_findings(parent_id)

    assert aggregate.masvs_spec_version == pinned_version
    assert pinned_version != CATALOG_VERSION, (
        "Test sentinel collided with the live catalog version; pick a "
        "different string."
    )
