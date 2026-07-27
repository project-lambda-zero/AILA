"""Forensics panel + sibling-review-quorum wiring (#18).

Proves the two primitives the ticket adds to the forensics module are
wired correctly against the forensics record models:

* ``test_forensics_setup_spawns_role_panel`` -- setup calls
  :func:`spawn_persona_siblings` bound to the forensics branch model and
  produces one branch per non-primary role
  (:class:`~aila.platform.contracts.enums.PersonaVoice`: MADDIE / RENZO)
  on top of the primary HALVAR branch, and enqueues one worker task per
  sibling. This is the "panel spawns the roles" acceptance clause.

* ``test_forensics_quorum_approves_finding`` -- with two active
  siblings both voting ``approve`` on a draft outcome the forensics
  :func:`evaluate_quorum` binding flips the outcome to
  :data:`OUTCOME_STATE_APPROVED`. This is the "quorum gates a finding"
  acceptance clause.

* ``test_forensics_quorum_vetoes_finding_on_reject`` -- with the
  forensics ``veto_k=1`` a single ``reject`` vote flips the outcome to
  :data:`OUTCOME_STATE_REJECTED`. The kill-fast bar mirrors VR.

Provider-independent -- no live LLM, no live worker; all mechanisms
tested through the platform primitives + forensics record models
directly. The parent still smokes the live hub end-to-end.
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import select

from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationOutcomeRecord,
    ForensicsInvestigationOutcomeReviewRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    VOTE_APPROVE,
    VOTE_REJECT,
    evaluate_quorum,
)
from aila.modules.forensics.workflow.panel.setup import (
    _PANEL_SIBLINGS,
    _PRIMARY_PERSONA,
)
from aila.platform.agents.branch_pool import (
    _strip_directives_from_state,
    _strip_rejected_from_state,
)
from aila.platform.contracts.enums import PersonaVoice
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.persona_spawn import spawn_persona_siblings


class _FakeQueue:
    """In-memory ARQ queue substitute -- records enqueue kwargs."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def submit(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


async def _dummy_task(**_kwargs: object) -> None:
    """Never invoked -- the fake queue records the enqueue and returns."""
    return None


async def _seed_forensics_investigation() -> tuple[str, str]:
    """Insert a project + investigation + primary panel branch. Return ids."""
    async with UnitOfWork() as uow:
        project = ForensicsProjectRecord(
            team_id="admin",
            name="panel-test",
            description="",
            system_id=1,
            analyzer_os="linux",
            evidence_directory="/tmp/panel-test",  # noqa: S108
            status="ready",
        )
        uow.session.add(project)
        await uow.session.flush()
        inv = InvestigationRunRecord(
            project_id=project.id,
            question="What is the earliest lateral-movement indicator?",
            status=InvestigationStatus.PENDING.value,
        )
        uow.session.add(inv)
        await uow.session.flush()
        primary = ForensicsInvestigationBranchRecord(
            investigation_id=inv.id,
            parent_branch_id=None,
            status="active",
            persona_voice=_PRIMARY_PERSONA.value,
            fork_reason="primary",
            fork_at_turn=0,
            case_state_json="{}",
            turn_count=0,
            branch_cost_usd=0.0,
        )
        uow.session.add(primary)
        await uow.session.flush()
        inv_id = inv.id
        primary_id = primary.id
        await uow.session.commit()
    return inv_id, primary_id


@pytest.mark.usefixtures("test_db")
async def test_forensics_setup_spawns_role_panel() -> None:
    """The panel setup INSERTs one branch per non-primary role and enqueues each."""
    inv_id, primary_id = await _seed_forensics_investigation()
    queue = _FakeQueue()

    result = await spawn_persona_siblings(
        inv_id,
        primary_id,
        None,  # forensics_investigations is not team-scoped on its base row
        siblings=_PANEL_SIBLINGS,
        branch_model=ForensicsInvestigationBranchRecord,
        inv_table="forensics_investigations",
        message_table="forensics_investigation_messages",
        task_fn=_dummy_task,
        track="forensics",
        group_id="forensics_panel_deliberation",
        task_queue=queue,
        strip_case_state=lambda raw: _strip_rejected_from_state(
            _strip_directives_from_state(raw),
        ),
    )

    # The 3-role spine (halvar primary + maddie critic + renzo implementer)
    # must materialize. VR uses maddie/renzo as its baseline critics /
    # implementers, so identical PersonaVoice values here catch a
    # regression in the platform spawn's persona filtering.
    assert PersonaVoice.MADDIE in _PANEL_SIBLINGS
    assert PersonaVoice.RENZO in _PANEL_SIBLINGS
    assert len(result.inserted) == len(_PANEL_SIBLINGS)
    assert len(result.enqueued) == len(_PANEL_SIBLINGS)

    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            select(ForensicsInvestigationBranchRecord).where(
                ForensicsInvestigationBranchRecord.investigation_id == inv_id,
            )
        )).all()
    personas = {r.persona_voice for r in rows}
    assert personas == {
        _PRIMARY_PERSONA.value,
        *(p.value for p in _PANEL_SIBLINGS),
    }
    # Every sibling branch is a child of the primary and starts fresh.
    for r in rows:
        if r.id == primary_id:
            continue
        assert r.parent_branch_id == primary_id
        assert r.status == "active"
        assert r.turn_count == 0
        assert r.fork_reason == f"auto_deliberation:{r.persona_voice}"

    # And every enqueue carried a distinct sibling branch id so the
    # per-sibling ARQ task actually references the right row.
    enqueued_branch_ids = {
        c["kwargs"]["branch_id"] for c in queue.calls
    }
    assert enqueued_branch_ids == {
        r.id for r in rows if r.id != primary_id
    }


async def _seed_with_siblings(
    *,
    outcome_kind: str = "panel_finding",
    sibling_count: int = 2,
    sibling_status: str = "active",
) -> tuple[str, str, list[str]]:
    """Seed a draft outcome + N sibling branches; return (inv, outcome, siblings)."""
    inv_id, primary_id = await _seed_forensics_investigation()
    async with UnitOfWork() as uow:
        outcome = ForensicsInvestigationOutcomeRecord(
            investigation_id=inv_id,
            branch_id=primary_id,
            outcome_kind=outcome_kind,
            payload_json=json.dumps({"finding": "smoke"}),
            confidence="caveated",
            evidence_refs_json="[]",
            state=OUTCOME_STATE_DRAFT,
            dispatch_status="pending",
        )
        uow.session.add(outcome)
        siblings: list[str] = []
        for i in range(sibling_count):
            sib = ForensicsInvestigationBranchRecord(
                investigation_id=inv_id,
                parent_branch_id=primary_id,
                status=sibling_status,
                persona_voice=(
                    PersonaVoice.MADDIE.value if i == 0 else PersonaVoice.RENZO.value
                ),
                fork_reason=(
                    f"auto_deliberation:"
                    f"{PersonaVoice.MADDIE.value if i == 0 else PersonaVoice.RENZO.value}"
                ),
                fork_at_turn=0,
                case_state_json="{}",
                turn_count=0,
                branch_cost_usd=0.0,
            )
            uow.session.add(sib)
            await uow.session.flush()
            siblings.append(sib.id)
        await uow.session.flush()
        outcome_id = outcome.id
        await uow.session.commit()
    return inv_id, outcome_id, siblings


async def _vote(*, outcome_id: str, reviewer_branch_id: str, persona: str, vote: str) -> None:
    async with UnitOfWork() as uow:
        uow.session.add(
            ForensicsInvestigationOutcomeReviewRecord(
                outcome_id=outcome_id,
                reviewer_branch_id=reviewer_branch_id,
                reviewer_persona=persona,
                vote=vote,
            ),
        )
        await uow.session.commit()


@pytest.mark.usefixtures("test_db")
async def test_forensics_quorum_approves_finding() -> None:
    """Two active siblings approving lifts a draft to APPROVED."""
    _inv, outcome_id, siblings = await _seed_with_siblings(sibling_count=2)
    for sid, persona in zip(
        siblings, [PersonaVoice.MADDIE.value, PersonaVoice.RENZO.value], strict=True,
    ):
        await _vote(
            outcome_id=outcome_id,
            reviewer_branch_id=sid,
            persona=persona,
            vote=VOTE_APPROVE,
        )
    res = await evaluate_quorum(outcome_id)
    assert res.new_state == OUTCOME_STATE_APPROVED
    assert res.approve_count == 2
    assert res.reject_count == 0

    # And the row itself was flipped, not just the tally reported.
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(ForensicsInvestigationOutcomeRecord).where(
                ForensicsInvestigationOutcomeRecord.id == outcome_id,
            )
        )).first()
    assert row is not None
    assert row.state == OUTCOME_STATE_APPROVED


@pytest.mark.usefixtures("test_db")
async def test_forensics_quorum_vetoes_finding_on_reject() -> None:
    """The forensics ``veto_k=1`` binding rejects on a single sibling reject."""
    _inv, outcome_id, siblings = await _seed_with_siblings(sibling_count=2)
    await _vote(
        outcome_id=outcome_id,
        reviewer_branch_id=siblings[0],
        persona=PersonaVoice.MADDIE.value,
        vote=VOTE_REJECT,
    )
    res = await evaluate_quorum(outcome_id)
    assert res.new_state == OUTCOME_STATE_REJECTED
    assert res.reject_count == 1

    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(ForensicsInvestigationOutcomeRecord).where(
                ForensicsInvestigationOutcomeRecord.id == outcome_id,
            )
        )).first()
    assert row is not None
    assert row.state == OUTCOME_STATE_REJECTED
