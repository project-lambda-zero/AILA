"""Platform investigation emit state factory (RFC-02 Phase 4c).

Exercises ``state_investigation_emit`` through VR record models with stub
task queue / config readers / finalize bindings. The finalization engine
is verbatim the malware production emit body modulo the ``bindings.``
indirection, so these tests target the paths RFC-02 consolidates + the
one behavioral change (config-driven caps): the auto-continue decision,
the investigation-level cap-exceeded halt, the reopen-window status guard,
and the post-completion proposer hooks.
"""
from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest
from sqlmodel import select

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.investigation_emit_base import (
    state_investigation_emit,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)

_DEFAULT_CAPS = {
    "overall_turn_cap": 500,
    "investigation_turn_cap": 300,
    "investigation_message_cap": 1000,
    "investigation_wall_clock_hours": 6.0,
    "wall_clock_idle_grace_s": 900.0,
}


class _FakeQueue:
    def __init__(self) -> None:
        self.submits: list[dict[str, Any]] = []

    async def submit(self, **kwargs: Any) -> str:
        self.submits.append(kwargs)
        return "task-id"


async def _noop_task(**_kwargs: Any) -> None:
    return None


def _bindings(
    fake_queue: _FakeQueue, caps: dict[str, Any],
) -> InvestigationStateBindings:
    async def _get_int(key: str) -> int:
        return int(caps[key])

    async def _get_float(key: str) -> float:
        return float(caps[key])

    async def _finalize(_inv_id: str) -> Any:
        return SimpleNamespace(trigger="no_trigger", action_taken=None)

    async def _evaluate_quorum(_outcome_id: str) -> Any:
        return SimpleNamespace(
            new_state="draft", approve_count=0, reject_count=0, quorum_k=1,
            siblings_active=0, transition_occurred=False, transition_reason=None,
        )

    async def _post_draft_review_request(**_kwargs: Any) -> None:
        return None

    class _StubDispatcher:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        async def dispatch(self, _outcome_id: str) -> Any:
            return SimpleNamespace(
                dispatch_status=SimpleNamespace(value="skipped"),
                dispatch_target=None, reason="stub",
            )

    class _StubExtractor:
        def __init__(self, **_kwargs: Any) -> None:
            pass

        async def extract(self, **_kwargs: Any) -> Any:
            return SimpleNamespace(extracted_count=0, skipped_reason="stub")

    return InvestigationStateBindings(
        inv_model=VRInvestigationRecord,
        branch_model=VRInvestigationBranchRecord,
        message_model=VRInvestigationMessageRecord,
        outcome_model=VRInvestigationOutcomeRecord,
        task_fn=_noop_task,
        synthesis_task_fn=_noop_task,
        verifier_task_fn=_noop_task,
        track="vr",
        task_queue_factory=lambda: fake_queue,
        get_int=_get_int,
        get_float=_get_float,
        outcome_dispatcher_cls=_StubDispatcher,
        pattern_extractor_cls=_StubExtractor,
        pattern_store_factory=lambda: SimpleNamespace(),
        approved_state="approved",
        evaluate_quorum=_evaluate_quorum,
        post_draft_review_request=_post_draft_review_request,
        finalize=_finalize,
        branch_table="vr_investigation_branches",
    )


async def _seed(
    status: InvestigationStatus, turn_count: int = 0,
    branch_status: str = "active",
) -> tuple[str, str]:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(name="eb", slug="eb", description="",
                               theme="custom", team_id="admin")
        uow.session.add(ws)
        await uow.session.flush()
        tgt = VRTargetRecord(
            workspace_id=ws.id, team_id="admin", display_name="t",
            kind="android_apk",
            descriptor_json=json.dumps({"apk_path": "/tmp/x.apk"}),  # noqa: S108
            primary_language=None, secondary_languages_json="[]",
            tags_json="[]", mcp_handles_json="{}", status="active",
            capability_profile_json="{}",
        )
        uow.session.add(tgt)
        await uow.session.flush()
        inv = VRInvestigationRecord(
            target_id=tgt.id, team_id="admin", kind="variant_hunt", title="t",
            initial_question="q", status=status.value, auto_pilot=False,
            strategy_family="vulnerability_research.variant_hunt",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.flush()
        br = VRInvestigationBranchRecord(
            investigation_id=inv.id, status=branch_status,
            turn_count=turn_count, fork_reason="primary",
            persona_voice="halvar",
        )
        uow.session.add(br)
        await uow.session.commit()
        return inv.id, br.id


@pytest.mark.usefixtures("test_db")
async def test_auto_continue_under_cap_reenqueues_same_branch() -> None:
    inv_id, br_id = await _seed(InvestigationStatus.RUNNING, turn_count=10)
    fake = _FakeQueue()
    handler = state_investigation_emit(
        _bindings(fake, _DEFAULT_CAPS), InvestigationStateHooks(),
    )

    result = await handler(
        {"investigation_id": inv_id, "branch_id": br_id,
         "exit_reason": "max_turns", "outcome_id": None},
        SimpleNamespace(),
    )

    assert result.output["status"] == InvestigationStatus.RUNNING.value
    assert result.output["exit_reason"] == "auto_continue"
    assert len(fake.submits) == 1
    sub = fake.submits[0]
    assert sub["track"] == "vr"
    assert sub["group_id"] == "vr_auto_continue"
    assert sub["bypass_dedup"] is True
    assert sub["kwargs"]["branch_id"] == br_id
    assert sub["fn"] is _noop_task


@pytest.mark.usefixtures("test_db")
async def test_branch_at_overall_cap_trips_investigation_turn_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def _fake_purge(_inv_id: str, track: str) -> dict[str, int]:
        del track
        return {"purged_jobs": 0}

    monkeypatch.setattr(
        "aila.platform.workflows.investigation_emit_base."
        "purge_arq_jobs_for_investigation",
        _fake_purge,
    )
    inv_id, br_id = await _seed(InvestigationStatus.RUNNING, turn_count=500)
    fake = _FakeQueue()
    handler = state_investigation_emit(
        _bindings(fake, _DEFAULT_CAPS), InvestigationStateHooks(),
    )

    result = await handler(
        {"investigation_id": inv_id, "branch_id": br_id,
         "exit_reason": "max_turns", "outcome_id": None},
        SimpleNamespace(),
    )

    # 500 >= overall_turn_cap 500 -> no auto-continue; 500 >= inv_turn_cap
    # 300 -> cap_exceeded halts the investigation.
    assert result.output["status"] == InvestigationStatus.COMPLETED.value
    assert result.output["exit_reason"].startswith(
        "cap_exceeded:investigation_turn_cap",
    )
    assert not fake.submits  # auto-continue never fired
    async with UnitOfWork() as uow:
        br = (await uow.session.exec(
            select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == br_id,
            ),
        )).first()
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == inv_id,
            ),
        )).first()
    assert br.status == "abandoned"
    assert inv.status == InvestigationStatus.COMPLETED.value


@pytest.mark.usefixtures("test_db")
async def test_status_flip_leaves_investigation_status_untouched() -> None:
    inv_id, br_id = await _seed(InvestigationStatus.PAUSED)
    fake = _FakeQueue()
    handler = state_investigation_emit(
        _bindings(fake, _DEFAULT_CAPS), InvestigationStateHooks(),
    )

    result = await handler(
        {"investigation_id": inv_id, "branch_id": br_id,
         "exit_reason": "inv_status_flipped:paused", "outcome_id": None},
        SimpleNamespace(),
    )

    # final_status None -> emit must NOT overwrite the operator-set state.
    assert result.output["status"] is None
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == inv_id,
            ),
        )).first()
    assert inv.status == InvestigationStatus.PAUSED.value


@pytest.mark.usefixtures("test_db")
async def test_proposer_hooks_fire_when_bound() -> None:
    inv_id, br_id = await _seed(InvestigationStatus.COMPLETED)
    fake = _FakeQueue()
    fired: list[str] = []

    async def _pattern(inv: str) -> None:
        fired.append(f"pattern:{inv}")

    async def _playbook(inv: str) -> None:
        fired.append(f"playbook:{inv}")

    handler = state_investigation_emit(
        _bindings(fake, _DEFAULT_CAPS),
        InvestigationStateHooks(
            propose_pattern=_pattern, propose_playbook=_playbook,
        ),
    )

    await handler(
        {"investigation_id": inv_id, "branch_id": br_id,
         "exit_reason": "status_locked:completed", "outcome_id": None},
        SimpleNamespace(),
    )

    assert fired == [f"pattern:{inv_id}", f"playbook:{inv_id}"]
