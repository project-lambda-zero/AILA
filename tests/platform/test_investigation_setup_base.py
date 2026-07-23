"""Platform investigation setup state factory (RFC-02 Phase 4a).

Exercises ``state_investigation_setup`` through VR record models with stub
spawn / pattern-store bindings so the platform logic (STATUS_LOCKED exit,
sibling-terminal exit, fresh-primary fork, orphan abandon, RUNNING flip,
cve-intel hook) is verified in isolation. The cve-intel behavior is driven
by whether the hook is set -- an unset hook is malware's configuration and
must yield an empty ``cve_intel`` list.
"""
from __future__ import annotations

import json
from typing import Any

import pytest
from sqlmodel import select

from aila.modules.vr.contracts.branch import PersonaVoice
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
    state_investigation_setup,
)


class _Store:
    async def applicable(self, **_kwargs: Any) -> list[Any]:
        return []


def _make_handler(spawn_calls: list[dict], *, cve: bool):
    async def _spawn(**kwargs: object) -> None:
        spawn_calls.append(kwargs)

    async def _resolve_cve(question: str) -> list[dict[str, Any]]:
        return [{"cve_id": "CVE-2026-0001", "status": "found", "q": question}]

    bindings = InvestigationStateBindings(
        inv_model=VRInvestigationRecord,
        branch_model=VRInvestigationBranchRecord,
        target_model=VRTargetRecord,
        primary_persona_value=PersonaVoice.HALVAR.value,
        unspecified_persona_value=PersonaVoice.UNSPECIFIED.value,
        spawn_fn=_spawn,
        pattern_store_factory=_Store,
        auto_deliberation_enabled=lambda: True,
    )
    hooks = InvestigationStateHooks(resolve_cve_intel=_resolve_cve if cve else None)
    return state_investigation_setup(bindings, hooks)


async def _seed_inv(
    status: InvestigationStatus = InvestigationStatus.CREATED,
) -> str:
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="sb", slug="sb", description="", theme="custom", team_id="admin",
        )
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
            target_id=tgt.id, team_id="admin", kind="variant_hunt",
            title="t", initial_question="q about CVE-2026-0001", status=status.value,
            auto_pilot=False, strategy_family="vulnerability_research.variant_hunt",
            cost_budget_usd=50.0,
        )
        uow.session.add(inv)
        await uow.session.commit()
        return inv.id


async def _seed_branch(inv_id: str, *, status: str, persona: str | None,
                       parent: str | None = None) -> str:
    async with UnitOfWork() as uow:
        br = VRInvestigationBranchRecord(
            investigation_id=inv_id, status=status, turn_count=0,
            fork_reason="seed", persona_voice=persona, parent_branch_id=parent,
        )
        uow.session.add(br)
        await uow.session.commit()
        return br.id


@pytest.mark.usefixtures("test_db")
async def test_fresh_primary_fork_flips_running_and_spawns() -> None:
    """No live primary -> fork a fresh HALVAR primary, flip RUNNING, spawn,
    resolve cve intel, and advance to the loop."""
    inv_id = await _seed_inv(InvestigationStatus.CREATED)
    spawn_calls: list[dict] = []
    handler = _make_handler(spawn_calls, cve=True)

    result = await handler({"investigation_id": inv_id}, None)

    assert result.next_state == "investigation_loop"
    assert result.output["cve_intel"] == [
        {"cve_id": "CVE-2026-0001", "status": "found", "q": "q about CVE-2026-0001"},
    ]
    assert len(spawn_calls) == 1
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id == inv_id),
        )).first()
        primary = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == inv_id)
            .where(VRInvestigationBranchRecord.parent_branch_id.is_(None)),
        )).first()
    assert inv.status == InvestigationStatus.RUNNING.value
    assert inv.started_at is not None
    assert primary is not None
    assert primary.persona_voice == PersonaVoice.HALVAR.value


@pytest.mark.usefixtures("test_db")
async def test_no_cve_hook_yields_empty_cve_intel() -> None:
    """Malware configuration: no resolve_cve_intel hook -> cve_intel == []."""
    inv_id = await _seed_inv(InvestigationStatus.CREATED)
    handler = _make_handler([], cve=False)

    result = await handler({"investigation_id": inv_id}, None)

    assert result.next_state == "investigation_loop"
    assert result.output["cve_intel"] == []


@pytest.mark.usefixtures("test_db")
async def test_status_locked_emits_clean_exit() -> None:
    """A paused investigation skips setup and emits a status_locked exit."""
    inv_id = await _seed_inv(InvestigationStatus.PAUSED)
    spawn_calls: list[dict] = []
    handler = _make_handler(spawn_calls, cve=True)

    result = await handler({"investigation_id": inv_id}, None)

    assert result.next_state == "investigation_emit"
    assert result.output["exit_reason"] == "status_locked:paused"
    assert spawn_calls == []  # locked exit never spawns
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(VRInvestigationRecord.id == inv_id),
        )).first()
    assert inv.status == InvestigationStatus.PAUSED.value  # not flipped


@pytest.mark.usefixtures("test_db")
async def test_sibling_terminal_branch_exits() -> None:
    """An explicit terminal branch exits to emit, never the loop."""
    inv_id = await _seed_inv(InvestigationStatus.RUNNING)
    dead = await _seed_branch(inv_id, status="abandoned", persona="noor")
    handler = _make_handler([], cve=True)

    result = await handler(
        {"investigation_id": inv_id, "branch_id": dead}, None,
    )

    assert result.next_state == "investigation_emit"
    assert result.output["exit_reason"] == "branch_already_terminal"
    assert result.output["branch_id"] == dead


@pytest.mark.usefixtures("test_db")
async def test_orphan_active_branches_abandoned_on_fresh_fork() -> None:
    """Forking a fresh primary abandons stray active/paused siblings."""
    inv_id = await _seed_inv(InvestigationStatus.CREATED)
    # The only primary is terminal, so setup forks a fresh one; an active
    # sibling parented to the dead primary is the orphan to abandon.
    dead_primary = await _seed_branch(
        inv_id, status="abandoned", persona="halvar", parent=None,
    )
    orphan = await _seed_branch(
        inv_id, status="active", persona="noor", parent=dead_primary,
    )
    spawn_calls: list[dict] = []
    handler = _make_handler(spawn_calls, cve=True)

    result = await handler({"investigation_id": inv_id}, None)

    assert result.next_state == "investigation_loop"
    async with UnitOfWork() as uow:
        orphan_row = (await uow.session.exec(
            select(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.id == orphan),
        )).first()
    assert orphan_row.status == "abandoned"
    assert orphan_row.closed_reason.startswith("superseded_by_reenqueue_self_heal:")
