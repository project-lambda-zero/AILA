"""Write-up workflow for a settled forensics panel investigation.

The panel emit state enqueues :func:`run_forensics_panel_writeup` instead of
running report generation inside its short phase-graph timeout. This workflow
reuses the free-flow promotion, write-up, and response-emit states unchanged;
its only new state reconstructs their input from the panel's durable step,
outcome, and branch records. A completed write-up makes a retried or duplicate
enqueue a no-op.
"""
from __future__ import annotations

import json
from typing import Any, cast

from sqlmodel import select

from aila.modules.forensics.db_models import (
    AgentStepRecord,
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationOutcomeRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
    WriteUpRecord,
)
from aila.modules.forensics.services.integration import build_integration_payload
from aila.modules.forensics.workflow.definitions import (
    _build_services,
    _state_response_emit,
)
from aila.modules.forensics.workflow.states.promotion import state_freeflow_promotion
from aila.modules.forensics.workflow.states.writeup import state_writeup
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import (
    RESERVED_SUCCEEDED,
    HandlerFn,
    StateResult,
    StateSpec,
    WorkflowDefinition,
)
from aila.storage.db_models import ManagedSystemRecord

__all__ = ["FORENSICS_PANEL_WRITEUP_V1", "run_forensics_panel_writeup"]


def _h(handler: object) -> HandlerFn:
    return cast("HandlerFn", handler)


def _step_dict(step: AgentStepRecord) -> dict[str, Any]:
    """Adapt a persisted panel step to the ordinary write-up step shape."""
    blob = json.loads(step.reasoning or "{}")
    if not isinstance(blob, dict):
        raise ValueError(f"panel step {step.id} has a non-object reasoning blob")
    return {
        "step_number": step.step_number,
        "action": step.action,
        "script_content": step.script_content,
        "command": step.command,
        "stdout": step.stdout,
        "stderr": step.stderr,
        "exit_code": step.exit_code,
        "reasoning": str(blob.get("reasoning") or ""),
        "provenance": blob.get("provenance"),
        "expected_observation": blob.get("expected_observation"),
        "panel": blob.get("panel"),
        "created_at": step.created_at.isoformat() if step.created_at else None,
    }


async def _state_load_panel_writeup(input: dict[str, Any], services: Any) -> StateResult:
    """Load one settled investigation and assemble the shared write-up input."""
    del services
    investigation_id = str(input.get("investigation_id") or "")
    if not investigation_id:
        raise ValueError("panel write-up: missing investigation_id")
    async with UnitOfWork() as uow:
        existing = (await uow.session.exec(
            select(WriteUpRecord)
            .where(WriteUpRecord.investigation_id == investigation_id)
            .order_by(WriteUpRecord.created_at.desc())
            .limit(1),
        )).first()
        if existing is not None:
            return StateResult(
                next_state=RESERVED_SUCCEEDED,
                output={**input, "writeup_id": existing.id},
            )
        inv = (await uow.session.exec(
            select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == investigation_id,
            ),
        )).first()
        if inv is None:
            raise ValueError(f"panel write-up: investigation {investigation_id} not found")
        project = (await uow.session.exec(
            select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == inv.project_id),
        )).first()
        if project is None:
            raise ValueError(f"panel write-up: project {inv.project_id} not found")
        system = (await uow.session.exec(
            select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id),
        )).first()
        if system is None:
            raise ValueError(f"panel write-up: analyzer system {project.system_id} not found")
        steps = (await uow.session.exec(
            select(AgentStepRecord)
            .where(AgentStepRecord.investigation_id == investigation_id)
            .order_by(AgentStepRecord.step_number, AgentStepRecord.created_at),
        )).all()
        outcome = None
        if inv.primary_outcome_id:
            outcome = (await uow.session.exec(
                select(ForensicsInvestigationOutcomeRecord).where(
                    ForensicsInvestigationOutcomeRecord.id == inv.primary_outcome_id,
                ),
            )).first()
        proposer = None
        if outcome is not None:
            proposer = (await uow.session.exec(
                select(ForensicsInvestigationBranchRecord).where(
                    ForensicsInvestigationBranchRecord.id == outcome.branch_id,
                ),
            )).first()
        case_state = json.loads(proposer.case_state_json if proposer is not None else "{}")
        outcome_payload = json.loads(outcome.payload_json) if outcome is not None else {}
        if not isinstance(case_state, dict) or not isinstance(outcome_payload, dict):
            raise ValueError("panel write-up: malformed outcome or branch state")
        output = {
            "investigation_id": investigation_id,
            "project_id": inv.project_id,
            "question": inv.question,
            "answer": inv.final_answer,
            "confidence": inv.confidence or "caveated",
            "steps": [_step_dict(step) for step in steps],
            "observables": case_state.get("observables") or {},
            "hypotheses": case_state.get("hypotheses") or [],
            "rejected": case_state.get("rejected") or [],
            "contract": outcome_payload.get("contract") or {},
            "integration": build_integration_payload(system),
            "evidence_directory": project.evidence_directory,
            "analyzer_os": project.analyzer_os,
        }
    return StateResult(next_state="promotion", output=output)


FORENSICS_PANEL_WRITEUP_V1 = WorkflowDefinition(
    definition_id="forensics.panel.writeup.v1",
    start_state="load",
    states={
        "load": StateSpec(
            handler=_h(_state_load_panel_writeup),
            timeout_s=60.0,
            max_retries=1,
            on_success="promotion",
        ),
        "promotion": StateSpec(
            handler=_h(state_freeflow_promotion),
            timeout_s=300.0,
            max_retries=1,
            on_success="writeup",
        ),
        "writeup": StateSpec(
            handler=_h(state_writeup),
            timeout_s=600.0,
            max_retries=1,
            on_success="response_emit",
        ),
        "response_emit": StateSpec(
            handler=_h(_state_response_emit),
            timeout_s=30.0,
            on_success=RESERVED_SUCCEEDED,
        ),
    },
    services_factory=_build_services,
)


@platform_task(
    track="forensics",
    module_id="forensics",
    max_tries=3,
    timeout_s=1800.0,
    definition=FORENSICS_PANEL_WRITEUP_V1,
)
async def run_forensics_panel_writeup(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed -- platform dispatch executes :data:`FORENSICS_PANEL_WRITEUP_V1`."""
    ...
