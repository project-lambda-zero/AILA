"""Analyzer actions for forensics panel branches.

The platform investigation loop hands every non-terminal panel decision to
:class:`PanelActionDispatcher`. Script, shell, and artifact-query decisions
run through the same analyzer actions the free-flow investigator uses
(:mod:`aila.modules.forensics.services.analyzer_actions`). Each executed
action is recorded twice in one transaction: as an ``AgentStepRecord`` on the
investigation (the step list and write-up read these) and as an engine
message on the branch (the panel researcher renders the branch's recent
results from these on its next turn).

The analyzer connection is resolved from the investigation's project and its
managed system row on every action, so a re-driven or sibling task needs no
connection details in its task kwargs.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func as sa_func
from sqlmodel import select

from aila.config import get_settings
from aila.modules.forensics.db_models import (
    AgentStepRecord,
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationMessageRecord,
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services import analyzer_actions
from aila.modules.forensics.services.agent_steps import bound_text, build_step_record
from aila.modules.forensics.services.integration import build_integration_payload
from aila.platform.agents.tool_execution import ToolExecutionResult
from aila.platform.contracts.enums import SenderKind
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.contracts.reasoning import ReasoningTurnDecision
from aila.platform.uow import UnitOfWork
from aila.storage.db_models import ManagedSystemRecord

__all__ = [
    "PANEL_ACTION_SENDER_ID",
    "PANEL_ANALYZER_SERVER_ID",
    "PanelActionDispatcher",
    "PanelAnalyzerUnavailableError",
]

_log = logging.getLogger(__name__)

# ``sender_id`` on the branch message that records an executed action. The
# panel researcher selects its recent results by this marker.
PANEL_ACTION_SENDER_ID = "panel_actions"
# ``server_id`` reported to the platform loop for every analyzer action.
PANEL_ANALYZER_SERVER_ID = "analyzer"

_EXECUTED_ACTIONS = frozenset({"script_execute", "tool_run", "artifact_query"})


class PanelAnalyzerUnavailableError(RuntimeError):
    """The investigation's project or analyzer system row is missing."""


@dataclass(frozen=True)
class _AnalyzerContext:
    project_id: str
    team_id: str | None
    analyzer_os: str
    integration: dict[str, Any]


async def _load_analyzer_context(investigation_id: str) -> _AnalyzerContext:
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(InvestigationRunRecord).where(InvestigationRunRecord.id == investigation_id),
        )).first()
        if inv is None:
            raise PanelAnalyzerUnavailableError(f"investigation {investigation_id} not found")
        project = (await uow.session.exec(
            select(ForensicsProjectRecord).where(ForensicsProjectRecord.id == inv.project_id),
        )).first()
        if project is None:
            raise PanelAnalyzerUnavailableError(
                f"project {inv.project_id} of investigation {investigation_id} not found",
            )
        system = (await uow.session.exec(
            select(ManagedSystemRecord).where(ManagedSystemRecord.id == project.system_id),
        )).first()
        if system is None:
            raise PanelAnalyzerUnavailableError(
                f"analyzer system {project.system_id} of project {project.id} no longer exists",
            )
        return _AnalyzerContext(
            project_id=project.id,
            team_id=inv.team_id,
            analyzer_os=project.analyzer_os,
            integration=build_integration_payload(system),
        )


async def _run_action(
    decision: ReasoningTurnDecision,
    ctx: _AnalyzerContext,
    *,
    investigation_id: str,
) -> tuple[str, dict[str, Any]]:
    """Run one analyzer action; return ``(tool_name, step fields)``."""
    settings = get_settings()
    if decision.action == "script_execute":
        script = decision.script_content or ""
        if not script.strip():
            return "run_script", {
                "stderr": "script_execute requires a non-empty script_content", "exit_code": 1,
            }
        result = await analyzer_actions.execute_script(
            settings=settings,
            integration=ctx.integration,
            analyzer_os=ctx.analyzer_os,
            investigation_id=investigation_id,
            script_content=script,
        )
        return "run_script", {"script_content": script, **result}
    if decision.action == "tool_run":
        try:
            shell_command = analyzer_actions.parse_tool_run_command(decision.command or "")
        except analyzer_actions.ToolRunContractError as exc:
            return "run_command", {"stderr": str(exc), "exit_code": 1}
        result = await analyzer_actions.execute_command(
            settings=settings,
            integration=ctx.integration,
            investigation_id=investigation_id,
            command=shell_command,
        )
        return "run_command", {"command": shell_command, **result}
    observables = decision.observables or {}
    result = await analyzer_actions.execute_artifact_query(
        settings=settings,
        project_id=ctx.project_id,
        search_text=(decision.command or "").strip(),
        artifact_family=str(observables.get("_artifact_family") or ""),
        artifact_type=str(observables.get("_artifact_type") or ""),
    )
    return "artifact_query", result


class PanelActionDispatcher:
    """Platform ``ActionDispatcher`` for forensics panel branches."""

    async def __call__(
        self,
        *,
        investigation_id: str,
        branch_id: str,
        decision: ReasoningTurnDecision,
        at_turn: int,
        phase_allowed_servers: frozenset[str] | None,
    ) -> ToolExecutionResult | None:
        del phase_allowed_servers  # analyzer actions are not MCP servers
        if decision.action not in _EXECUTED_ACTIONS:
            return None
        ctx = await _load_analyzer_context(investigation_id)
        tool_name, outcome = await _run_action(decision, ctx, investigation_id=investigation_id)
        exit_code = outcome.get("exit_code")
        success = exit_code == 0
        error = "" if success else str(outcome.get("stderr") or f"exit code {exit_code}")
        message_id = await self._record(
            investigation_id=investigation_id,
            branch_id=branch_id,
            team_id=ctx.team_id,
            decision=decision,
            at_turn=at_turn,
            outcome=outcome,
        )
        _log.info(
            "panel action inv=%s branch=%s turn=%d action=%s exit=%s",
            investigation_id, branch_id, at_turn, decision.action, exit_code,
        )
        return ToolExecutionResult(
            server_id=PANEL_ANALYZER_SERVER_ID,
            tool_name=tool_name,
            message_id=message_id,
            success=success,
            error=error[:2000],
        )

    async def _record(
        self,
        *,
        investigation_id: str,
        branch_id: str,
        team_id: str | None,
        decision: ReasoningTurnDecision,
        at_turn: int,
        outcome: dict[str, Any],
    ) -> str:
        """Write the step row and the branch message in one transaction."""
        async with UnitOfWork() as uow:
            branch = (await uow.session.exec(
                select(ForensicsInvestigationBranchRecord).where(
                    ForensicsInvestigationBranchRecord.id == branch_id,
                ),
            )).first()
            persona = (branch.persona_voice if branch is not None else None) or "primary"
            # Lock the investigation row so concurrent branches number their
            # steps without colliding.
            inv = (await uow.session.exec(
                select(InvestigationRunRecord)
                .where(InvestigationRunRecord.id == investigation_id)
                .with_for_update(),
            )).first()
            last_step = (await uow.session.exec(
                select(sa_func.coalesce(sa_func.max(AgentStepRecord.step_number), 0)).where(
                    AgentStepRecord.investigation_id == investigation_id,
                ),
            )).one()
            step_number = int(last_step or 0) + 1
            turn_result: dict[str, Any] = {
                "step_number": step_number,
                "action": decision.action,
                "reasoning": decision.reasoning,
                "expected_observation": decision.expected_observation,
                "contract": decision.contract.model_dump(mode="json") if decision.contract else {},
                "hypotheses": [h.model_dump(mode="json") for h in decision.hypotheses],
                "rejected": [r.model_dump(mode="json") for r in decision.rejected],
                "observables": dict(decision.observables or {}),
                "provenance": decision.provenance.model_dump(mode="json"),
                "submitted": False,
                **outcome,
            }
            uow.session.add(build_step_record(
                investigation_id=investigation_id,
                team_id=team_id,
                step_number=step_number,
                turn_result=turn_result,
                panel={"persona_voice": persona, "branch_id": branch_id, "at_turn": at_turn},
            ))
            if inv is not None:
                inv.attempts_used = step_number
                uow.session.add(inv)
            exit_code = outcome.get("exit_code")
            payload = {
                "text": f"{decision.action} exit={exit_code}",
                "action": decision.action,
                "reasoning": bound_text(decision.reasoning, 2000),
                "step_number": step_number,
                "command": analyzer_actions.sanitize_for_postgres_text(outcome.get("command")),
                "script_content": analyzer_actions.sanitize_for_postgres_text(
                    outcome.get("script_content"),
                ),
                "stdout": analyzer_actions.sanitize_for_postgres_text(outcome.get("stdout")),
                "stderr": analyzer_actions.sanitize_for_postgres_text(outcome.get("stderr")),
                "exit_code": exit_code,
                "is_error": exit_code != 0,
            }
            message = ForensicsInvestigationMessageRecord(
                investigation_id=investigation_id,
                branch_id=branch_id,
                sender_kind=SenderKind.ENGINE.value,
                sender_id=PANEL_ACTION_SENDER_ID,
                payload_kind=PayloadKind.TEXT.value,
                payload_json=json.dumps(payload, default=str),
                at_turn=at_turn,
                evidence_refs_json="[]",
            )
            uow.session.add(message)
            await uow.commit()
            return message.id
