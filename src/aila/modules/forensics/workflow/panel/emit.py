"""Forensics panel emit state.

Runs after each branch's investigation loop. It ticks sibling-review quorum
on every draft, records terminal verdicts as forensics experience patterns,
closes the branch whose loop just ended, and asks the shared finalizer to
settle the investigation once no branch remains active or paused.

The finalizer owns answer dispatch, terminal status, and write-up enqueueing.
Keeping those steps out of the phase-graph emit avoids duplicate terminal
writes and keeps the longer write-up LLM job outside this state's timeout.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.modules.forensics._task_queue import default_task_queue
from aila.modules.forensics.contracts.pattern import (
    ForensicsPatternCreate,
    ForensicsPatternKind,
)
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationOutcomeRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    evaluate_quorum,
    summarize_outcome_for_review,
)
from aila.modules.forensics.services.pattern_store import PatternStore
from aila.modules.forensics.workflow.panel.finalize import finalize_panel_investigation
from aila.platform.contracts import utc_now
from aila.platform.eval.experience_writer import ExperienceWriter
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import RESERVED_SUCCEEDED, StateResult

__all__ = ["state_forensics_panel_emit"]

_log = logging.getLogger(__name__)


async def _load_draft_outcome_ids(investigation_id: str) -> list[str]:
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(ForensicsInvestigationOutcomeRecord.id).where(
                ForensicsInvestigationOutcomeRecord.investigation_id == investigation_id,
                ForensicsInvestigationOutcomeRecord.state == OUTCOME_STATE_DRAFT,
            )
        )).all()
    return [str(rid) for rid in rows]


async def _load_outcome_payload(outcome_id: str) -> str | None:
    """Return the raw ``payload_json`` string for one outcome, or ``None``.

    Used by the RFC-08 record_experience hook to derive the pattern body
    from the same field ``summarize_outcome_for_review`` reads for sibling
    review prompts, so the pattern catalog carries the same finding text
    the panel deliberated on.
    """
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            _select(ForensicsInvestigationOutcomeRecord.payload_json).where(
                ForensicsInvestigationOutcomeRecord.id == outcome_id,
            )
        )).first()
    if row is None:
        return None
    return str(row or "")


async def _record_forensics_experience(
    *,
    verdict: Any,
    investigation_id: str,
    outcome_id: str,
    summary: str,
    body: str,
) -> None:
    """RFC-08 step 1 module closure: write a signed pattern on a verdict.

    Forensics has no target row -- the project IS the workspace, so the
    investigation's ``project_id`` doubles as ``workspace_id`` on the
    pattern create. Delegates to :class:`ExperienceWriter` with the
    forensics :class:`PatternStore` + :class:`ForensicsPatternCreate` +
    :attr:`ForensicsPatternKind.TRIAGE_RULE`. The writer itself skips
    non-terminal verdicts + empty summary/body, so a still-DRAFT quorum
    tick or a payload with no finding text is a safe no-op; the emit
    call site already gates on ``transition_occurred`` for the common
    still-DRAFT skip.
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == investigation_id,
            ),
        )).first()
    if inv is None or not inv.project_id:
        _log.warning(
            "forensics record_experience: investigation/project missing inv=%s",
            investigation_id,
        )
        return
    writer = ExperienceWriter(
        pattern_store=PatternStore(knowledge=ServiceFactory().knowledge),
        pattern_create_cls=ForensicsPatternCreate,
        pattern_kind=ForensicsPatternKind.TRIAGE_RULE,
    )
    result = await writer.record(
        workspace_id=inv.project_id,
        investigation_id=investigation_id,
        verdict=verdict,
        summary=summary,
        body=body,
        team_id=inv.team_id,
        evidence_refs=[outcome_id],
    )
    _log.info(
        "forensics record_experience outcome=%s pattern=%s polarity=%s "
        "skipped=%s",
        outcome_id, result.pattern_id, result.polarity, result.skipped_reason,
    )


async def _close_branch_after_loop(branch_id: str, exit_reason: str) -> None:
    """Close a branch whose own loop ended; preserve operator-driven states.

    The platform loop deliberately leaves branch status untouched on exit.
    Normal branch completion and branch-local failures are therefore settled
    here. Investigation pauses, cancellations, cursor stops, and sibling
    quorum abandonment already belong to another authority and are not
    overwritten.
    """
    if not branch_id:
        return
    if exit_reason in ("terminal_submit", "max_turns"):
        status = "completed"
    elif exit_reason.startswith(("researcher_error", "tool_loop_blocked")):
        status = "abandoned"
    else:
        return
    now = utc_now()
    async with UnitOfWork() as uow:
        branch = (await uow.session.exec(
            _select(ForensicsInvestigationBranchRecord)
            .where(ForensicsInvestigationBranchRecord.id == branch_id)
            .with_for_update(),
        )).first()
        if branch is None or branch.status != "active":
            return
        branch.status = status
        branch.closed_reason = exit_reason
        branch.closed_at = now
        branch.updated_at = now
        uow.session.add(branch)
        await uow.commit()


async def _reopen_reviewers_for_draft(
    investigation_id: str,
    outcome_id: str,
    proposer_branch_id: str,
) -> list[str]:
    """Re-drive closed reviewers when a rejected answer gets a successor.

    Approval needs two non-proposing votes. Without this step a second draft
    has only the still-running examiner available after the first proposer
    closed, so no later draft could ever reach quorum. Each examiner may
    propose only once (the researcher's repeat-proposal gate), which bounds
    these follow-up review tasks to the three-examiner panel.
    """
    # Deferred to avoid the panel task -> definition -> emit import cycle.
    from aila.modules.forensics.workflow.panel.task import (  # noqa: PLC0415
        run_forensics_panel_investigate,
    )

    async with UnitOfWork() as uow:
        outcome = (await uow.session.exec(
            _select(ForensicsInvestigationOutcomeRecord).where(
                ForensicsInvestigationOutcomeRecord.id == outcome_id,
            ),
        )).first()
        if outcome is None or outcome.state != OUTCOME_STATE_DRAFT:
            return []
        rejected_exists = (await uow.session.exec(
            _select(ForensicsInvestigationOutcomeRecord.id).where(
                ForensicsInvestigationOutcomeRecord.investigation_id == investigation_id,
                ForensicsInvestigationOutcomeRecord.state == OUTCOME_STATE_REJECTED,
            ).limit(1),
        )).first()
        if rejected_exists is None:
            return []
        inv = (await uow.session.exec(
            _select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == investigation_id,
            ),
        )).first()
        if inv is None or inv.status != "running":
            return []
        reviewers = (await uow.session.exec(
            _select(ForensicsInvestigationBranchRecord).where(
                ForensicsInvestigationBranchRecord.investigation_id == investigation_id,
                ForensicsInvestigationBranchRecord.id != proposer_branch_id,
                ForensicsInvestigationBranchRecord.status.in_(["completed", "abandoned"]),
            ),
        )).all()
        now = utc_now()
        for branch in reviewers:
            branch.status = "active"
            branch.closed_reason = None
            branch.closed_at = None
            branch.updated_at = now
            uow.session.add(branch)
        team_id = inv.team_id
        reviewer_ids = [branch.id for branch in reviewers]
        await uow.commit()

    for reviewer_id in reviewer_ids:
        try:
            await default_task_queue().submit(
                track="forensics",
                fn=run_forensics_panel_investigate,
                kwargs={"investigation_id": investigation_id, "branch_id": reviewer_id},
                user_id="system",
                group_id="forensics_panel_deliberation",
                team_id=team_id,
                bypass_dedup=True,
            )
        except (SQLAlchemyError, OSError, RuntimeError, ValueError) as exc:
            # The active row remains recoverable by the stuck-investigation
            # sweep; never claim it was enqueued when the broker rejected it.
            _log.exception(
                "forensics panel reviewer re-drive failed inv=%s branch=%s err=%s",
                investigation_id, reviewer_id, exc,
            )
    return reviewer_ids


async def state_forensics_panel_emit(
    input: dict[str, Any], services: Any,
) -> StateResult:
    """Evaluate panel quorum on every draft outcome + finalize when done."""
    del services  # emit uses only DB primitives; no external services needed
    investigation_id = str(input.get("investigation_id") or "")
    branch_id = str(input.get("branch_id") or "")
    if not investigation_id:
        raise ValueError("forensics_panel_emit: missing investigation_id")

    draft_ids = await _load_draft_outcome_ids(investigation_id)
    for outcome_id in draft_ids:
        try:
            result = await evaluate_quorum(outcome_id)
        except (RuntimeError, ValueError) as exc:
            _log.warning(
                "forensics_panel_emit quorum FAILED inv=%s outcome=%s err=%s",
                investigation_id, outcome_id, exc, exc_info=True,
            )
            continue
        _log.info(
            "forensics_panel_emit quorum inv=%s outcome=%s new_state=%s "
            "reason=%s",
            investigation_id, outcome_id, result.new_state,
            result.transition_reason,
        )
        # RFC-08 step 1: on a terminal quorum transition (approved or
        # rejected) hand the verdict + a payload excerpt to the
        # ExperienceWriter so a signed pattern lands in the forensics
        # PatternStore. Gated on ``transition_occurred`` so a still-
        # DRAFT quorum tick does not fire; mirrors the platform
        # investigation_emit_base gate. Best-effort: never break the
        # existing finalize path -- a store crash logs + continues.
        if result.transition_occurred and result.new_state in (
            OUTCOME_STATE_APPROVED, OUTCOME_STATE_REJECTED,
        ):
            try:
                payload_json = await _load_outcome_payload(outcome_id)
                excerpt = summarize_outcome_for_review(payload_json)
                first_line = excerpt.splitlines()[0] if excerpt else ""
                _summary = (first_line or excerpt)[:400]
                await _record_forensics_experience(
                    verdict=result,
                    investigation_id=investigation_id,
                    outcome_id=outcome_id,
                    summary=_summary,
                    body=excerpt,
                )
            except (
                SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError,
            ) as exc:
                _log.warning(
                    "forensics record_experience FAILED inv=%s outcome=%s "
                    "err=%s",
                    investigation_id, outcome_id, exc, exc_info=True,
                )

    exit_reason = str(input.get("exit_reason") or "")
    await _close_branch_after_loop(branch_id, exit_reason)
    reactivated_reviewer_ids: list[str] = []
    outcome_id = str(input.get("outcome_id") or "")
    if exit_reason == "terminal_submit" and outcome_id:
        reactivated_reviewer_ids = await _reopen_reviewers_for_draft(
            investigation_id, outcome_id, branch_id,
        )
    finalized = await finalize_panel_investigation(investigation_id)

    _log.info(
        "forensics_panel_emit DONE inv=%s branch=%s evaluated=%d status=%s",
        investigation_id, branch_id, len(draft_ids), finalized.status,
    )
    return StateResult(
        next_state=RESERVED_SUCCEEDED,
        output={
            **input,
            "quorum_evaluated_outcome_ids": draft_ids,
            "reactivated_reviewer_ids": reactivated_reviewer_ids,
            "investigation_status": finalized.status,
        },
    )
