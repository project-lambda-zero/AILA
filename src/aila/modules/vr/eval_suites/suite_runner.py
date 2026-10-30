"""Measurement-run orchestration for the VR benchmark harness.

``start_suite_run`` loads a suite manifest, creates one VR investigation
per benchmark task against the task's pre-provisioned target, enqueues the
investigation, and records a pending result row. ``collect_suite_run``
scores every task whose investigation has reached a terminal state
(reference-answer match + live cost + outcome polarity) and rolls the
aggregates onto the run row. ``leaderboard`` projects each suite's most
recent run.

The investigation-creation sequence mirrors the POST /vr/investigations
handler (validate target under team scope, insert the investigation plus
its primary HALVAR branch, submit ``run_vr_investigate``) so a measured run
is identical to an operator-launched one.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlmodel import select

from aila.platform.contracts import utc_now
from aila.platform.services.investigation_cost import compute_live_investigation_cost

from ..contracts import BranchStatus, InvestigationKind, InvestigationStatus, PersonaVoice
from ..db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from ..db_models.eval_suite import VREvalSuiteRunRecord, VREvalTaskResultRecord
from .answer_match import is_match
from .contracts import (
    BenchmarkTaskSpec,
    LeaderboardRow,
    SuiteRunSummary,
    TaskResultSummary,
)
from .manifest_loader import load_suite_manifest

__all__ = [
    "TERMINAL_STATUSES",
    "start_suite_run",
    "collect_suite_run",
    "leaderboard",
    "run_summary",
]

_log = logging.getLogger(__name__)

# Discovery is the default investigation kind for a benchmark task; the
# strategy string matches _KIND_DEFAULT_STRATEGY[DISCOVERY] in the router.
_DISCOVERY_STRATEGY = "vulnerability_research.discovery_research"

TERMINAL_STATUSES: frozenset[str] = frozenset({
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
    InvestigationStatus.ABANDONED.value,
    InvestigationStatus.STALLED.value,
})


def _collect_strings(value: Any, out: list[str]) -> None:
    """Append every string leaf of a parsed-JSON value to ``out``."""
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for item in value.values():
            _collect_strings(item, out)
    elif isinstance(value, list):
        for item in value:
            _collect_strings(item, out)


async def _candidate_texts(uow: Any, investigation_id: str) -> list[str]:
    """Return the answer-bearing strings an investigation produced.

    Reads the non-superseded outcome payloads for the investigation and
    flattens every string leaf -- the reference answer, when found, lives
    somewhere in a produced outcome (a finding body, a PoC, a memo).
    """
    stmt = select(VRInvestigationOutcomeRecord.payload_json).where(
        VRInvestigationOutcomeRecord.investigation_id == investigation_id,
        VRInvestigationOutcomeRecord.superseded_at.is_(None),
    )
    rows = (await uow.session.exec(stmt)).all()
    texts: list[str] = []
    for payload_json in rows:
        if not payload_json:
            continue
        try:
            parsed = json.loads(payload_json)
        except ValueError:
            texts.append(payload_json)
            continue
        _collect_strings(parsed, texts)
    return texts


async def start_suite_run(
    uow: Any,
    *,
    suite: str,
    dataset_root: str,
    default_budget_usd: float,
    requested_by: str | None,
    team_id: str | None,
    task_queue: Any,
) -> VREvalSuiteRunRecord:
    """Create a run, spin one investigation per task, enqueue each."""
    manifest = load_suite_manifest(dataset_root, suite)

    run = VREvalSuiteRunRecord(
        suite=suite,
        status="running",
        requested_by=requested_by,
        team_id=team_id,
        total_count=len(manifest.tasks),
    )
    uow.session.add(run)
    await uow.session.flush()

    to_submit: list[str] = []
    for task in manifest.tasks:
        investigation_id = await _spawn_task_investigation(
            uow,
            run_id=run.id,
            task=task,
            default_budget_usd=default_budget_usd,
            team_id=team_id,
        )
        if investigation_id is not None:
            to_submit.append(investigation_id)

    await uow.session.commit()
    await uow.session.refresh(run)

    # run_vr_investigate is imported lazily: workflow/task.py re-exports the
    # eval-suite tasks, so a top-level import here would be circular.
    from ..workflow.task import run_vr_investigate  # noqa: PLC0415

    for investigation_id in to_submit:
        await task_queue.submit(
            track="vr",
            fn=run_vr_investigate,
            kwargs={"investigation_id": investigation_id},
            user_id=requested_by,
            group_id="admin",
            team_id=team_id,
        )

    return run


async def _spawn_task_investigation(
    uow: Any,
    *,
    run_id: str,
    task: BenchmarkTaskSpec,
    default_budget_usd: float,
    team_id: str | None,
) -> str | None:
    """Insert the investigation + primary branch + pending result row.

    Returns the investigation id to enqueue, or None (recording an error
    result) when the task's target does not exist under the team scope.
    """
    target_stmt = select(VRTargetRecord).where(VRTargetRecord.id == task.target_id)
    if team_id is not None:
        target_stmt = target_stmt.where(VRTargetRecord.team_id == team_id)
    target = (await uow.session.exec(target_stmt)).first()

    if target is None:
        uow.session.add(VREvalTaskResultRecord(
            run_id=run_id,
            task_id=task.task_id,
            name=task.name,
            category=task.category,
            investigation_id=None,
            status="error",
            reference_answer=task.reference_answer,
            finished_at=utc_now(),
        ))
        _log.warning(
            "eval suite task '%s' target '%s' not found; recorded error",
            task.task_id, task.target_id,
        )
        return None

    investigation = VRInvestigationRecord(
        target_id=task.target_id,
        team_id=team_id,
        kind=InvestigationKind.DISCOVERY.value,
        title=task.name or task.task_id,
        initial_question=task.description or task.name or task.task_id,
        status=InvestigationStatus.CREATED.value,
        auto_pilot=True,
        strategy_family=_DISCOVERY_STRATEGY,
        cost_budget_usd=task.budget_usd or default_budget_usd,
    )
    uow.session.add(investigation)
    await uow.session.flush()

    uow.session.add(VRInvestigationBranchRecord(
        investigation_id=investigation.id,
        status=BranchStatus.ACTIVE.value,
        fork_reason="primary",
        persona_voice=PersonaVoice.HALVAR.value,
    ))
    uow.session.add(VREvalTaskResultRecord(
        run_id=run_id,
        task_id=task.task_id,
        name=task.name,
        category=task.category,
        investigation_id=investigation.id,
        status="pending",
        reference_answer=task.reference_answer,
    ))
    return investigation.id


async def collect_suite_run(uow: Any, run_id: str) -> VREvalSuiteRunRecord | None:
    """Score every task whose investigation is terminal; roll aggregates."""
    run = (await uow.session.exec(
        select(VREvalSuiteRunRecord).where(VREvalSuiteRunRecord.id == run_id),
    )).first()
    if run is None:
        return None

    results = (await uow.session.exec(
        select(VREvalTaskResultRecord).where(VREvalTaskResultRecord.run_id == run_id),
    )).all()

    pending_remaining = False
    for result in results:
        if result.status != "pending":
            continue
        if result.investigation_id is None:
            result.status = "error"
            result.finished_at = utc_now()
            continue
        investigation = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == result.investigation_id,
            ),
        )).first()
        if investigation is None:
            result.status = "error"
            result.finished_at = utc_now()
            continue
        if investigation.status not in TERMINAL_STATUSES:
            pending_remaining = True
            continue

        candidates = await _candidate_texts(uow, investigation.id)
        result.solved = is_match(result.reference_answer, candidates)
        result.cost_usd = await compute_live_investigation_cost(uow, investigation.id)
        result.polarity = investigation.primary_outcome_polarity
        result.status = "scored"
        result.finished_at = utc_now()

    run.solved_count = sum(1 for r in results if r.solved)
    run.total_cost_usd = float(sum(r.cost_usd for r in results))
    run.total_count = len(results)
    if not pending_remaining:
        run.status = "collected"
        run.finished_at = utc_now()

    await uow.session.commit()
    await uow.session.refresh(run)
    return run


def _result_summary(result: VREvalTaskResultRecord) -> TaskResultSummary:
    return TaskResultSummary(
        task_id=result.task_id,
        name=result.name,
        category=result.category,
        investigation_id=result.investigation_id,
        status=result.status,
        solved=result.solved,
        cost_usd=result.cost_usd,
        polarity=result.polarity,
    )


def _iso(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


async def run_summary(uow: Any, run_id: str) -> SuiteRunSummary | None:
    """Return a run with its per-task result rows, or None when absent."""
    run = (await uow.session.exec(
        select(VREvalSuiteRunRecord).where(VREvalSuiteRunRecord.id == run_id),
    )).first()
    if run is None:
        return None
    results = (await uow.session.exec(
        select(VREvalTaskResultRecord)
        .where(VREvalTaskResultRecord.run_id == run_id)
        .order_by(VREvalTaskResultRecord.task_id),
    )).all()
    return SuiteRunSummary(
        id=run.id,
        suite=run.suite,
        status=run.status,
        solved_count=run.solved_count,
        total_count=run.total_count,
        total_cost_usd=run.total_cost_usd,
        created_at=_iso(run.created_at),
        finished_at=_iso(run.finished_at),
        results=[_result_summary(r) for r in results],
    )


async def leaderboard(uow: Any) -> list[LeaderboardRow]:
    """Aggregate each suite's most recent run into a leaderboard row."""
    runs = (await uow.session.exec(
        select(VREvalSuiteRunRecord).order_by(VREvalSuiteRunRecord.created_at.desc()),
    )).all()
    seen: set[str] = set()
    rows: list[LeaderboardRow] = []
    for run in runs:
        if run.suite in seen:
            continue
        seen.add(run.suite)
        total = run.total_count or 0
        solved = run.solved_count or 0
        rows.append(LeaderboardRow(
            suite=run.suite,
            solved_count=solved,
            total_count=total,
            solve_rate=(solved / total) if total else 0.0,
            avg_cost_usd=(run.total_cost_usd / total) if total else 0.0,
            last_run_at=_iso(run.created_at),
        ))
    return rows
