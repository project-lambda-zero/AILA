"""Platform task entry point for the VR (vulnerability research) workflow.

The function is a pure seed stub decorated with ``@platform_task``.
All platform orchestration (WorkflowRunRecord creation, plan_json writes,
DurableStateMachine execution, state transitions) is owned by
``@platform_task`` via the workflow-engine dispatch path when a
``definition`` is supplied — the same pattern used by the forensics and
vulnerability modules.

This satisfies the v5.0 core principle: modules write pure state handlers
and nothing else.
"""
from __future__ import annotations

from typing import Any

import httpx

# Re-export enrichment-pipeline tasks so the platform worker bootstrap
# (which loads only ``<module>/workflow/task.py``) picks them up and
# registers them with the ARQ function table. Without these re-exports
# the API can enqueue rank/profile jobs but the worker rejects them
# with ``function 'run_function_ranking' not found``.
from aila.modules.vr.enrichment.workers import (  # noqa: F401  (re-export for ARQ registration)
    run_capability_profile_build,
    run_function_ranking,
)
from aila.modules.vr.workflow.definitions import VR_INVESTIGATE_V1, VR_NDAY_V1
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

# fix §141 + §142 — explicit transient-error tuple for @platform_task
# retries on this module's seeds. Without retriable_on, the @platform_task
# wrapper defaults to "retry on any exception", which retries
# non-transient failures (LLM-disabled-by-operator, KeyError-from-
# corrupted-state, CancelledError, Pydantic ValidationError, etc.) that
# will never succeed on a second try. Each retry costs one worker slot +
# whatever LLM tokens the first try burned before raising.
#
# The tuple covers exactly the transports that legitimately flap under
# load: DB / IO / socket (OSError), arbitrary wall-clock waits
# (TimeoutError), TCP-level rejects (ConnectionError), and httpx-level
# transport / 5xx upstream errors (httpx.HTTPError covers HTTPStatusError
# + TimeoutException + TransportError + ProtocolError). Anything else
# fails fast.
#
# Mirrors ``definitions._TRANSPORT_TRANSIENT`` (which controls per-STATE
# retries inside the workflow engine); this tuple controls per-TASK
# retries at the ARQ layer (the outer envelope around the engine run).
_TASK_TRANSIENT: tuple[type[BaseException], ...] = (
    OSError,
    TimeoutError,
    ConnectionError,
    httpx.HTTPError,
)

__all__ = [
    "run_capability_profile_build",
    "run_function_ranking",
    "run_fuzz_campaign_launch",
    "run_target_analysis",
    "run_vr_investigate",
    "run_vr_nday",
    "run_vr_outcome_dispatch",
    "run_vr_synthesis",
]


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=10800.0,  # 3 hours — covers full setup -> research -> PoC -> advisory
    # fix §141 — explicit retriable_on so the ARQ-level retry only
    # fires on transports that legitimately flap (the same shape as
    # VR_NDAY_V1's _TRANSPORT_TRANSIENT, mirrored here at task level).
    retriable_on=_TASK_TRANSIENT,
    definition=VR_NDAY_V1,
)
async def run_vr_nday(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed — platform dispatch handles workflow execution via VR_NDAY_V1."""
    ...


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=1,
    timeout_s=7800.0,  # 2h+ — covers a full investigation_loop run
    # fix §142 — explicit retriable_on so the single retry budget is
    # only spent on transport-class transients. VR_INVESTIGATE_V1's
    # investigation_setup state opens a DB session + does CVE-intel
    # network calls; a transient DB / network blip is worth the
    # retry, a Pydantic ValidationError / KeyError / PermissionError
    # / CancelledError is not.
    retriable_on=_TASK_TRANSIENT,
    definition=VR_INVESTIGATE_V1,
)
async def run_vr_investigate(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed function for the ``VR_INVESTIGATE_V1`` workflow definition.

    fix §83 — this body deliberately contains a single ``...`` Ellipsis.
    The ``@platform_task`` decorator wraps the function so the platform
    layer dispatches the workflow engine via the bound ``definition``
    kwarg above instead of executing this body. The body would only
    run if the platform decorator were removed; the docstring is the
    visible contract for readers. Do NOT add logic inside this function
    — phase-handoff / state transitions live on ``VR_INVESTIGATE_V1``.

    Required kwarg: ``investigation_id``. The setup state resolves the
    primary branch from the DB; operator does not provide branch_id.
    """
    ...


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=15600.0,  # 4h 20m — covers clone (10m) + 4h index poll + slack
)
async def run_target_analysis(
    ctx: TaskContext,
    target_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Backend ingestion for one target. Idempotent.

    Calls audit_mcp.index_codebase or ida.upload depending on kind,
    polls until ready, stores backend handles + auto-detected language
    on the row, and transitions analysis_state through INGESTING → READY
    (or → FAILED with operator-visible message).

    Auto-chains the post-ingestion enrichment stages
    (capability_profile + function_ranking) when ingestion completes —
    previously the operator had to re-hit ``/resume-analysis`` for
    each downstream stage to start. See ``_task_queue.enqueue_downstream_target_stages``.
    """
    from aila.modules.vr.services import TargetAnalysisService  # noqa: PLC0415  (lazy: avoids cycle)

    from .._task_queue import (  # noqa: PLC0415
        default_task_queue,
        enqueue_downstream_target_stages,
    )

    svc = TargetAnalysisService()
    await svc.analyze(target_id)

    # Fan out enrichment stages now that ingestion is DONE (or was
    # already DONE — the helper is idempotent and a no-op if ingestion
    # is somehow still pending).
    enqueued = await enqueue_downstream_target_stages(
        target_id,
        default_task_queue(),
        user_id=ctx.user_id,
        team_id=ctx.team_id,
    )
    return {"target_id": target_id, "status": "ok", "enqueued": enqueued}


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=1,
    timeout_s=120.0,  # SSH connect + start fuzzer; not the campaign itself
)
async def run_fuzz_campaign_launch(
    ctx: TaskContext,
    campaign_id: str,
    **_: Any,
) -> dict[str, Any]:
    """SSH to the campaign's analysis_system_id workstation, start
    the fuzzer per its engine_id, capture remote PID + corpus/crashes
    paths back onto the campaign row.

    Per D-33 the workstation is dedicated — AILA never runs the
    fuzzer in-process. This task only kicks off the remote process;
    the sidecar at ``tools/aila_fuzz_reporter/`` reports its progress
    back via PATCH /fuzz/campaigns/{id} + POST /fuzz/crashes.
    """
    del ctx
    from aila.modules.vr.services.fuzz_service import (  # noqa: PLC0415
        FuzzCampaignService,
    )

    svc = FuzzCampaignService()
    return await svc.launch_campaign(campaign_id)


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=300.0,  # ~3-4 LLM round-trips for PocWriter + retries
)
async def run_vr_draft_poc(
    ctx: TaskContext,
    finding_id: str,
    investigation_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Draft a PoC for a confirmed VR finding via PocWriter agent.

    Loads facts from the source investigation (via pdf_report's
    ``_collect_facts`` so PoC + PDF report see identical input),
    runs the writer, persists the result onto ``VRFindingRecord.
    poc_code`` + ``poc_language``.

    Failures are caught + logged onto the finding's
    ``draft_error_text`` field so operator sees what went wrong
    rather than a silent miss.
    """
    del ctx
    import json as _json  # noqa: PLC0415
    import logging  # noqa: PLC0415

    from sqlmodel import select  # noqa: PLC0415

    from aila.modules.vr.db_models import VRFindingRecord  # noqa: PLC0415
    from aila.modules.vr.reporting.pdf_report import (  # noqa: PLC0415
        _collect_facts,
    )
    from aila.modules.vr.reporting.poc_writer import PocWriter  # noqa: PLC0415
    from aila.platform.contracts._common import utc_now  # noqa: PLC0415
    from aila.platform.uow import UnitOfWork  # noqa: PLC0415

    log = logging.getLogger(__name__)

    # Gate: if the verifier already refuted this investigation's finding,
    # skip the PoC write entirely. Writing a PoC for a refuted claim
    # burns ~3 LLM round-trips on code that cannot reproduce a non-bug,
    # and the resulting "PoC" misleads operators into trusting the
    # finding. Mark the finding row with the skip reason instead.

    from aila.modules.vr.db_models import (  # noqa: PLC0415
        VRInvestigationOutcomeRecord,
    )

    async with UnitOfWork() as uow:
        canonical = (await uow.session.exec(
            select(VRInvestigationOutcomeRecord)
            .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
            .order_by(VRInvestigationOutcomeRecord.created_at.asc())
            .limit(1)
        )).first()
        if canonical is not None:
            try:
                cp = _json.loads(canonical.payload_json or "{}")
            except (ValueError, TypeError):
                cp = {}
            vr = cp.get("verifier_report") or {}
            if vr.get("verdict") == "refuted":
                conf = vr.get("confidence")
                conf_str = f"{conf:.2f}" if isinstance(conf, (int, float)) else "?"
                skip_reason = (
                    f"verifier_refuted_conf_{conf_str}: "
                    f"{(vr.get('summary') or '')[:300]}"
                )
                finding = (await uow.session.exec(
                    select(VRFindingRecord).where(VRFindingRecord.id == finding_id),
                )).first()
                if finding is not None:
                    finding.poc_skip_reason = skip_reason
                    finding.updated_at = utc_now()
                    uow.session.add(finding)
                    await uow.commit()
                log.info(
                    "run_vr_draft_poc SKIPPED finding=%s reason=verifier_refuted conf=%s",
                    finding_id, conf_str,
                )
                return {
                    "finding_id": finding_id,
                    "status": "skipped",
                    "reason": "verifier_refuted",
                    "verifier_confidence": conf,
                }

    facts = await _collect_facts(investigation_id)
    if facts is None:
        return {
            "finding_id": finding_id,
            "status": "error",
            "error": f"investigation {investigation_id} not found for PoC drafting",
        }

    poc_facts = {
        **facts,
        "vulnerability_class": (facts.get("final_answer") or "")[:120],
        "root_cause_summary": (facts.get("final_reasoning") or "")[:2000],
    }

    try:
        draft = await PocWriter().write(poc_facts)
    except (RuntimeError, ValueError) as exc:
        log.warning(
            "run_vr_draft_poc: writer failed for finding_id=%s err=%s",
            finding_id, exc,
        )
        return {
            "finding_id": finding_id,
            "status": "writer_error",
            "error": f"{type(exc).__name__}: {exc}",
        }

    persisted_at = utc_now()
    async with UnitOfWork() as uow:
        finding = (await uow.session.exec(
            select(VRFindingRecord).where(VRFindingRecord.id == finding_id),
        )).first()
        if finding is None:
            log.warning(
                "run_vr_draft_poc: finding %s disappeared before persist",
                finding_id,
            )
            return {
                "finding_id": finding_id,
                "status": "error",
                "error": "finding row disappeared between dispatch and persist",
            }
        finding.poc_code = draft.code
        finding.poc_language = draft.language[:32]
        # Stash the structured draft (build/run commands, caveats) on
        # evidence_refs_json as a single entry the UI can render —
        # poc_code is just the source, the rest of PocDraft is
        # metadata that doesn't have its own column.
        existing_refs = _json.loads(finding.evidence_refs_json or "[]")
        existing_refs.append({
            "kind": "poc_draft_metadata",
            "drafted_at": persisted_at.isoformat(),
            "title": draft.title,
            "build_command": draft.build_command,
            "run_command": draft.run_command,
            "target_setup": draft.target_setup,
            "expected_outcome": draft.expected_outcome,
            "can_run": draft.can_run,
            "missing_inputs": draft.missing_inputs,
            "caveats": draft.caveats,
            "safety_notes": draft.safety_notes,
        })
        finding.evidence_refs_json = _json.dumps(existing_refs)
        uow.session.add(finding)
        await uow.session.commit()

    log.info(
        "run_vr_draft_poc: finding=%s language=%s can_run=%s code_lines=%d",
        finding_id, draft.language, draft.can_run, draft.code.count("\n") + 1,
    )
    return {
        "finding_id": finding_id,
        "status": "ok",
        "language": draft.language,
        "can_run": draft.can_run,
        "code_chars": len(draft.code),
    }

@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=900.0,  # 15 min — one synthesis LLM call + DB writes
    # fix §141 / §142 — explicit retriable_on so retries only fire on
    # transport-class transients. Synthesis is an LLM round-trip + DB
    # writes: an LLM 5xx / connection blip is worth one retry, an
    # LLM-disabled-by-operator / structured-parse failure / state-
    # corruption KeyError is not.
    retriable_on=_TASK_TRANSIENT,
)
async def run_vr_synthesis(
    ctx: TaskContext,
    investigation_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Consolidate every persona branch's terminal outcome into one
    final synthesis outcome for the investigation.

    Triggered by ``investigation_emit._maybe_trigger_synthesis`` once
    every branch in the panel has submitted a terminal outcome.
    Idempotent — exits early if ``inv.primary_outcome_id`` is already
    set (synthesis already ran).
    """
    del ctx
    from aila.modules.vr.agents.synthesis_agent import (  # noqa: PLC0415
        SynthesisAgent,
    )
    agent = SynthesisAgent(investigation_id=investigation_id)
    return await agent.run()


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=600.0,  # 10 min — two LLM calls + N audit-mcp probes
)
async def run_vr_claim_verifier(
    ctx: TaskContext,
    investigation_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Adversarially verify the canonical outcome's claim.

    Three-stage pipeline (extract preconditions → probe audit-mcp →
    classify verdict) that writes ``verifier_report`` into the
    canonical outcome's payload. Triggered post-synthesis so the
    operator sees an independent confirmed/refuted verdict next to
    the panel's narrative — catches the false-positive classes the
    deliberation panel keeps missing on shape-pattern-matching alone.

    Idempotent — exits early when ``verifier_report`` is already in
    the canonical payload.
    """
    del ctx
    from aila.modules.vr.agents.claim_verifier import (  # noqa: PLC0415
        ClaimVerifierAgent,
    )
    agent = ClaimVerifierAgent(investigation_id=investigation_id)
    return await agent.run()


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=600.0,  # 10 min — dispatcher writes outcome + halts siblings + flips inv
)
async def run_vr_outcome_dispatch(
    ctx: TaskContext,
    outcome_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Dispatch one approved outcome via OutcomeDispatcher.dispatch.

    fix §90 — was an inline ``dispatcher.dispatch(...)`` call from
    ``HonestVulnResearcher.run_turn`` on quorum APPROVED. Dispatch
    cascades cross-branch (halts sibling branches, flips inv to
    COMPLETED, purges ARQ jobs) and must not run inside one branch's
    turn-execution context — other branches' workers would observe
    the cascade mid-flight outside their own atomic-commit boundary.

    This task lets the agent enqueue dispatch and continue its own
    turn cleanly; the dispatcher fires from its own worker context,
    inside its own UoW, against its own retry budget.
    """
    del ctx
    from aila.modules.vr.agents.outcome_dispatcher import (  # noqa: PLC0415
        OutcomeDispatcher,
    )
    from aila.platform.services.factory import (  # noqa: PLC0415
        ServiceFactory,
    )

    dispatcher = OutcomeDispatcher(knowledge=ServiceFactory().knowledge)
    result = await dispatcher.dispatch(outcome_id)
    return {
        "outcome_id": result.outcome_id,
        "outcome_kind": (
            result.outcome_kind.value
            if hasattr(result.outcome_kind, "value")
            else str(result.outcome_kind)
        ),
        "dispatch_status": (
            result.dispatch_status.value
            if hasattr(result.dispatch_status, "value")
            else str(result.dispatch_status)
        ),
        "dispatch_target": result.dispatch_target,
        "reason": result.reason,
    }
