"""Platform task entry point for the VR (vulnerability research) workflow.

The function is a pure seed stub decorated with ``@platform_task``.
All platform orchestration (WorkflowRunRecord creation, plan_json writes,
DurableStateMachine execution, state transitions) is owned by
``@platform_task`` via the workflow-engine dispatch path when a
``definition`` is supplied -- the same pattern used by the forensics and
vulnerability modules.

This satisfies the v5.0 core principle: modules write pure state handlers
and nothing else.
"""
from __future__ import annotations

import json as _json
import logging
from typing import Any

import httpx
from sqlmodel import select

from aila.modules.vr._task_queue import (
    default_task_queue,
    enqueue_downstream_target_stages,
)
from aila.modules.vr.agents.claim_verifier import ClaimVerifierAgent
from aila.modules.vr.agents.narrative_agent import (
    NarrativeOptions,
    VRNarrativeAgent,
)
from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules.vr.agents.synthesis_agent import SynthesisAgent
from aila.modules.vr.contracts.evidence_ref import EvidenceRefList
from aila.modules.vr.db_models import VRFindingRecord, VRInvestigationOutcomeRecord

# Re-export enrichment-pipeline tasks so the platform worker bootstrap
# (which loads only ``<module>/workflow/task.py``) picks them up and
# registers them with the ARQ function table. Without these re-exports
# the API can enqueue rank/profile jobs but the worker rejects them
# saying ``function 'run_function_ranking' not found``.
from aila.modules.vr.enrichment.workers import (
    run_capability_profile_build,
    run_function_ranking,
    run_target_enrichment,
)
from aila.modules.vr.reporting.pdf_report import _collect_facts
from aila.modules.vr.reporting.poc_writer import PocWriter
from aila.modules.vr.services import TargetAnalysisService
from aila.modules.vr.services.followup_discovery import maybe_spawn_vr_followup
from aila.modules.vr.services.fuzz_service import FuzzCampaignService
from aila.modules.vr.workflow.definitions import VR_NDAY_V1
from aila.modules.vr.workflow.definitions_hub import VR_INVESTIGATE_HUB
from aila.platform.contracts import utc_now
from aila.platform.services.factory import ServiceFactory
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task
from aila.platform.uow import UnitOfWork

# fix §141 + §142 -- explicit transient-error tuple for @platform_task
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

_log = logging.getLogger(__name__)

__all__ = [
    "run_capability_profile_build",
    "run_function_ranking",
    "run_fuzz_campaign_launch",
    "run_target_analysis",
    "run_target_enrichment",
    "run_vr_auto_patch",
    "run_vr_claim_verifier",
    "run_vr_investigate",
    "run_vr_narrative",
    "run_vr_nday",
    "run_vr_outcome_dispatch",
    "run_vr_synthesis",
]


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=10800.0,  # 3 hours -- covers full setup -> research -> PoC -> advisory
    # fix §141 -- explicit retriable_on so the ARQ-level retry only
    # fires on transports that legitimately flap (the same shape as
    # VR_NDAY_V1's _TRANSPORT_TRANSIENT, mirrored here at task level).
    retriable_on=_TASK_TRANSIENT,
    definition=VR_NDAY_V1,
)
async def run_vr_nday(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed -- platform dispatch handles workflow execution via VR_NDAY_V1."""
    ...


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=1,
    timeout_s=7800.0,  # 2h+ -- covers a full investigation_loop run
    # fix §142 -- explicit retriable_on so the single retry budget is
    # only spent on transport-class transients. VR_INVESTIGATE_HUB's
    # investigation_setup state opens a DB session + does CVE-intel
    # network calls; a transient DB / network blip is worth the
    # retry, a Pydantic ValidationError / KeyError / PermissionError
    # / CancelledError is not.
    retriable_on=_TASK_TRANSIENT,
    definition=VR_INVESTIGATE_HUB,
)
async def run_vr_investigate(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed function for the ``VR_INVESTIGATE_HUB`` workflow definition.

    fix §83 -- this body deliberately contains a single ``...`` Ellipsis.
    The ``@platform_task`` decorator wraps the function so the platform
    layer dispatches the workflow engine via the bound ``definition``
    kwarg above instead of executing this body. The body would only
    run if the platform decorator were removed; the docstring is the
    visible contract for readers. Do NOT add logic inside this function
    -- phase-handoff / state transitions live on ``VR_INVESTIGATE_HUB``.

    Required kwarg: ``investigation_id``. The setup state resolves the
    primary branch from the DB; operator does not provide branch_id.
    """
    ...


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=15600.0,  # 4h 20m -- covers clone (10m) + 4h index poll + slack
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
    (capability_profile + function_ranking) when ingestion completes --
    previously the operator had to re-hit ``/resume-analysis`` for
    each downstream stage to start. See ``_task_queue.enqueue_downstream_target_stages``.
    """
    svc = TargetAnalysisService()
    await svc.analyze(target_id)

    # Fan out enrichment stages now that ingestion is DONE (or was
    # already DONE -- the helper is idempotent and a no-op if ingestion
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

    Per D-33 the workstation is dedicated -- AILA never runs the
    fuzzer in-process. This task only kicks off the remote process;
    the sidecar at ``tools/aila_fuzz_reporter/`` reports its progress
    back via PATCH /fuzz/campaigns/{id} + POST /fuzz/crashes.
    """
    del ctx
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
    """Draft a PoC for a confirmed VR finding via the PocWriter agent.

    Loads facts from the source investigation (via pdf_report's
    ``_collect_facts`` so PoC + PDF report see identical input),
    runs the writer, then commits ``poc_code``, ``poc_language``,
    and a structured ``poc_draft_metadata`` entry into
    ``VRFindingRecord.evidence_refs_json``.

    If the canonical outcome's ``verifier_report`` verdict is
    ``refuted``, skips drafting entirely and stamps the finding's
    ``poc_skip_reason`` so operators see why no PoC exists.

    Writer-side failures (RuntimeError / ValueError) are logged via
    ``log.warning`` and returned in the result dict with
    ``status='writer_error'``; the finding row is left untouched in
    that case.
    """
    del ctx
    log = logging.getLogger(__name__)

    # Gate: if the verifier already refuted this investigation's finding,
    # skip the PoC write entirely. Writing a PoC for a refuted claim
    # burns ~3 LLM round-trips on code that cannot reproduce a non-bug,
    # and the resulting "PoC" misleads operators into trusting the
    # finding. Mark the finding row with the skip reason instead.

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
        # evidence_refs_json as a single entry the UI can render --
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
        finding.evidence_refs_json = EvidenceRefList.model_validate(
            existing_refs,
        ).model_dump_json()
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
    timeout_s=900.0,  # 15 min -- one synthesis LLM call + DB writes
    # fix §141 / §142 -- explicit retriable_on so retries only fire on
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
    Idempotent -- exits early if ``inv.primary_outcome_id`` is already
    set (synthesis already ran).
    """
    del ctx
    agent = SynthesisAgent(investigation_id=investigation_id)
    result = await agent.run()
    # Autonomous take-over of the panel's recommended further
    # discoveries. Gated on the primitive (only fires on
    # ``no_finding`` / ``inconclusive`` polarity + non-empty
    # recommendations + depth cap + budget floor + idempotency), so
    # calling it unconditionally is safe -- every skip returns a
    # ``{'status': 'skipped', 'reason': ...}`` dict. A follow-up
    # failure MUST NOT fail the synthesis task itself: the panel_summary
    # is already committed, the operator surface has already updated,
    # and the follow-up chain is a best-effort autonomy layer on top.
    if isinstance(result, dict) and result.get("status") == "ok":
        try:
            followup = await maybe_spawn_vr_followup(investigation_id)
        except (OSError, RuntimeError, TimeoutError, ValueError) as exc:
            _log.warning(
                "run_vr_synthesis follow-up spawn failed inv=%s err=%s",
                investigation_id, exc,
            )
            followup = {"status": "failed", "reason": f"{type(exc).__name__}"}
        result["followup"] = followup
    return result


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=900.0,  # 15 min -- one long-form LLM call + DB writes
    # Retries only on transport-class transients. An LLM 5xx / DB blip
    # is worth one retry; an LLM-disabled-by-operator, structured-
    # parse failure, or state-corruption KeyError is not (mirrors the
    # rationale on run_vr_synthesis above).
    retriable_on=_TASK_TRANSIENT,
)
async def run_vr_narrative(
    ctx: TaskContext,
    investigation_id: str,
    options: dict[str, Any] | None = None,
    **_: Any,
) -> dict[str, Any]:
    """Generate the long-form narrative writeup for one investigation.

    Separate artifact from :func:`run_vr_synthesis` -- the narrative
    is a chronological vulnerability-research story stored under
    ``payload["investigation_narrative"]`` on the canonical outcome,
    alongside (not replacing) ``payload["panel_summary"]`` from the
    synthesis path.

    Reachable from ``POST /vr/investigations/{id}/narrative`` with
    optional ``options`` carrying tone / length / focus knobs.
    Idempotent without ``options.force``: skips when a narrative is
    already present on the canonical outcome.
    """
    del ctx
    opts = NarrativeOptions()
    if options:
        for key in ("force", "tone", "length", "operator_focus"):
            if key in options:
                setattr(opts, key, options[key])
    agent = VRNarrativeAgent(investigation_id=investigation_id, options=opts)
    return await agent.run()


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=600.0,  # 10 min -- two LLM calls + N audit-mcp probes
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
    the panel's narrative -- catches the false-positive classes the
    deliberation panel keeps missing on shape-pattern-matching alone.

    Idempotent -- exits early when ``verifier_report`` is already in
    the canonical payload.
    """
    del ctx
    agent = ClaimVerifierAgent(investigation_id=investigation_id)
    return await agent.run()


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=600.0,  # 10 min -- dispatcher writes outcome + halts siblings + flips inv
)
async def run_vr_outcome_dispatch(
    ctx: TaskContext,
    outcome_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Dispatch one approved outcome via OutcomeDispatcher.dispatch.

    fix §90 -- was an inline ``dispatcher.dispatch(...)`` call from
    ``HonestVulnResearcher.run_turn`` on quorum APPROVED. Dispatch
    cascades cross-branch (halts sibling branches, flips inv to
    COMPLETED, purges ARQ jobs) and must not run inside one branch's
    turn-execution context -- other branches' workers would observe
    the cascade mid-flight outside their own atomic-commit boundary.

    This task lets the agent enqueue dispatch and continue its own
    turn cleanly; the dispatcher fires from its own worker context,
    inside its own UoW, against its own retry budget.
    """
    del ctx
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


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=900.0,
    retriable_on=_TASK_TRANSIENT,
)
async def run_vr_auto_patch(
    ctx: TaskContext,
    investigation_id: str,
    **_: Any,
) -> dict[str, Any]:
    """RFC #149 auto-patch synthesis + verifier for a confirmed VR finding.

    Triggered from :func:`aila.platform.workflows.investigation_emit_base
    ._maybe_trigger_patcher` after the claim verifier writes a
    ``verifier_report`` with ``verdict == "confirmed"`` on the canonical
    outcome AND the operator has flipped ``platform.autopatch_enabled``
    to True. Default OFF so this task never fires on an unmodified
    deployment.
    """
    del ctx
    return await _run_vr_auto_patch(investigation_id)


async def _run_vr_auto_patch(investigation_id: str) -> dict[str, Any]:
    """Body for :func:`run_vr_auto_patch` -- separated so tests can
    call it without the ARQ decorator wrapper."""
    from aila.config import get_settings
    from aila.platform.config import build_platform_settings
    from aila.platform.services.patching import (
        PatchFinding,
        PatchingService,
    )

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationOutcomeRecord)
            .where(VRInvestigationOutcomeRecord.investigation_id == investigation_id)
            .order_by(VRInvestigationOutcomeRecord.created_at.asc())
            .limit(1)
        )).first()
        if inv is None:
            return {"status": "skipped", "reason": "no_canonical_outcome"}
        try:
            payload = _json.loads(inv.payload_json or "{}")
        except (ValueError, TypeError):
            payload = {}
        if payload.get("patch_report"):
            return {"status": "skipped", "reason": "already_patched"}
        vr = payload.get("verifier_report") or {}
        if not isinstance(vr, dict) or vr.get("verdict") != "confirmed":
            return {"status": "skipped", "reason": "verifier_not_confirmed"}
        # Grab the newest finding created for this investigation via
        # the outcome's investigation link -- OutcomeDispatcher writes
        # one VRFindingRecord per confirmed finding.
        from aila.modules.vr.db_models.investigation import VRInvestigationRecord
        inv_row = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            )
        )).first()
        if inv_row is None:
            return {"status": "skipped", "reason": "investigation_row_missing"}
        finding = (await uow.session.exec(
            select(VRFindingRecord)
            .where(VRFindingRecord.project_id == inv_row.project_id)
            .order_by(VRFindingRecord.created_at.desc())
            .limit(1),
        )).first()

    platform_settings = build_platform_settings(get_settings())
    patching = PatchingService(platform_settings)
    if not await patching.is_enabled():
        return {"status": "skipped", "reason": "autopatch_disabled"}

    # Assemble PatchFinding from the finding record (fall back to the
    # canonical outcome payload when no finding row was persisted --
    # confirmed-without-finding is a legitimate short-circuit path).
    finding_ref = finding.id if finding is not None else f"outcome:{inv.id}"
    root_cause = (finding.root_cause if finding is not None else "") or str(
        payload.get("root_cause") or payload.get("answer") or "",
    )
    vuln_fn = (finding.vulnerable_function if finding is not None else "") or str(
        payload.get("vulnerable_function") or "",
    )
    cwe_id = (finding.cwe_id if finding is not None else "") or str(
        payload.get("cwe_id") or "",
    )
    title = str(payload.get("title") or payload.get("summary") or "")

    patch_finding = PatchFinding(
        finding_ref=finding_ref,
        module_id="vr",
        investigation_id=investigation_id,
        outcome_id=inv.id,
        team_id=inv_row.team_id,
        title=title[:256],
        root_cause=root_cause[:8000],
        vulnerable_function=vuln_fn[:255],
        cwe_id=cwe_id[:16],
        verifier_report=vr,
    )

    # Source context via audit-mcp read_function when the finding named
    # a function; empty context (root_cause only) otherwise so the
    # coder model decides to DECLINE gracefully.
    source_ctx = await _fetch_vr_source_ctx(
        investigation_id=investigation_id,
        vulnerable_function=vuln_fn,
        affected_components=payload.get("affected_components") or [],
    )

    # Harness: reuse the finding's PoC as the reproducer. When there is
    # no PoC we still call verify_patch (records skipped/no_harness) so
    # the attempt row lands.
    harness = _build_vr_harness(finding=finding)

    attempt = await patching.run(patch_finding, source_ctx, harness)

    # Stamp patch_report on the canonical outcome payload -- the
    # emit-chokepoint idempotency check reads this key next fire.
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRInvestigationOutcomeRecord).where(
                VRInvestigationOutcomeRecord.id == inv.id,
            )
        )).first()
        if row is None:
            return {
                "status": "ok",
                "attempt_id": attempt.attempt_id,
                "verify_status": attempt.verify.status,
                "verify_reason": attempt.verify.reason,
                "warning": "outcome_disappeared_before_stamp",
            }
        try:
            merged = _json.loads(row.payload_json or "{}")
        except (ValueError, TypeError):
            merged = {}
        merged["patch_report"] = {
            "attempt_id": attempt.attempt_id,
            "finding_ref": attempt.finding_ref,
            "verdict": attempt.verify.status,
            "reason": attempt.verify.reason,
            "files": list(attempt.synthesis.files),
            "synth_model": attempt.synthesis.model,
            "cost_usd": attempt.total_cost_usd,
            "declined": attempt.synthesis.declined,
        }
        row.payload_json = _json.dumps(merged)
        uow.session.add(row)
        await uow.commit()

    _log.info(
        "vr auto_patch DONE inv=%s attempt=%s verdict=%s reason=%s cost_usd=%.4f",
        investigation_id, attempt.attempt_id,
        attempt.verify.status, attempt.verify.reason, attempt.total_cost_usd,
    )
    return {
        "status": "ok",
        "attempt_id": attempt.attempt_id,
        "finding_ref": attempt.finding_ref,
        "verify_status": attempt.verify.status,
        "verify_reason": attempt.verify.reason,
        "synth_declined": attempt.synthesis.declined,
        "synth_files": list(attempt.synthesis.files),
        "total_cost_usd": attempt.total_cost_usd,
    }


async def _fetch_vr_source_ctx(
    *,
    investigation_id: str,
    vulnerable_function: str,
    affected_components: list[Any],
) -> list[Any]:
    """Retrieve one or more :class:`PatchSourceContext` blobs via
    audit-mcp read_function for the coder model.

    Returns an empty list when no source is reachable. The caller
    (:func:`_run_vr_auto_patch`) still calls the synthesiser -- the
    coder LLM is expected to DECLINE cleanly when the context is
    insufficient, and that DECLINE gets recorded as
    ``synthesis_declined`` on the attempt row so operators can see
    which findings need better source pinpointing before autopatch
    can help.
    """
    # Resolve target index_id from the investigation's target row.
    from aila.modules.vr.db_models.investigation import VRInvestigationRecord
    from aila.modules.vr.db_models.target import VRTargetRecord
    from aila.platform.mcp.factory import make_bridge
    from aila.platform.services.patching import PatchSourceContext
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            )
        )).first()
        if inv is None or not inv.target_id:
            return []
        target = (await uow.session.exec(
            select(VRTargetRecord).where(
                VRTargetRecord.id == inv.target_id,
            )
        )).first()
    if target is None:
        return []
    try:
        handles = _json.loads(target.mcp_handles_json or "{}")
    except (ValueError, TypeError):
        handles = {}
    index_id = str(handles.get("audit_mcp_index_id") or "")
    if not index_id:
        return []

    # Extract (file_path, function_name) pairs from affected_components
    # first; fall back to the finding's vulnerable_function alone.
    pairs: list[tuple[str, str]] = []
    for raw in (affected_components or [])[:4]:
        if isinstance(raw, dict):
            fp = str(raw.get("file") or "").strip()
            fn = str(raw.get("function") or "").strip()
            if fp and fn:
                pairs.append((fp, fn))
    if not pairs and vulnerable_function:
        pairs.append(("", vulnerable_function))
    if not pairs:
        return []

    from aila.modules.vr.services.mcp_call_logger import record_call
    bridge = make_bridge("audit_mcp", module_id="vr", recorder=record_call)
    ctxs: list[PatchSourceContext] = []
    for fp, fn in pairs:
        args = {"index_id": index_id, "name": fn}
        if fp:
            args["file_path"] = fp
        try:
            result = await bridge.forward(action="read_function", **args)
        except (OSError, RuntimeError, ValueError, httpx.HTTPError):
            continue
        if not isinstance(result, dict) or result.get("status") == "error":
            continue
        body = result.get("body")
        if isinstance(body, list):
            code = "\n".join(str(b) for b in body)
        else:
            code = str(body or result.get("content") or "")
        if not code.strip():
            continue
        rendered_path = str(result.get("file_path") or fp or f"{fn}.src")
        start_line = int(result.get("start_line") or 1)
        ctxs.append(PatchSourceContext(
            file_path=rendered_path,
            start_line=start_line,
            content=code[:16000],
            language=_vr_language_from_ext(rendered_path),
            notes=f"read_function name={fn}",
        ))
    return ctxs


def _vr_language_from_ext(file_path: str) -> str:
    ext = file_path.rsplit(".", 1)[-1].lower() if "." in file_path else ""
    return {
        "c": "c", "h": "c",
        "cc": "cpp", "cpp": "cpp", "cxx": "cpp", "hpp": "cpp",
        "py": "python", "rs": "rust", "go": "go",
        "js": "javascript", "ts": "typescript", "java": "java",
    }.get(ext, "")


def _build_vr_harness(*, finding: Any) -> Any:
    """Build a :class:`PatchHarness` from the finding's PoC.

    Only text-source PoCs (python / shell / node) can be re-run inside
    the sandbox without a compile step, so we honour the finding's
    ``poc_language`` and pick the interpreter accordingly. Compiled
    PoCs (C / C++ / rust) are recorded as unavailable -- a follow-up
    can wire a compile-then-run harness once the sandbox has toolchains
    provisioned.
    """
    from aila.platform.services.patching import PatchHarness

    if finding is None or not (finding.poc_code or "").strip():
        return PatchHarness(available=False)

    lang = (finding.poc_language or "").strip().lower()
    poc = finding.poc_code
    interpreter_map = {
        "python": ("python3", "poc.py"),
        "python3": ("python3", "poc.py"),
        "py": ("python3", "poc.py"),
        "bash": ("bash", "poc.sh"),
        "sh": ("sh", "poc.sh"),
        "shell": ("bash", "poc.sh"),
        "node": ("node", "poc.js"),
        "javascript": ("node", "poc.js"),
        "js": ("node", "poc.js"),
    }
    picked = interpreter_map.get(lang)
    if picked is None:
        # Compiled PoC -- record unavailable so the row still lands.
        return PatchHarness(available=False)
    interpreter, filename = picked

    # Vulnerable PoC exits non-zero (or crashes); patched code exits
    # cleanly. crash_signature reuses the finding's ASAN/UBSAN keyword
    # when present so a re-crash on the patched build still trips
    # ``rejected`` even if exit code silently changed.
    signature = ""
    if finding.asan_report:
        for tag in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "SIGSEGV"):
            if tag in finding.asan_report:
                signature = tag
                break
    return PatchHarness(
        available=True,
        argv=[interpreter, filename],
        input_files={filename: poc},
        env={},
        timeout_s=60.0,
        workdir="/work",
        expected_exit=0,
        crash_signature=signature,
    )
