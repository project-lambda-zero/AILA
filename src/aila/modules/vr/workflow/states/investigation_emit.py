"""Investigation emit state (M3.R-7).

Finalizes the investigation row based on the loop's exit reason:
  terminal_submit             → COMPLETED, primary_outcome_id linked
  max_turns                   → AUTO-RE-ENQUEUE (status stays RUNNING)
                                if branch.turn_count < _OVERALL_TURN_CAP
                                AND no terminal outcome -- the agent
                                keeps reasoning across multiple task
                                runs until it converges or hits the
                                cumulative cap. Operator can pause via
                                the API at any time.
  max_turns + cumulative cap  → COMPLETED with reason "exhausted --
                                operator should review or re-enqueue"
  status_flipped:paused       → PAUSED stays PAUSED (don't overwrite)
  status_flipped:failed       → FAILED stays FAILED
  researcher_error:*          → FAILED, error recorded in observables
                                of the primary branch
"""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr._task_queue import default_task_queue
from aila.modules.vr.agents.branch_manager import BranchManager
from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules.vr.agents.pattern_extractor import (
    PatternExtractor,
)
from aila.modules.vr.contracts.pattern import PatternKind, VRPatternCreate
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    evaluate_quorum,
    post_draft_review_request,
)
from aila.modules.vr.services.pattern_store import PatternStore
from aila.modules.vr.workflow.finalize import finalize_investigation
from aila.platform.config_base import ModuleConfigReader
from aila.platform.eval.experience_writer import ExperienceWriter
from aila.platform.services.factory import ServiceFactory
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.investigation_emit_base import (
    state_investigation_emit as _build_emit_state,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)
from aila.platform.workflows.types import StateResult

__all__ = ["state_investigation_emit"]

_log = logging.getLogger(__name__)
_cfg = ModuleConfigReader("vr")


# The emit handler is the platform factory bound to VR's models + agents.
# Built lazily on first call: the synthesis / verifier / investigate task
# functions live in vr.workflow.task, which imports vr.workflow.definitions
# (which imports this state module), so a module-level task import would be
# circular. First-call build defers them to a point where every module is
# fully imported.
_HANDLER: Any = None


async def _record_experience(
    *,
    verdict: Any,
    investigation_id: str,
    outcome_id: str,
    summary: str,
    body: str,
) -> None:
    """RFC-08 step 1 module closure: write a signed pattern on a verdict.

    Resolves the investigation's ``workspace_id`` via the
    investigation -> target chain (target owns ``workspace_id`` on VR),
    then delegates to :class:`ExperienceWriter` with VR's PatternStore
    + ``VRPatternCreate`` + ``PatternKind.TRIAGE_RULE``. The writer
    itself skips non-terminal states + empty summary/body so a DRAFT
    verdict is a safe no-op; the emit_base call site already gates on
    ``transition_occurred`` for the common still-DRAFT skip.
    """
    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            ),
        )).first()
        if inv is None:
            _log.warning(
                "vr record_experience: investigation %s missing",
                investigation_id,
            )
            return
        target = (await uow.session.exec(
            _select(VRTargetRecord).where(
                VRTargetRecord.id == inv.target_id,
            ),
        )).first()
    if target is None or not target.workspace_id:
        _log.warning(
            "vr record_experience: target/workspace missing inv=%s",
            investigation_id,
        )
        return

    writer = ExperienceWriter(
        pattern_store=PatternStore(knowledge=ServiceFactory().knowledge),
        pattern_create_cls=VRPatternCreate,
        pattern_kind=PatternKind.TRIAGE_RULE,
    )
    result = await writer.record(
        workspace_id=target.workspace_id,
        investigation_id=investigation_id,
        verdict=verdict,
        summary=summary,
        body=body,
        team_id=inv.team_id,
        evidence_refs=[outcome_id],
    )
    _log.info(
        "vr record_experience outcome=%s pattern=%s polarity=%s skipped=%s",
        outcome_id, result.pattern_id, result.polarity, result.skipped_reason,
    )


def _build_branch_manager(investigation_id: str) -> Any:
    """Return a :class:`BranchManager` bound to ``investigation_id``.

    Called by the platform aggregation spine to merge duplicate-signature
    branches and promote the strongest positive. Kept trivial so the
    guarded factory site in the emit chokepoint sees a plain
    :class:`RuntimeError` when the module surface is broken, not a
    hidden partial construction.
    """
    return BranchManager(investigation_id)


def _build_falsifier_agent() -> Any:
    """Construct a :class:`FalsifierAgent` bound to the platform LLM client.

    The falsifier drives one refutation attempt per finalize pass over
    the strongest positive outcome. Deferred imports keep the emit
    handler's construction cost bounded (the falsifier + AilaLLMClient +
    ConfigRegistry + SecretStore chain only lands when the aggregate
    step actually reaches for it). Reuses the same idempotent
    completion adapter shape as :mod:`aila.modules.vr.agents.explorer_planner`
    so a retried worker replays the cached refutation instead of paying
    the model API a second time.
    """
    from aila.platform.agents.falsifier import FalsifierAgent  # noqa: PLC0415
    from aila.platform.agents.idempotent_llm import (  # noqa: PLC0415
        idempotent_llm_call,
    )
    from aila.platform.llm.client import AilaLLMClient  # noqa: PLC0415
    from aila.storage.registry import ConfigRegistry  # noqa: PLC0415
    from aila.storage.secrets import SecretStore  # noqa: PLC0415

    _client = AilaLLMClient(
        registry=ConfigRegistry(), secret_store=SecretStore(),
    )

    async def _completion(
        *, prompt: str, system: str, **_kwargs: Any,
    ) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        response, _cache_hit = await idempotent_llm_call(
            _client,
            method="chat",
            task_type="falsifier",
            messages=messages,
            investigation_id=_kwargs.get("investigation_id", ""),
        )
        return str(response.content or "")

    return FalsifierAgent(_completion)


def _build_emit_handler() -> Any:
    from aila.modules.vr.workflow.task import (
        run_vr_auto_patch,
        run_vr_claim_verifier,
        run_vr_investigate,
        run_vr_synthesis,
    )

    bindings = InvestigationStateBindings(
        inv_model=VRInvestigationRecord,
        branch_model=VRInvestigationBranchRecord,
        message_model=VRInvestigationMessageRecord,
        outcome_model=VRInvestigationOutcomeRecord,
        task_fn=run_vr_investigate,
        synthesis_task_fn=run_vr_synthesis,
        verifier_task_fn=run_vr_claim_verifier,
        # RFC #149 auto-patch. Gated by ``platform.autopatch_enabled``
        # inside the emit-chokepoint trigger; default OFF so binding
        # the task here is a no-op on every existing deployment.
        patcher_task_fn=run_vr_auto_patch,
        track="vr",
        task_queue_factory=default_task_queue,
        get_int=_cfg.get_int,
        get_float=_cfg.get_float,
        outcome_dispatcher_cls=OutcomeDispatcher,
        pattern_extractor_cls=PatternExtractor,
        pattern_store_factory=lambda: PatternStore(
            knowledge=ServiceFactory().knowledge,
        ),
        approved_state=OUTCOME_STATE_APPROVED,
        evaluate_quorum=evaluate_quorum,
        post_draft_review_request=post_draft_review_request,
        finalize=finalize_investigation,
        branch_table="vr_investigation_branches",
        record_experience=_record_experience,
        # Aggregation spine wiring (issue .run/issues/19_aggregation_spine.md).
        # Threads a per-investigation :class:`BranchManager` and a
        # :class:`FalsifierAgent` into the platform aggregate finalizer
        # so merge/promote/refute actually run in production. Both are
        # constructed inside a guarded try in the emit chokepoint; a
        # factory raise degrades the aggregate step to skeleton-only.
        branch_pool_factory=_build_branch_manager,
        falsifier_factory=_build_falsifier_agent,
    )
    # VR has no post-completion proposers.
    return _build_emit_state(bindings, InvestigationStateHooks())


async def state_investigation_emit(
    input: dict[str, Any], services: Any,
) -> StateResult:
    """VR binding of the platform emit factory (lazy first-call build)."""
    global _HANDLER
    if _HANDLER is None:
        _HANDLER = _build_emit_handler()
    return await _HANDLER(input, services)
