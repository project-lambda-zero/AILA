"""Investigation setup state (M3.R-7).

Validates that the investigation + primary branch exist, marks status
as RUNNING, stamps started_at. Forwards investigation_id + branch_id to
the loop state.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from aila.modules.vr._task_queue import default_task_queue
from aila.modules.vr.agents.branch_manager import (
    _strip_directives_from_state,
    _strip_rejected_from_state,
)
from aila.modules.vr.contracts.branch import PersonaVoice
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.cve_intel_resolver import (
    extract_cve_ids,
    resolve_cve_intel,
)
from aila.modules.vr.services.pattern_store import PatternStore
from aila.platform.services.knowledge import KnowledgeService
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)
from aila.platform.workflows.investigation_setup_base import (
    state_investigation_setup as _build_setup_state,
)
from aila.platform.workflows.persona_spawn import spawn_persona_siblings


# Auto-deliberation toggle. When 1 (default), investigation_setup
# spawns sibling branches for critic + implementer personas and
# enqueues a separate run_vr_investigate task per sibling so each
# persona reasons independently against its own task_type-routed
# LLM. Set VR_AUTO_PERSONA_DELIBERATION=0 to disable (single-branch
# fallback -- operator forks personas manually).
#
# fix §295 -- lazy getter (was module-load `_AUTO_DELIBERATION`).
# Reading env at module load makes the toggle unchangeable for the
# worker lifetime; operator-flipped env after a worker restart never
# took effect until full process bounce. Lazy getter is read each
# time setup runs, so a worker that sees a fresh env on next ARQ
# task wakeup honours it.
def _is_auto_deliberation_enabled() -> bool:
    return os.environ.get("VR_AUTO_PERSONA_DELIBERATION", "1") == "1"

# The personas assigned to the auto-spawned siblings. Primary branch
# becomes the first researcher; each entry below spawns a sibling.
#
# Full 6-persona panel (2 researchers + 2 critics + 2 implementers):
#   halvar (primary) + noor  = researchers -- propose hypotheses
#   maddie + yuki            = critics -- falsify, demand evidence
#   renzo + wei              = implementers -- build PoCs, settle disputes
_DELIBERATION_SIBLINGS: tuple[PersonaVoice, ...] = (
    PersonaVoice.NOOR,    # researcher (alternative style to halvar)
    PersonaVoice.MADDIE,  # critic (aggressive falsifier)
    PersonaVoice.YUKI,    # critic (methodical falsifier)
    PersonaVoice.RENZO,   # implementer (PoC builder)
    PersonaVoice.WEI,     # implementer (cost-efficient prioritizer)
)
_PRIMARY_PERSONA: PersonaVoice = PersonaVoice.HALVAR  # researcher

__all__ = ["state_investigation_setup"]

_log = logging.getLogger(__name__)


# fix §293 -- module-level consecutive failure counters for the two
# best-effort lookups (CVE intel, knowledge-transfer pattern store)
# that surround the main UoW. The prior bare `except Exception` +
# `_log.warning(...)` swallowed silent infrastructure rot: a broken
# NVD mirror, a missing IntelService dependency, or a corrupted
# pattern_store could fail every investigation for hours while only
# producing WARN noise. After 5 consecutive failures on either path,
# escalate to _log.error so log destinations (Grafana / Loki) can
# page on it. Reset to 0 on each success. Module-level state is
# correct here -- counters are per-worker-process and reset on
# restart, which is the right granularity (an operator that
# restarts a worker has actively re-checked the integration).
_CONSECUTIVE_CVE_INTEL_FAILURES: int = 0
_FAILURE_ESCALATION_THRESHOLD: int = 5


async def _resolve_cve_intel(question: str) -> list[dict[str, Any]]:
    """Resolve CVE ids in *question* to intel dicts (VR setup-factory hook).

    Extracts CVE ids, resolves each via the NVD-backed resolver, and
    returns the dict list. Never raises: a failure returns the empty
    degraded default and escalates to error-level logging after
    ``_FAILURE_ESCALATION_THRESHOLD`` consecutive failures.
    """
    global _CONSECUTIVE_CVE_INTEL_FAILURES
    cve_ids = extract_cve_ids(question)
    if not cve_ids:
        return []
    try:
        resolutions = await resolve_cve_intel(cve_ids)
        _CONSECUTIVE_CVE_INTEL_FAILURES = 0  # fix §293 -- reset on success
        return [r.to_dict() for r in resolutions]
    except (ImportError, OSError, RuntimeError, ValueError, TypeError) as exc:
        _CONSECUTIVE_CVE_INTEL_FAILURES += 1
        if _CONSECUTIVE_CVE_INTEL_FAILURES >= _FAILURE_ESCALATION_THRESHOLD:
            _log.error(
                "investigation_setup: CVE intel resolve failed %d times in a "
                "row (last err: %s) -- escalating; check NVD mirror + "
                "cve_intel_resolver IntelService dependency",
                _CONSECUTIVE_CVE_INTEL_FAILURES, exc, exc_info=True,
            )
        else:
            _log.warning(
                "investigation_setup: CVE intel resolve failed "
                "(consecutive=%d): %s",
                _CONSECUTIVE_CVE_INTEL_FAILURES, exc, exc_info=True,
            )
        return []


async def _spawn_persona_siblings_and_enqueue(
    *,
    investigation_id: str,
    primary_branch_id: str,
    team_id: str | None,
) -> None:
    """Bind the shared platform persona spawn to VR models and helpers.

    The two-phase atomic spawn body lives in
    :func:`aila.platform.workflows.persona_spawn.spawn_persona_siblings`;
    VR supplies its branch model, table names, persona tuple, task
    function, ARQ track and group, and the case_state strip composition.
    """
    from aila.modules.vr.workflow.task import run_vr_investigate

    await spawn_persona_siblings(
        investigation_id,
        primary_branch_id,
        team_id,
        siblings=_DELIBERATION_SIBLINGS,
        branch_model=VRInvestigationBranchRecord,
        inv_table="vr_investigations",
        message_table="vr_investigation_messages",
        task_fn=run_vr_investigate,
        track="vr",
        group_id="vr_auto_deliberation",
        task_queue=default_task_queue(),
        strip_case_state=lambda raw: _strip_rejected_from_state(
            _strip_directives_from_state(raw),
        ),
    )


_SETUP_BINDINGS = InvestigationStateBindings(
    inv_model=VRInvestigationRecord,
    branch_model=VRInvestigationBranchRecord,
    target_model=VRTargetRecord,
    primary_persona_value=_PRIMARY_PERSONA.value,
    unspecified_persona_value=PersonaVoice.UNSPECIFIED.value,
    spawn_fn=_spawn_persona_siblings_and_enqueue,
    pattern_store_factory=lambda: PatternStore(knowledge=KnowledgeService()),
    auto_deliberation_enabled=_is_auto_deliberation_enabled,
)
_SETUP_HOOKS = InvestigationStateHooks(resolve_cve_intel=_resolve_cve_intel)

# The setup handler is the platform factory bound to VR's models + hook.
state_investigation_setup = _build_setup_state(_SETUP_BINDINGS, _SETUP_HOOKS)
