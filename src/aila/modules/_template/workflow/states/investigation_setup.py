"""Investigation setup state scaffold (RFC-02 Phase 4a).

Copy-me scaffold demonstrating the canonical binding shape for a new
module's ``investigation_setup`` state. The setup body -- stale-branch
self-heal, orphan-abandon, status-flip whitelist, knowledge-transfer
pattern lookup, primary-branch resolution -- lives on the platform in
:mod:`aila.platform.workflows.investigation_setup_base`. This module
supplies its concrete record models, primary persona, sibling-spawn
function, pattern-store factory, and auto-deliberation toggle; the
platform never names a module.

Sibling persona spawn goes through
:func:`aila.platform.workflows.persona_spawn.spawn_persona_siblings`
(RFC-02 Phase 3) with the module's branch model, table names, task
function, ARQ track, task queue, and case-state strip composition
threaded in as bindings.

Rename ``Template`` / ``template`` throughout, replace the placeholder
strip helpers with the module's real case-state strippers, and add any
per-module hook (CVE intel resolver, knowledge retrieval, etc.) via
:class:`InvestigationStateHooks`.
"""
from __future__ import annotations

import logging
import os
from typing import Any

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationRecord,
    TemplateTargetRecord,
)
from aila.platform.contracts.enums import PersonaVoice
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)
from aila.platform.workflows.investigation_setup_base import (
    state_investigation_setup as _build_setup_state,
)
from aila.platform.workflows.persona_spawn import spawn_persona_siblings

__all__ = ["state_investigation_setup"]

_log = logging.getLogger(__name__)

# ARQ track (== queue name) and cross-module group id for the sibling
# spawn fan-out. Rename in one place; every submit below picks it up.
_TEMPLATE_TRACK = "template"
_TEMPLATE_GROUP_ID = "template_auto_deliberation"

# Auto-deliberation toggle. When ``1`` (default) the setup state spawns
# one sibling branch per persona in ``_DELIBERATION_SIBLINGS`` and
# enqueues one worker task per sibling so each persona reasons against
# its own task_type-routed LLM. Read lazily (not at module load) so an
# operator env flip takes effect on the next task wakeup without a
# worker restart.
def _is_auto_deliberation_enabled() -> bool:
    return os.environ.get("TEMPLATE_AUTO_PERSONA_DELIBERATION", "1") == "1"


# The primary persona owns the first branch of every investigation.
# Every subsequent persona in ``_DELIBERATION_SIBLINGS`` gets its own
# branch spawned in phase 1 of ``spawn_persona_siblings`` and a matching
# ``run_template_investigate`` task submitted in phase 2.
_PRIMARY_PERSONA: PersonaVoice = PersonaVoice.HALVAR
_DELIBERATION_SIBLINGS: tuple[PersonaVoice, ...] = (
    PersonaVoice.MADDIE,
    PersonaVoice.RENZO,
)


def _strip_case_state(raw: str) -> str:
    """Case-state strip composition applied to reactivated / forked branches.

    Real modules compose their reject-strip and directive-strip helpers
    here so a reactivated persona starts from a clean baseline. The
    scaffold returns the raw string unchanged; replace with the module's
    real strip composition when copying.
    """
    return raw


async def _spawn_persona_siblings_and_enqueue(
    investigation_id: str,
    primary_branch_id: str,
    team_id: str | None,
    sizing_hint: Any = None,
) -> None:
    """Bind the shared platform persona spawn to the template's models.

    The two-phase atomic spawn body lives in
    :func:`aila.platform.workflows.persona_spawn.spawn_persona_siblings`;
    this closure supplies the module's branch model, table names, persona
    tuple, task function, ARQ track and group, task queue, and the
    case-state strip composition. ``sizing_hint`` is forwarded verbatim
    so a routing-history-driven panel cap takes effect when the caller
    supplies one.
    """
    # Deferred import: a real module wires the queue through its own
    # ``_task_queue.py`` helper so the queue picks up the module's
    # config-driven Redis binding + team-id inheritance. The scaffold
    # constructs the queue lazily so the file compiles without the
    # ``_task_queue.py`` helper that a fresh copy has not written yet.
    # ``run_template_investigate`` is imported here too because
    # ``workflow.task`` imports ``workflow.definitions``, which
    # imports every state file (including THIS one). A module-scope
    # import here would form the classic setup <-> task cycle -- vr
    # uses the same deferred-import shape.
    from aila.modules._template.workflow.task import run_template_investigate
    from aila.platform.tasks.queue import TaskQueue
    from aila.storage.registry import ConfigRegistry

    task_queue = TaskQueue(
        config_registry=ConfigRegistry(),
        module_id="template",
    )
    await spawn_persona_siblings(
        investigation_id,
        primary_branch_id,
        team_id,
        siblings=_DELIBERATION_SIBLINGS,
        branch_model=TemplateInvestigationBranchRecord,
        inv_table="template_investigations",
        message_table="template_investigation_messages",
        task_fn=run_template_investigate,
        track=_TEMPLATE_TRACK,
        group_id=_TEMPLATE_GROUP_ID,
        task_queue=task_queue,
        strip_case_state=_strip_case_state,
        sizing_hint=sizing_hint,
    )


_SETUP_BINDINGS = InvestigationStateBindings(
    inv_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    target_model=TemplateTargetRecord,
    primary_persona_value=_PRIMARY_PERSONA.value,
    unspecified_persona_value=PersonaVoice.UNSPECIFIED.value,
    spawn_fn=_spawn_persona_siblings_and_enqueue,
    auto_deliberation_enabled=_is_auto_deliberation_enabled,
    module_id="template",
)
# A real module adds its per-module hooks here (CVE intel resolver,
# retrieved-knowledge resolver, etc.). Every hook is optional; unset
# leaves the platform default in place.
_SETUP_HOOKS = InvestigationStateHooks()

# The setup handler IS the platform factory bound to the template's
# models + hooks. No local body: the factory owns the entire setup
# behavior and rule 41 in ``aila.tools.honesty_audit`` locks this file
# out of drifting a copy back in.
state_investigation_setup = _build_setup_state(_SETUP_BINDINGS, _SETUP_HOOKS)
