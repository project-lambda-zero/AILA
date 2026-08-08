"""Template investigation task functions (RFC-02).

Real :func:`@platform_task`-decorated seeds a copier extends into the
module's live workflow. Two tasks land here:

* :func:`run_template_investigate` -- the ``VR_INVESTIGATE_HUB`` /
  ``VR_INVESTIGATE_HUB`` shape: seed body is a single ``...`` because
  ``@platform_task(definition=...)`` runs the workflow engine against
  the bound :class:`WorkflowDefinition` instead of executing the body.
* :func:`run_template_outcome_dispatch` -- the sibling job the
  researcher submits when quorum flips an outcome to APPROVED. Runs
  the module's outcome dispatcher against the outcome id.

Both task names are module-prefixed per Common Mistake #19: the
platform ARQ registry keys tasks by bare ``__name__`` so an unprefixed
``run_investigate`` would collide with a live module the moment this
scaffold is copied.

.. important:: This module is NOT registered in
   :mod:`aila.platform.modules.builtin` -- the ``_template`` scaffold
   stays out of live discovery. Import-time task registration is
   therefore inert: the tasks land in the ``_REGISTRY`` map (a
   harmless registration), but ARQ only picks them up when a copied
   module is added to the builtin list.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.modules._template.workflow.definitions import TEMPLATE_INVESTIGATE_V1
from aila.platform.services.factory import ServiceFactory
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = [
    "run_template_investigate",
    "run_template_outcome_dispatch",
]

_log = logging.getLogger(__name__)

# Bucket the transport-transient family for @platform_task retries.
# Matches the vr / malware shape: DB / socket / HTTP flakes retry once
# at the ARQ layer; Pydantic / permission / cancellation errors surface
# to the operator on first fault.
_TASK_TRANSIENT: tuple[type[BaseException], ...] = (
    OSError,
    TimeoutError,
    ConnectionError,
)


@platform_task(
    track="template",
    module_id="template",
    max_tries=1,
    timeout_s=7800.0,  # 2h -- covers a full investigation_loop run
    retriable_on=_TASK_TRANSIENT,
    definition=TEMPLATE_INVESTIGATE_V1,
)
async def run_template_investigate(
    ctx: TaskContext,
    **kwargs: Any,
) -> dict[str, Any]:
    """Seed for the ``TEMPLATE_INVESTIGATE_V1`` workflow definition.

    Body is a single ``...``: :func:`platform_task` dispatches the
    workflow engine against the bound ``definition`` above; this body
    only runs when the decorator is removed. Copiers keep the ``...``
    shape and extend :data:`TEMPLATE_INVESTIGATE_V1` instead.

    Required kwarg: ``investigation_id``. Setup resolves the primary
    branch from the DB; operators do not provide ``branch_id``.
    """
    del ctx, kwargs
    ...


@platform_task(
    track="template",
    module_id="template",
    max_tries=2,
    timeout_s=600.0,
    retriable_on=_TASK_TRANSIENT,
)
async def run_template_outcome_dispatch(
    ctx: TaskContext,
    outcome_id: str,
    **_: Any,
) -> dict[str, Any]:
    """Dispatch one approved outcome via :class:`OutcomeDispatcher`."""
    del ctx
    # Deferred import: outcome_dispatcher imports back into agents
    # through the finalize / synthesis chokepoints, and importing at
    # module scope forms a cycle with the task registry.
    from aila.modules._template.agents.outcome_dispatcher import (
        OutcomeDispatcher,
    )

    dispatcher = OutcomeDispatcher(knowledge=ServiceFactory().knowledge)
    result = await dispatcher.dispatch(outcome_id)
    return {
        "outcome_id": result.outcome_id,
        "outcome_kind": result.outcome_kind.value,
        "dispatch_status": result.dispatch_status.value,
        "dispatch_target": result.dispatch_target,
        "reason": result.reason,
    }
