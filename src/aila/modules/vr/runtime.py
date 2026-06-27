"""VR module runtime: validates action requests for capability matching.

VRRuntime is constructed by VRModule.build_runtime() and receives scoped tools
via ModuleContext. It validates the incoming payload as a VRProjectCreate so
the platform routing system can confirm capability match, but it does NOT run
the durable workflow inline.

VR n-day analysis is a long-running pipeline (setup -> research -> PoC ->
advisory -> emit) that can take hours. Holding an HTTP request open for that
duration is incorrect: the workflow is triggered exclusively through the task
queue from ``POST /vr/projects`` (see ``api_router.py``), which submits the
``run_vr_nday`` platform task. The task wrapper owns ``DurableStateMachine``
execution; this runtime only confirms the request is well-formed.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from aila.modules.vr.contracts import VRProjectCreate
from aila.platform.contracts.runtime import PlatformResponse
from aila.platform.modules import ModuleCapabilityProfile, ModuleRequest

__all__ = ["VRRuntime"]

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class VRRuntime:
    """Stateless dispatch object for VR module actions.

    Constructed once per platform instance by VRModule.build_runtime().
    """

    module_id: str
    action_id: str
    capability_profiles: list[ModuleCapabilityProfile]

    async def handle(self, request: ModuleRequest) -> PlatformResponse:
        """Validate the request payload and return a queued-style response.

        VR workflows execute via the task queue, not inline. This handler
        validates the payload so the platform router can match capabilities,
        then directs the caller to the project creation endpoint which is the
        sole trigger for the durable workflow.

        Raises ValueError with a clear message when the action_id does not
        belong to this module so the platform orchestrator surfaces a typed
        error instead of swallowing it.
        """
        if request.action_id != self.action_id:
            raise ValueError(
                f"VR module cannot handle action {request.action_id!r}. "
                f"Expected {self.action_id!r}."
            )

        payload = VRProjectCreate.model_validate(request.payload or {})
        _log.info(
            "vr.nday request validated run_id=%s name=%s -- workflow trigger via POST /vr/projects",
            request.run_id, payload.name,
        )

        return PlatformResponse(
            run_id=request.run_id,
            action_id=request.action_id,
            message=(
                f"VR n-day analysis for {payload.name!r} accepted. "
                "Use POST /vr/projects to create a project and trigger the workflow."
            ),
            module_payload=None,
            artifacts={},
        )
