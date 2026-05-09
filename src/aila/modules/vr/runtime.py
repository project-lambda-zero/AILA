"""VR module runtime: handles action requests.

VRRuntime is constructed by VRModule.build_runtime() and receives scoped tools
via ModuleContext. It validates the incoming payload as a VRProjectCreate and
dispatches to the durable VR_NDAY_V1 workflow via the platform's workflow
engine, returning a PlatformResponse.

Per D-05 / Phase 178: invocations of ``DurableStateMachine.execute`` run the
workflow inline and persist all cursor state in Postgres so an interrupted
run can be resumed. The runtime never opens a new Session; the caller's
``request.session`` is the bound transaction.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from aila.modules.vr.contracts import VRProjectCreate
from aila.modules.vr.workflow.definitions import VR_NDAY_V1
from aila.platform.contracts.runtime import PlatformResponse
from aila.platform.modules import ModuleCapabilityProfile, ModuleRequest
from aila.platform.workflows.engine import DurableStateMachine

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
        """Validate the request payload and run VR_NDAY_V1 to completion.

        Raises ValueError with a clear message when the action_id does not
        belong to this module so the platform orchestrator surfaces a typed
        error to the caller instead of swallowing it.
        """
        if request.action_id != self.action_id:
            raise ValueError(
                f"VR module cannot handle action {request.action_id!r}. "
                f"Expected {self.action_id!r}."
            )

        payload = VRProjectCreate.model_validate(request.payload or {})

        # initial_input MUST be JSON-serializable — DurableStateMachine.execute
        # validates this and crashes on Pydantic models. ``mode='json'`` produces
        # primitive enum values and ISO timestamps the engine can persist.
        initial_input = {
            "project_id": str(request.payload.get("project_id", "")) if request.payload else "",
            "name": payload.name,
            "cve_id": payload.cve_id,
            "target_path": payload.target.path,
            "target_class": payload.target.target_class.value,
            "binary_id": payload.target.binary_id,
            "patched_path": payload.patched_target.path if payload.patched_target else None,
            "patched_binary_id": (
                payload.patched_target.binary_id if payload.patched_target else None
            ),
            "source_available": payload.target.source_available,
            "context_notes": payload.context_notes,
        }

        result = await DurableStateMachine.execute(
            request.run_id,
            VR_NDAY_V1,
            initial_input=initial_input,
        )
        _log.info(
            "vr.nday workflow completed run_id=%s name=%s terminal_keys=%s",
            request.run_id, payload.name, sorted(result.keys()),
        )

        return PlatformResponse(
            run_id=request.run_id,
            action_id=request.action_id,
            message=f"VR n-day workflow completed for {payload.name!r}.",
            module_payload=None,
            artifacts={},
        )
