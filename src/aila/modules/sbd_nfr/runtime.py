"""Runtime handler for the SbD NFR module.

The sbd_nfr module is API-driven via FastAPI routes (questionnaire sessions,
answers, scope evaluation, workbook generation).  The ModuleRuntime.handle()
path is not used for the primary SbD flow — it exists to satisfy the
ModuleProtocol contract and to support future CLI/agent dispatch if needed.
"""

from __future__ import annotations

from dataclasses import dataclass

from aila.platform.contracts._common import JsonObject
from aila.platform.contracts.runtime import PlatformResponse
from aila.platform.modules import ModuleCapabilityProfile, ModuleRequest

__all__ = ["SbdNfrRuntime"]


@dataclass(slots=True)
class SbdNfrRuntime:
    """Runtime handler for routed SbD NFR actions.

    Constructed once per platform instance by SbdNfrModule.build_runtime().
    """

    module_id: str
    action_id: str
    capability_profiles: list[ModuleCapabilityProfile]

    async def handle(self, request: ModuleRequest) -> PlatformResponse:
        """Return a placeholder response.

        The sbd_nfr module is operated via its REST API surface, not via
        ModuleRuntime.handle().  This method satisfies the protocol contract.
        """
        payload: JsonObject = {"module_id": self.module_id, "status": "use_api"}
        return PlatformResponse(
            run_id=request.run_id,
            action_id=self.action_id,
            message=(
                f"SbD NFR assessments are managed through the /sbd_nfr API. "
                f"Use POST /sbd_nfr/sessions to start a new assessment."
            ),
            module_payload=payload,
            artifacts={},
        )
