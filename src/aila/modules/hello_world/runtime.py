"""Hello-world module runtime: handles a single action request.

HelloWorldRuntime is constructed by HelloWorldModule.build_runtime() and
receives scoped tools via ModuleContext. It validates the incoming payload
and delegates to HelloWorldWorkflow.
"""
from __future__ import annotations

from dataclasses import dataclass

from aila.platform.contracts.runtime import PlatformResponse
from aila.platform.modules import ModuleCapabilityProfile, ModuleRequest

from .contracts import HelloOptions, HelloPayload
from .workflow import HelloWorldWorkflow

__all__ = ["HelloWorldRuntime"]


@dataclass(slots=True)
class HelloWorldRuntime:
    """Runtime handler for hello_world module actions.

    Constructed once per request by HelloWorldModule.build_runtime().
    """

    module_id: str
    action_id: str
    capability_profiles: list[ModuleCapabilityProfile]

    async def handle(self, request: ModuleRequest) -> PlatformResponse:
        """Process a module action request.

        Args:
            request: Incoming request with run_id, payload dict, and options dict.

        Returns:
            A PlatformResponse with run_id, action_id, message, module_payload, artifacts.
        """
        payload = HelloPayload.model_validate(request.payload or {})
        options = HelloOptions.model_validate(request.options or {})
        return HelloWorldWorkflow().run(
            run_id=request.run_id,
            action_id=self.action_id,
            target_names=list(payload.target_names),
            force_refresh=options.force_refresh,
            module_id=self.module_id,
        )
