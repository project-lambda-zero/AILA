"""Template module runtime: handles a single action request.

TemplateRuntime is constructed by TemplateModule.build_runtime() and
receives scoped tools via ModuleContext. It validates the incoming payload
and delegates to TemplateWorkflow.
"""
from __future__ import annotations

from dataclasses import dataclass

from aila.platform.contracts.runtime import PlatformResponse
from aila.platform.modules import ModuleCapabilityProfile, ModuleRequest

from .contracts import TemplateOptions, TemplatePayload
from .workflow import TemplateWorkflow

__all__ = ["TemplateRuntime"]


@dataclass(slots=True)
class TemplateRuntime:
    """Runtime handler for template module actions.

    Constructed once per request by TemplateModule.build_runtime().
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
        payload = TemplatePayload.model_validate(request.payload or {})
        options = TemplateOptions.model_validate(request.options or {})
        return TemplateWorkflow().run(
            run_id=request.run_id,
            action_id=self.action_id,
            target_names=list(payload.target_names),
            force_refresh=options.force_refresh,
            module_id=self.module_id,
        )
