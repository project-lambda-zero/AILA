"""Forensics module runtime: handles action requests.

ForensicsRuntime is constructed by ForensicsModule.build_runtime() and
receives scoped tools via ModuleContext. It validates the incoming payload
and delegates to the platform's ``DurableStateMachine`` via task.py
functions, or directly through ``FORENSICS_DISPATCHER_V1`` which uses the
platform two-phase dispatch pattern (``is_dispatcher=True``).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from aila.modules.forensics.contracts import ForensicsOptions, ForensicsPayload
from aila.platform.contracts.runtime import PlatformResponse
from aila.platform.modules import ModuleCapabilityProfile, ModuleRequest

if TYPE_CHECKING:
    from aila.platform.tools.ssh import SSHCommandTool


__all__ = ["ForensicsRuntime"]

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class ForensicsRuntime:
    """Stateless dispatch object for forensics module actions.

    Constructed once per platform instance by ForensicsModule.build_runtime().
    """

    module_id: str
    analyze_action_id: str
    investigate_action_id: str
    capability_profiles: list[ModuleCapabilityProfile]
    ssh_tool: SSHCommandTool | None = field(default=None)
    workflow_model: Any = field(default=None)
    readiness_service: Any = field(default=None)

    async def handle(self, request: ModuleRequest) -> PlatformResponse:
        """Dispatch a forensics action request via DurableStateMachine.

        Uses the platform's durable workflow engine for execution, giving us
        cursor persistence, audit logging, retries, and resumability.
        """
        payload = ForensicsPayload.model_validate(request.payload or {})
        options = ForensicsOptions.model_validate(request.options or {})

        if request.action_id == self.analyze_action_id:
            return await self._run_analysis(request, payload, options)
        if request.action_id == self.investigate_action_id:
            return await self._run_investigation(request, payload, options)

        raise ValueError(
            f"Forensics module cannot handle action {request.action_id!r}. "
            f"Expected one of: {self.analyze_action_id!r}, {self.investigate_action_id!r}."
        )

    async def _run_analysis(
        self,
        request: ModuleRequest,
        payload: ForensicsPayload,
        _options: ForensicsOptions,
    ) -> PlatformResponse:
        """Execute the full evidence analysis workflow via DurableStateMachine."""
        from aila.modules.forensics.workflow.task import run_forensics_analysis

        synthetic_ctx: dict[str, Any] = {
            "job_id": request.run_id,
            "job_try": 1,
        }

        project_id = payload.project_id
        integration = self._resolve_integration(request)

        result = await run_forensics_analysis(
            synthetic_ctx,
            project_id=project_id,
            evidence_directory=self._resolve_evidence_directory(request),
            integration=integration,
            analyzer_os=self._resolve_analyzer_os(request),
            run_id=request.run_id,
        )
        return PlatformResponse(
            run_id=request.run_id,
            action_id=request.action_id,
            message=f"Forensics analysis completed for project {project_id}.",
            module_payload=result,
            artifacts={},
        )

    async def _run_investigation(
        self,
        request: ModuleRequest,
        payload: ForensicsPayload,
        options: ForensicsOptions,
    ) -> PlatformResponse:
        """Execute a bounded free-flow investigation via DurableStateMachine."""
        from aila.modules.forensics.workflow.task import run_forensics_investigation

        synthetic_ctx: dict[str, Any] = {
            "job_id": request.run_id,
            "job_try": 1,
        }

        integration = self._resolve_integration(request)
        module_payload = request.payload or {}
        investigation_id = module_payload.get("investigation_id", "")

        result = await run_forensics_investigation(
            synthetic_ctx,
            investigation_id=investigation_id,
            project_id=payload.project_id,
            question=payload.question,
            max_attempts=options.max_attempts,
            integration=integration,
            analyzer_os=self._resolve_analyzer_os(request),
            run_id=request.run_id,
        )
        return PlatformResponse(
            run_id=request.run_id,
            action_id=request.action_id,
            message=f"Investigation completed: {payload.question[:80]}",
            module_payload=result,
            artifacts={},
        )

    def _resolve_integration(self, request: ModuleRequest) -> dict[str, Any]:
        """Extract SSH integration fields from the request payload."""
        mp = request.payload or {}
        return mp.get("integration", {})

    def _resolve_evidence_directory(self, request: ModuleRequest) -> str:
        mp = request.payload or {}
        return mp.get("evidence_directory", "/evidence")

    def _resolve_analyzer_os(self, request: ModuleRequest) -> str:
        mp = request.payload or {}
        return mp.get("analyzer_os", "linux")
