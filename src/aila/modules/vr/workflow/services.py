"""VRWorkflowServices -- wired service bag for VR workflow state handlers.

Built once per workflow run by ``definitions._build_services``. Each state
handler receives this as its ``services`` argument. Construction is done
inside ``build()`` so a fresh instance is returned per run (Phase 178 D-15
freshness contract); no caching across handlers.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from aila.config import Settings, get_settings
from aila.modules.vr.config_schema import VRConfigSchema
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.modules.vr.services.target_ingestion import TargetIngestionService
from aila.modules.vr.tools.advisory_builder import AdvisoryBuilderTool
from aila.modules.vr.tools.crash_triage import CrashTriageTool
from aila.modules.vr.tools.patch_differ import PatchDifferTool
from aila.modules.vr.tools.poc_runner import PoCRunnerTool
from aila.platform.config import build_platform_settings
from aila.platform.llm.client import AilaLLMClient
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
from aila.platform.services import SSHService
from aila.platform.services.factory import ServiceFactory
from aila.storage.registry import ConfigRegistry

__all__ = ["VRWorkflowServices"]

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class VRWorkflowServices:
    """Dependency bag for VR workflow state handlers.

    Fields:
        run_id: Unique identifier for this workflow execution.
        settings: Platform Settings.
        config: Operator-tunable VR module config (turn/tool-time budgets,
            PoC retry caps, SSH timeouts).
        ida_bridge: HTTP bridge to the IDA headless MCP server.
        poc_runner: SSH-driven PoC compile/run/verify orchestrator.
        crash_triage: ASAN parser + dedup-signature computer.
        advisory_builder: CVSS scorer, CWE mapper, advisory formatter.
        patch_differ: Wrapper over IDA bridge diff capabilities.
        llm_client: Platform LLM client for agent reasoning steps.
        ssh: Platform SSH service for file transfer + remote command
            execution against analyzer / PoC workstations.
        ingestion: VR target ingestion service -- uploads, git clones,
            HTTP downloads onto the analyzer machine via SSH.
    """

    run_id: str
    settings: Settings
    config: VRConfigSchema
    ida_bridge: IDABridgeTool
    poc_runner: PoCRunnerTool
    crash_triage: CrashTriageTool
    advisory_builder: AdvisoryBuilderTool
    patch_differ: PatchDifferTool
    llm_client: AilaLLMClient
    ssh: SSHService
    ingestion: TargetIngestionService

    @classmethod
    async def build(cls, run_id: str) -> VRWorkflowServices:
        """Construct a fresh services bundle for ``run_id``.

        No caching across calls (D-15): two sequential ``build`` returns
        are distinct objects so handler retries always see a clean
        service surface.

        The ``config`` field is populated from ConfigRegistry so that
        operator overrides (``PUT /config/vr/*``) take effect on the
        NEXT workflow run. Previously ``config = VRConfigSchema()``
        built the bag from schema defaults only, silently ignoring
        every DB-persisted override.
        """
        settings = get_settings()
        config = await _resolve_vr_config()
        ida = IDABridgeTool(recorder=record_call)
        ssh = SSHService(build_platform_settings(settings))
        return cls(
            run_id=run_id,
            settings=settings,
            config=config,
            ida_bridge=ida,
            poc_runner=PoCRunnerTool(settings),
            crash_triage=CrashTriageTool(),
            advisory_builder=AdvisoryBuilderTool(),
            patch_differ=PatchDifferTool(ida_bridge=ida),
            llm_client=ServiceFactory().llm_client,
            ssh=ssh,
            ingestion=TargetIngestionService(ssh=ssh),
        )


async def _resolve_vr_config() -> VRConfigSchema:
    """Build a VRConfigSchema whose fields carry operator overrides.

    Resolves every declared field via ConfigRegistry (env > cache > DB >
    schema default) and constructs the schema. Fields the registry
    cannot resolve (returns ``None``) fall back to the schema default
    by simply omitting them from the constructor kwargs, so pydantic
    fills them from ``Field(default=...)``.
    """
    registry = ConfigRegistry()
    resolved: dict[str, Any] = {}
    for name in VRConfigSchema.model_fields:
        value = await registry.get("vr", name)
        if value is not None:
            resolved[name] = value
    return VRConfigSchema(**resolved)
