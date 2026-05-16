"""ARQ entrypoint for capability profile build (M3.T-4).

Wires IDABridgeTool + AuditMcpBridgeTool into CapabilityProfileBuilder
via @platform_task. Enqueued by:
  * api_router on POST /api/vr/targets/<id>/enrich
  * future M3.R-* investigation engine when an investigation references
    a target whose enrichment_status is unenriched/failed
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.enrichment.services import CapabilityProfileBuilder
from aila.modules.vr.tools.audit_mcp_bridge import AuditMcpBridgeTool
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_capability_profile_build"]


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=900.0,
)
async def run_capability_profile_build(
    ctx: TaskContext,
    target_id: str,
) -> dict[str, Any]:
    """Build capability_profile for one target and return its dict.

    The builder routes by target kind:
      source target → audit-mcp detect_languages + attack_surface + preanalysis
      binary target → IDA binary_survey + checksec + classify_behavior
                      + verify_capabilities + capa_scan
    Rule engine maps (target_kind, primary_language) onto D-51
    applicable_* lists.
    """
    builder = CapabilityProfileBuilder(
        ida=IDABridgeTool(),
        audit_mcp=AuditMcpBridgeTool(),
    )
    profile = await builder.build(target_id)
    return profile.model_dump(mode="json")
