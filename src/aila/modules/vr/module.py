"""VR (vulnerability research) module entrypoint.

Implements ModuleProtocol. This file is the only file the platform imports
directly — all wiring (capability profiles, tool registration, runtime
construction, route declarations, seed data, and health checks) happens here.

Auto-discovered by the platform via ``pkgutil.iter_modules`` on
``aila.modules``; ``MODULE_ID`` is derived from the folder name so renaming
the package automatically renames the module everywhere.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aila.storage.registry import ConfigRegistry, SchemaRegistry

from aila.config import Settings
from aila.platform.contracts._common import JsonObject
from aila.platform.modules import (
    ModuleCapabilityProfile,
    ModuleContext,
    ModuleProtocol,
    ModuleRouteSpec,
    ModuleRuntime,
    action_id_for,
)
from aila.platform.runtime import ToolRegistry

from .capabilities import CAPABILITY_DESCRIPTION, CAPABILITY_EXAMPLES
from .runtime import VRRuntime
from .tool_keys import (
    ALL_TOOL_KEYS,
    TOOL_ADVISORY_BUILDER,
    TOOL_CRASH_TRIAGE,
    TOOL_IDA_BRIDGE,
    TOOL_PATCH_DIFFER,
    TOOL_POC_RUNNER,
)

__all__ = ["VRModule", "create_module"]

_log = logging.getLogger(__name__)

MODULE_ID = Path(__file__).parent.name
NDAY_ACTION_ID = action_id_for(MODULE_ID, "write_nday_poc")
SEED_VERSION = "1.0"


class VRModule(ModuleProtocol):
    """ModuleProtocol implementation for offensive vulnerability research.

    Owns N-day PoC development against compiled binaries: tool registration
    for the IDA Pro bridge and PoC sandbox, durable workflow construction,
    and disclosure-status tracking on findings.
    """

    module_id = MODULE_ID
    nday_action_id = NDAY_ACTION_ID

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        """Return capability profiles advertising this module to the routing agent."""
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.nday_action_id,
                description=CAPABILITY_DESCRIPTION,
                tools=list(ALL_TOOL_KEYS),
                examples=list(CAPABILITY_EXAMPLES),
            ),
        ]

    def required_tools(self) -> list[str]:
        """Return tool keys this module needs in its runtime tool scope."""
        return [
            TOOL_IDA_BRIDGE,
            TOOL_POC_RUNNER,
            TOOL_PATCH_DIFFER,
            TOOL_CRASH_TRIAGE,
            TOOL_ADVISORY_BUILDER,
        ]

    def report_filter_keys(self) -> list[str]:
        """No filterable reports yet."""
        return []

    async def register_tools(
        self,
        tool_registry: ToolRegistry,
        settings: Settings,
        registry: ConfigRegistry | None = None,
        schema_registry: SchemaRegistry | None = None,
    ) -> None:
        """Register VR tables, config schema, and tool instances.

        Tool construction is dependency-ordered: PatchDifferTool composes the
        already-built IDABridgeTool so we instantiate the bridge first and
        thread the same instance into the differ.
        """
        if schema_registry is not None:
            from aila.modules.vr.db_models import VRFindingRecord, VRProjectRecord
            schema_registry.push(VRProjectRecord, VRFindingRecord)

        if registry is not None:
            from aila.modules.vr.config_schema import VRConfigSchema
            await registry.register(self.module_id, VRConfigSchema)

        from aila.modules.vr.tools.advisory_builder import AdvisoryBuilderTool
        from aila.modules.vr.tools.crash_triage import CrashTriageTool
        from aila.modules.vr.tools.ida_bridge import IDABridgeTool
        from aila.modules.vr.tools.patch_differ import PatchDifferTool
        from aila.modules.vr.tools.poc_runner import PoCRunnerTool

        ida_bridge = IDABridgeTool()
        tool_registry.register(TOOL_IDA_BRIDGE, ida_bridge)
        tool_registry.register(TOOL_POC_RUNNER, PoCRunnerTool(settings))
        tool_registry.register(TOOL_PATCH_DIFFER, PatchDifferTool(ida_bridge))
        tool_registry.register(TOOL_CRASH_TRIAGE, CrashTriageTool())
        tool_registry.register(TOOL_ADVISORY_BUILDER, AdvisoryBuilderTool())

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        """Construct and return the VRRuntime."""
        del context
        return VRRuntime(
            module_id=self.module_id,
            action_id=self.nday_action_id,
            capability_profiles=self.capability_profiles(),
        )

    def filter_report_rows(
        self,
        rows: list[JsonObject],
        filters: JsonObject | None = None,
    ) -> list[JsonObject]:
        """No filterable reports — return rows unchanged."""
        del filters
        return list(rows)

    def route_specs(self) -> list[ModuleRouteSpec]:
        """Declare the VR module's HTTP route surface.

        Per MODULE_STANDARD: the api_router import is DEFERRED to avoid
        importing FastAPI at module-collection time. The platform calls
        router_factory() once at startup and mounts the returned router
        under the declared prefix.
        """
        from .api_router import create_vr_router

        return [
            ModuleRouteSpec(
                prefix="/vr",
                router_factory=create_vr_router,
                tool_keys=tuple(ALL_TOOL_KEYS),
                config_namespace=self.module_id,
            ),
        ]

    async def seed_data(self, session: Any) -> None:
        """Stamp the seed version row idempotently.

        VR has no master data to seed yet (CVSS/CWE templates ship as static
        JSON files alongside the AdvisoryBuilderTool). This still has to
        write the version row so future re-seed checks work.
        """
        from sqlmodel import select

        from aila.platform.contracts._common import utc_now
        from aila.storage.db_models import SeedVersionRecord

        existing = (await session.exec(
            select(SeedVersionRecord).where(SeedVersionRecord.module_id == self.module_id)
        )).first()
        if existing is not None and existing.seed_version == SEED_VERSION:
            return

        if existing is None:
            session.add(SeedVersionRecord(module_id=self.module_id, seed_version=SEED_VERSION))
        else:
            existing.seed_version = SEED_VERSION
            existing.seeded_at = utc_now()
            session.add(existing)
        await session.commit()

    async def system_summary(self, system_id: int, session: Any) -> dict[str, Any]:
        """VR is not system-scoped today."""
        del system_id, session
        return {}

    async def report_count(self, run_id: str, session: Any) -> dict[str, Any]:
        """VR does not own platform workflow run reports."""
        del run_id, session
        return {}

    def health_checks(self) -> dict[str, object]:
        """Probe the IDA headless MCP that every n-day workflow depends on."""

        async def _ida_reachability() -> dict[str, object]:
            import os

            import httpx

            base_url = os.environ.get("IDA_HEADLESS_URL", "http://127.0.0.1:18821").rstrip("/")
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    response = await client.get(f"{base_url}/health")
                if response.status_code < 500:
                    return {"status": "up", "detail": f"IDA MCP reachable at {base_url}"}
                return {
                    "status": "degraded",
                    "detail": f"IDA MCP at {base_url} returned HTTP {response.status_code}",
                }
            except (httpx.HTTPError, OSError) as exc:
                return {
                    "status": "degraded",
                    "detail": f"IDA MCP unreachable at {base_url}: {type(exc).__name__}: {exc}",
                }

        return {"vr.ida_reachability": _ida_reachability}


_SWEEPS_REGISTERED = False


def _register_vr_periodic_sweeps() -> None:
    """Register VR's per-tick maintenance sweeps with the platform reaper.

    Called from :func:`create_module` so the registration is a side-effect
    of module instantiation — the same lifecycle hook the platform uses
    for capability profiles + tool keys + route specs. This is the
    operator-visible chokepoint where "VR module owns these sweeps" is
    declared; the platform iterates the registry without knowing VR
    exists.

    Idempotent via the module-level ``_SWEEPS_REGISTERED`` flag — safe
    against repeated ``create_module()`` calls (test fixtures, hot-reload).
    """
    global _SWEEPS_REGISTERED  # noqa: PLW0603 — module-init flag
    if _SWEEPS_REGISTERED:
        return
    _SWEEPS_REGISTERED = True

    from aila.platform.tasks.sweeps import (  # noqa: PLC0415
        register_periodic_sweep,
    )

    # vr.stage_tracker — reaps stuck target-analysis stages whose
    # workers never recorded a terminal transition. Returns an int
    # count of stages reaped.
    from .services.stage_tracker import reap_stuck_stages  # noqa: PLC0415
    register_periodic_sweep("vr.stage_tracker", reap_stuck_stages)

    # vr.investigation_reaper — completes investigations past their
    # turn / message / wall-clock caps when no worker reaches the
    # turn-boundary check.
    from .services.investigation_reaper import (  # noqa: PLC0415
        sweep_cap_exceeded_investigations,
    )
    register_periodic_sweep(
        "vr.investigation_reaper",
        sweep_cap_exceeded_investigations,
    )

    # vr.branch_reaper — flips orphan ACTIVE branches whose parent
    # investigation has reached a terminal status.
    from .services.branch_reaper import (  # noqa: PLC0415
        sweep_orphan_active_branches,
    )
    register_periodic_sweep("vr.branch_reaper", sweep_orphan_active_branches)

    # vr.masvs_parent_reconciler — drives the parent batch state
    # machine (CREATED → RUNNING → COMPLETED) for MASVS audits.
    from .masvs.parent_reconciler import (  # noqa: PLC0415
        sweep_masvs_audit_parents,
    )
    register_periodic_sweep(
        "vr.masvs_parent_reconciler",
        sweep_masvs_audit_parents,
    )


# Module-load-time registration. Imports are deferred inside the
# function so a `from aila.modules.vr.module import VRModule` for
# the protocol type doesn't fire the registration; only the platform's
# `create_module()` call triggers it.


def create_module() -> ModuleProtocol:
    """Return a new VRModule instance for the platform module loader."""
    _register_vr_periodic_sweeps()
    return VRModule()
