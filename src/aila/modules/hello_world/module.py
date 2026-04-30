"""Hello-world module entrypoint.

Implements ModuleProtocol. This file is the only file the platform imports
directly -- all wiring happens here. This module proves the module contract
works for any new module scaffolded from _template.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

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

from .capabilities import MODULE_DESCRIPTION, MODULE_EXAMPLES, MODULE_TOOLS
from .runtime import HelloWorldRuntime
from .tool_keys import HELLO_WORLD_GREET_TOOL
from .tools import HelloGreetTool

MODULE_ID = Path(__file__).parent.name
MODULE_ACTION_ID = action_id_for(MODULE_ID, "run")
SEED_VERSION = "1"


class HelloWorldModule(ModuleProtocol):
    """Hello-world module implementing ModuleProtocol.

    Minimal but complete module proving the platform contract works for any
    new module. Routes, tools, config all register without platform edits.
    """

    module_id = MODULE_ID
    action_id = MODULE_ACTION_ID

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        """Return capability profiles advertising this module to the routing agent.

        Returns:
            A list of ModuleCapabilityProfile with description and examples for
            LLM routing decisions.
        """
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.action_id,
                description=MODULE_DESCRIPTION,
                tools=list(MODULE_TOOLS),
                examples=list(MODULE_EXAMPLES),
            )
        ]

    def route_specs(self) -> list[ModuleRouteSpec]:
        """Declare HTTP routes this module contributes to the platform API.

        Returns:
            A list with one ModuleRouteSpec mounting the hello_world router
            at /hello_world.
        """
        from .api_router import create_hello_world_router

        return [
            ModuleRouteSpec(
                prefix="/hello_world",
                router_factory=create_hello_world_router,
                tool_keys=(HELLO_WORLD_GREET_TOOL,),
                config_namespace=None,
            ),
        ]

    def required_tools(self) -> list[str]:
        """Return tool keys this module requires from the ToolRegistry.

        Returns:
            List of tool key strings.
        """
        return [HELLO_WORLD_GREET_TOOL]

    def report_filter_keys(self) -> list[str]:
        """Return field keys valid in filter_report_rows().

        Returns:
            Empty list -- hello_world has no filterable reports.
        """
        return []

    async def register_tools(self, tool_registry: ToolRegistry, settings: Settings, registry=None, schema_registry=None) -> None:
        """Register module tools into the platform ToolRegistry.

        Args:
            tool_registry: Platform-provided registry.
            settings: Infrastructure settings passed to tool constructors.
            registry: Optional ConfigRegistry (unused).
            schema_registry: Optional SchemaRegistry (unused).
        """
        del registry, schema_registry
        tool_registry.register(HELLO_WORLD_GREET_TOOL, HelloGreetTool(settings))

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        """Construct the runtime handler for this module.

        Args:
            context: Build-time dependencies.

        Returns:
            A HelloWorldRuntime whose handle() method processes requests.
        """
        del context
        return HelloWorldRuntime(
            module_id=self.module_id,
            action_id=self.action_id,
            capability_profiles=self.capability_profiles(),
        )

    def filter_report_rows(
        self,
        rows: list[JsonObject],
        filters: JsonObject | None = None,
    ) -> list[JsonObject]:
        """Filter report rows. Hello_world has no reports, returns rows unchanged.

        Args:
            rows: List of report row dicts.
            filters: Filter dict (ignored).

        Returns:
            All rows unchanged.
        """
        del filters
        return list(rows)

    async def seed_data(self, session: "Any") -> None:
        """Seed initial data for this module. Called once after create_all().

        Idempotent: checks SeedVersionRecord before inserting. Hello_world
        has no seed data, so this just stamps the version.

        Args:
            session: Active AsyncSession.
        """
        from sqlmodel import select

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
            from aila.platform.contracts._common import utc_now
            existing.seeded_at = utc_now()
            session.add(existing)
        await session.commit()

    async def system_summary(self, system_id: int, session: "Any") -> dict[str, Any]:
        """Return module-contributed dashboard data for a system.

        Args:
            system_id: Primary key of the system.
            session: Active SQLModel session.

        Returns:
            Empty dict -- hello_world has no system data.
        """
        del system_id, session
        return {}

    async def report_count(self, run_id: str, session: "Any") -> dict[str, Any]:
        """Return semantic count breakdown for a report.

        Args:
            run_id: WorkflowRunRecord primary key.
            session: Active SQLModel session.

        Returns:
            Empty dict -- hello_world has no reports.
        """
        del run_id, session
        return {}

    def health_checks(self) -> dict[str, object]:
        """Return module-specific health check callables.

        Returns:
            Empty dict -- hello_world has no health checks.
        """
        return {}


def create_module() -> ModuleProtocol:
    """Instantiate and return the hello_world module.

    Returns:
        A HelloWorldModule implementing ModuleProtocol.
    """
    return HelloWorldModule()
