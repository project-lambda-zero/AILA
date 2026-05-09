"""Template module entrypoint.

Implements ModuleProtocol. This file is the only file the platform imports
directly — all wiring happens here.
"""
from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sqlmodel import Session

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
from .runtime import TemplateRuntime
from .tool_keys import TEMPLATE_SAMPLE_TOOL
from .tools import TemplateSampleTool

MODULE_ID = Path(__file__).parent.name
MODULE_ACTION_ID = action_id_for(MODULE_ID, "run")
MODULE_REPORT_FILTER_KEYS = ["replace_with_real_filter_key"]
SEED_VERSION = "1.0"


class TemplateModule(ModuleProtocol):
    """Template module implementing ModuleProtocol.

    Copy this class and rename to match your module_id. Replace all
    TEMPLATE/replace_with_* placeholders with real values.
    """

    module_id = MODULE_ID
    action_id = MODULE_ACTION_ID

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        """Return capability profiles advertising this module to the routing agent.

        Returns:
            A list of ModuleCapabilityProfile with description and examples for
            LLM routing decisions.

        Raises:
            ValueError: If MODULE_DESCRIPTION or MODULE_TOOLS are still placeholders.
        """
        if not MODULE_DESCRIPTION.strip():
            raise ValueError("Template modules must set a real capability description.")
        if not MODULE_TOOLS:
            raise ValueError("Template modules must declare at least one tool key.")
        if not MODULE_EXAMPLES:
            raise ValueError("Template modules must declare at least one example.")
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
            A list of ModuleRouteSpec for platform router auto-mounting.
            Return [] (the default) if this module has no HTTP routes yet.

        Example when your module has HTTP routes::

            # from my_module.api_router import create_my_router
            # return [
            #     ModuleRouteSpec(
            #         prefix="/my_module",
            #         router_factory=create_my_router,
            #         tool_keys=("my_module.tool_a",),
            #         config_namespace="my_module",
            #     ),
            # ]
        """
        return []

    def required_tools(self) -> list[str]:
        """Return tool keys this module requires from the ToolRegistry.

        Returns:
            List of tool key strings. Platform scopes the tool registry to only
            these keys before passing it to build_runtime().
        """
        return list(MODULE_TOOLS)

    def report_filter_keys(self) -> list[str]:
        """Return field keys valid in filter_report_rows().

        Returns:
            List of lowercase filter key names. Only these keys are applied;
            unknown keys in the filter dict are silently ignored.
        """
        return list(MODULE_REPORT_FILTER_KEYS)

    async def register_tools(self, tool_registry: ToolRegistry, settings: Settings, registry=None, schema_registry=None) -> None:
        """Register module tools into the platform ToolRegistry.

        Args:
            tool_registry: Platform-provided registry. Call register() for each tool.
            settings: Infrastructure settings passed to tool constructors.
            registry: Optional ConfigRegistry (unused by template).
            schema_registry: Optional SchemaRegistry (unused by template).
        """
        tool_registry.register(TEMPLATE_SAMPLE_TOOL, TemplateSampleTool(settings))

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        """Construct the runtime handler for this module.

        Args:
            context: Build-time dependencies: settings, scoped tools, LLM model.

        Returns:
            A ModuleRuntime whose handle() method processes incoming requests.
        """
        del context
        return TemplateRuntime(
            module_id=self.module_id,
            action_id=self.action_id,
            capability_profiles=self.capability_profiles(),
        )

    def filter_report_rows(
        self,
        rows: list[JsonObject],
        filters: JsonObject | None = None,
    ) -> list[JsonObject]:
        """Filter report rows by exact key/value match.

        Args:
            rows: List of report row dicts to filter.
            filters: Dict of filter keys to filter values. Unknown keys are ignored.

        Returns:
            Filtered list. Returns all rows unchanged when filters is None or empty.
        """
        if not isinstance(filters, dict) or not filters:
            return list(rows)
        allowed_keys = {key.strip().lower() for key in self.report_filter_keys() if key.strip()}
        normalized_filters = {
            str(key).strip().lower(): str(value).strip().lower()
            for key, value in filters.items()
            if str(key).strip() and str(value).strip() and str(key).strip().lower() in allowed_keys
        }
        if not normalized_filters:
            return list(rows)
        filtered_rows: list[JsonObject] = []
        for row in rows:
            normalized_row = {
                str(key).strip().lower(): str(value).strip().lower()
                for key, value in row.items()
                if str(key).strip()
            }
            if all(normalized_row.get(key, "") == value for key, value in normalized_filters.items()):
                filtered_rows.append(row)
        return filtered_rows


    async def seed_data(self, session: Any) -> None:
        """Seed initial data for this module (per MODULE_STANDARD.md D-06/D-07).

        Idempotent: checks SeedVersionRecord first. Skips entirely if this
        module's seed_version already matches SEED_VERSION. Bump SEED_VERSION
        at module level when adding new seed rows to trigger re-seeding on
        next startup.

        Replace the ``pass`` body with real seed logic (scoring policies,
        lookup tables, etc.).
        """
        from sqlmodel import select

        from aila.storage.db_models import SeedVersionRecord

        existing = (await session.exec(
            select(SeedVersionRecord).where(SeedVersionRecord.module_id == self.module_id)
        )).first()
        if existing is not None and existing.seed_version == SEED_VERSION:
            return

        # Replace with real seed logic (scoring policies, lookup tables, etc.)
        pass

        if existing is None:
            session.add(SeedVersionRecord(module_id=self.module_id, seed_version=SEED_VERSION))
        else:
            existing.seed_version = SEED_VERSION
            from aila.platform.contracts._common import utc_now
            existing.seeded_at = utc_now()
            session.add(existing)
        await session.commit()

    async def system_summary(self, system_id: int, session: Session) -> dict[str, Any]:
        """Return module-contributed dashboard data for a single system.

        Called by GET /systems/{id} to enrich system detail with module-specific
        data. Override to return meaningful counts or statistics for the given
        system (e.g. ``{"critical": 5, "kev_count": 2}``).

        Args:
            system_id: ManagedSystemRecord primary key.
            session: Active SQLModel session. Do not create a new session_scope.

        Returns:
            Dict of module-specific data. Empty dict means no contribution.
        """
        del system_id, session
        return {}

    async def report_count(self, run_id: str, session: Session) -> dict[str, Any]:
        """Return semantic count breakdown for a report owned by this module.

        Called by GET /reports/{run_id}/count. Override to return a severity
        or category breakdown (e.g. ``{"total_findings": 55, "critical": 5}``).
        Return ``{}`` if this module does not own the given run_id.

        Args:
            run_id: WorkflowRunRecord primary key.
            session: Active SQLModel session. Do not create a new session_scope.

        Returns:
            Dict of count fields. Empty dict means no contribution.
        """
        del run_id, session
        return {}

    def health_checks(self) -> dict[str, object]:
        """Return module-specific health check callables (optional).

        Called by GET /health to collect module-contributed checks. Each value
        is a zero-argument callable returning a ModuleHealthResult. Override
        when your module has external dependencies worth monitoring.

        Example::

            # return {"my_check": lambda: ModuleHealthResult(status="up")}

        Returns:
            Dict mapping check name to zero-argument callable.
        """
        return {}


def create_module() -> ModuleProtocol:
    """Instantiate and return this module.

    Returns:
        A TemplateModule implementing ModuleProtocol.
        Replace TemplateModule with your real module class.
    """
    return TemplateModule()
