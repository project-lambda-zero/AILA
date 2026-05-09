"""Forensics module entrypoint.

Implements ModuleProtocol. This file is the only file the platform imports
directly — all wiring happens here.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypedDict

if TYPE_CHECKING:
    from aila.storage.registry import SchemaRegistry

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

__all__ = ["ForensicsModule", "create_module"]


class ForensicsSummary(TypedDict, total=False):
    forensics_projects: int
    forensics_active: int
from .runtime import ForensicsRuntime
from .tool_catalog import iter_tool_specs
from .tool_keys import all_tool_keys

_log = logging.getLogger(__name__)

MODULE_ID = Path(__file__).parent.name
ANALYZE_ACTION_ID = action_id_for(MODULE_ID, "analyze_evidence")
INVESTIGATE_ACTION_ID = action_id_for(MODULE_ID, "investigate")
SHARED_TOOL_KEYS = ("registry.systems", "ssh.command")
SEED_VERSION = "1.0"
REPORT_ROW_FILTER_KEYS = (
    "artifact_family",
    "artifact_type",
    "source_tool",
    "project_id",
)


class ForensicsModule(ModuleProtocol):
    """ModuleProtocol implementation for forensic investigation.

    Owns the lifecycle of forensic evidence analysis: tool registration,
    runtime construction, report row filtering, and initial data seeding.
    """

    module_id = MODULE_ID
    analyze_action_id = ANALYZE_ACTION_ID
    investigate_action_id = INVESTIGATE_ACTION_ID

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        """Return capability profiles advertising this module to the routing agent."""
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.analyze_action_id,
                description=CAPABILITY_DESCRIPTION,
                tools=["registry.systems", "ssh.command", *all_tool_keys()],
                examples=list(CAPABILITY_EXAMPLES[:3]),
            ),
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.investigate_action_id,
                description=(
                    "Run a bounded free-flow investigation on forensic evidence. "
                    "Agent generates and executes Python scripts on the analyzer "
                    "machine to answer specific questions (max 10 attempts)."
                ),
                tools=["ssh.command", *all_tool_keys()],
                examples=list(CAPABILITY_EXAMPLES[3:]),
            ),
        ]

    def required_tools(self) -> list[str]:
        """Return tool keys this module needs before handle() is called."""
        return [*SHARED_TOOL_KEYS, *all_tool_keys()]

    def report_filter_keys(self) -> list[str]:
        """Return field names valid for report row filtering."""
        return ["artifact_family", "artifact_type", "source_tool", "project_id"]

    async def register_tools(
        self,
        tool_registry: ToolRegistry,
        settings: Settings,
        registry=None,
        schema_registry: SchemaRegistry | None = None,
    ) -> None:
        """Register all forensics module tools and DB models.

        Pushes DB models into schema_registry, registers config schema, and
        discovers + registers all tool specs from the tools/ subpackage.
        """
        if schema_registry is not None:
            from aila.modules.forensics.db_models import (
                AgentStepRecord,
                AnswerCandidateRecord,
                ArtifactRecord,
                ForensicsProjectRecord,
                InvestigationRunRecord,
                LeadRecord,
                ProjectEvidenceRecord,
                WriteUpRecord,
            )
            schema_registry.push(
                ForensicsProjectRecord,
                ProjectEvidenceRecord,
                ArtifactRecord,
                LeadRecord,
                InvestigationRunRecord,
                AgentStepRecord,
                WriteUpRecord,
                AnswerCandidateRecord,
            )

        if registry is not None:
            from aila.modules.forensics.config_schema import FORENSICS_LLM_MODEL, ForensicsConfigSchema
            await registry.register(self.module_id, ForensicsConfigSchema)

            import os
            for task_type in ("forensics_freeflow", "forensics_resolver", "forensics_writeup"):
                env_key = f"AILA_PLATFORM_LLM_MODEL_{task_type.upper()}"
                if not os.environ.get(env_key):
                    os.environ[env_key] = FORENSICS_LLM_MODEL
                    _log.info("Seeded %s=%s for forensics LLM routing", env_key, FORENSICS_LLM_MODEL)

        for spec in iter_tool_specs():
            tool_registry.register(spec.key(), spec.factory(settings))

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        """Construct and return a fully-wired ForensicsRuntime."""
        from aila.platform.tools.ssh import SSHCommandTool

        ssh_tool = context.tool_registry.require("ssh.command", SSHCommandTool)

        return ForensicsRuntime(
            module_id=self.module_id,
            analyze_action_id=self.analyze_action_id,
            investigate_action_id=self.investigate_action_id,
            capability_profiles=self.capability_profiles(),
            ssh_tool=ssh_tool,
            workflow_model=context.runtime_model,
        )

    def filter_report_rows(
        self,
        rows: list[JsonObject],
        filters: JsonObject | None = None,
    ) -> list[JsonObject]:
        """Filter report rows by exact key/value match on allowed keys."""
        if not isinstance(filters, dict) or not filters:
            return list(rows)
        allowed = {k.strip().lower() for k in REPORT_ROW_FILTER_KEYS if k.strip()}
        normalized = {
            str(k).strip().lower(): str(v).strip().lower()
            for k, v in filters.items()
            if str(k).strip() and str(v).strip() and str(k).strip().lower() in allowed
        }
        if not normalized:
            return list(rows)
        result: list[JsonObject] = []
        for row in rows:
            row_norm = {str(k).strip().lower(): str(v).strip().lower() for k, v in row.items() if str(k).strip()}
            if all(row_norm.get(k, "") == v for k, v in normalized.items()):
                result.append(row)
        return result

    async def seed_data(self, session: Any) -> None:
        """Seed initial data for the forensics module (idempotent)."""
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

    def route_specs(self) -> list[ModuleRouteSpec]:
        """Declare the forensics module HTTP route surface."""
        from aila.modules.forensics.api_router import create_forensics_router

        return [
            ModuleRouteSpec(
                prefix="/forensics",
                router_factory=create_forensics_router,
                tool_keys=tuple(all_tool_keys()),
                config_namespace="forensics",
            ),
        ]

    async def system_summary(self, system_id: int, session: Any) -> ForensicsSummary:
        """Return forensics project counts for a system."""
        try:
            from sqlmodel import select

            from aila.modules.forensics.db_models import ForensicsProjectRecord

            if session is None:
                return {}
            stmt = select(ForensicsProjectRecord).where(
                ForensicsProjectRecord.system_id == system_id
            )
            rows = (await session.exec(stmt)).all()
            if not rows:
                return {}
            return {
                "forensics_projects": len(rows),
                "forensics_active": sum(1 for r in rows if r.status in ("created", "ready", "analyzing")),
            }
        except (OSError, RuntimeError, ValueError):
            _log.debug("system_summary failed for system_id=%s", system_id, exc_info=True)
            return {}

    async def report_count(self, _run_id: str, _session: Any) -> dict[str, int]:
        """Return empty dict — forensics does not own workflow run reports."""
        return {}

    def health_checks(self) -> dict[str, object]:
        """Return SSH reachability probe callable for the platform health router.

        The platform inspects the callable: if it is a coroutine function it
        awaits it directly in the main event loop; if sync it wraps it in
        asyncio.to_thread.  This probe is async so it runs in the main loop
        and can safely share the asyncpg connection pool.
        """

        async def _ssh_reachability() -> dict[str, object]:
            try:
                from aila.config import get_settings
                from aila.modules.forensics.db_models import ForensicsProjectRecord
                from aila.modules.forensics.tools._ssh_helper import get_ssh_service
                from aila.platform.uow import UnitOfWork
                from aila.storage.db_models import ManagedSystemRecord
                from sqlmodel import select

                # Only probe systems that are actually used by forensics projects.
                async with UnitOfWork() as uow:
                    session = uow.session
                    system_ids = [
                        row for row in (await session.exec(
                            select(ForensicsProjectRecord.system_id).distinct()
                        )).all()
                        if row is not None
                    ]
                    if not system_ids:
                        return {
                            "status": "up",
                            "detail": "No forensics projects configured — skipping SSH probe",
                        }
                    systems = (await session.exec(
                        select(ManagedSystemRecord).where(
                            ManagedSystemRecord.id.in_(system_ids)
                        )
                    )).all()

                if not systems:
                    return {
                        "status": "up",
                        "detail": "No analyzer systems found — skipping SSH probe",
                    }

                ssh = await get_ssh_service(get_settings())
                last_error = ""
                for system in systems:
                    integration = {
                        "name": system.name,
                        "host": system.host,
                        "username": system.username,
                        "port": system.port,
                        "private_key_path": system.private_key_path,
                        "password_secret_id": system.password_secret_id,
                        "known_hosts_path": system.known_hosts_path,
                        "host_key_fingerprint": system.host_key_fingerprint,
                    }
                    try:
                        output = await ssh.run_command(
                            integration,
                            "echo aila-health-probe",
                            timeout_seconds=3.0,
                            connect_timeout=3.0,
                        )
                        if "aila-health-probe" in output:
                            return {"status": "up", "detail": f"SSH reachable: {system.name} ({system.host})"}
                        last_error = f"unexpected output: {output.strip()[:80]}"
                    except (OSError, TimeoutError, ConnectionError, RuntimeError, ValueError) as exc:
                        last_error = f"{type(exc).__name__}: {exc}"
                        _log.debug("forensics.ssh_reachability: %s (%s) — %s", system.name, system.host, last_error)

                _log.warning("forensics.ssh_reachability: all forensics systems unreachable. Last: %s", last_error)
                return {
                    "status": "degraded",
                    "detail": f"SSH probe failed on all {len(systems)} forensics system(s). Last: {last_error}",
                }

            except (OSError, TimeoutError, ConnectionError, RuntimeError, ValueError) as exc:
                detail = f"Health probe error: {type(exc).__name__}: {exc}"
                _log.warning("forensics.ssh_reachability outer: %s", detail)
                return {"status": "degraded", "detail": detail}

        return {"forensics.ssh_reachability": _ssh_reachability}


def create_module() -> ModuleProtocol:
    """Return a new ForensicsModule instance for the platform module loader."""
    return ForensicsModule()
