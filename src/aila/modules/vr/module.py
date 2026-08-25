"""VR (vulnerability research) module entrypoint.

Implements ModuleProtocol. This file is the only file the platform imports
directly -- all wiring (capability profiles, tool registration, runtime
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
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.platform.contracts import JsonObject
from aila.platform.contracts.reasoning import (
    ReasoningDomainProfile,
    ReasoningStrategyDeclaration,
)
from aila.platform.mcp import default_capability_registry
from aila.platform.modules import (
    ModuleCapabilityProfile,
    ModuleContext,
    ModuleProtocol,
    ModuleRouteSpec,
    ModuleRuntime,
    action_id_for,
)
from aila.platform.runtime import ToolRegistry
from aila.platform.tasks.sweeps import (
    SweepPriority,
    all_periodic_sweeps,
    register_periodic_sweep,
)

from .capabilities import CAPABILITY_DESCRIPTION, CAPABILITY_EXAMPLES
from .masvs.parent_reconciler import sweep_masvs_audit_parents
from .runtime import VRRuntime
from .services.branch_reaper import sweep_orphan_active_branches
from .services.investigation_reconciler import sweep_investigations_reconcile
from .services.stage_tracker import reap_stuck_stages
from .services.stall_recovery import sweep_stalled_investigations
from .services.stuck_healer import sweep_stuck_investigations
from .tool_keys import (
    ALL_TOOL_KEYS,
    TOOL_ADVISORY_BUILDER,
    TOOL_CRASH_TRIAGE,
    TOOL_IDA_BRIDGE,
    TOOL_PATCH_DIFFER,
    TOOL_POC_RUNNER,
)
from .workflow.finalize import sweep_finalizable_investigations

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

    def reasoning_strategies(self) -> list[ReasoningStrategyDeclaration]:
        """Reasoning strategy families this module owns (RFC-05 d)."""
        return [
            ReasoningStrategyDeclaration(
                family="vulnerability_research",
                task_type="vulnerability_research",
                description="Exploitability, advisory, and remediation reasoning.",
                match_priority=20,
                match_keywords=[
                    "cve",
                    "cvss",
                    "advisory",
                    "package version",
                    "exploitability",
                    "kev",
                    "epss",
                ],
            ),
            ReasoningStrategyDeclaration(
                family="web_pentest",
                task_type="web_pentest",
                description="Web application attack-path reasoning.",
                match_priority=60,
                match_keywords=[
                    "xss",
                    "sqli",
                    "idor",
                    "csrf",
                    "jwt",
                    "token",
                    "auth bypass",
                    "request",
                    "response",
                    "endpoint",
                    "burp",
                ],
            ),
            ReasoningStrategyDeclaration(
                family="mobile_reverse",
                task_type="mobile_reverse",
                description="Mobile app reverse-engineering and threat analysis.",
                match_priority=10,
                match_keywords=[
                    "apk",
                    "ipa",
                    "android",
                    "ios",
                    "mobile",
                    "dexclassloader",
                    "manifest",
                ],
            ),
        ]

    def reasoning_domain_profiles(self) -> list[ReasoningDomainProfile]:
        """Reasoning domain profiles this module owns (RFC-05 d)."""
        return [
            ReasoningDomainProfile(
                domain_id="vulnerability_research",
                task_type="vulnerability_research",
                description="Exploitability, advisories, versions, and remediation reasoning.",
                allowed_strategies=["vulnerability_research", "generic"],
                default_strategy="vulnerability_research",
            ),
            ReasoningDomainProfile(
                domain_id="web_pentest",
                task_type="web_pentest",
                description="Attack-path and web application security reasoning.",
                allowed_strategies=["web_pentest", "network_forensics", "generic"],
                default_strategy="web_pentest",
            ),
            ReasoningDomainProfile(
                domain_id="mobile_reverse",
                task_type="mobile_reverse",
                description="APK/IPA reverse engineering and mobile app threat analysis.",
                allowed_strategies=["mobile_reverse", "malware_static", "generic"],
                default_strategy="mobile_reverse",
            ),
        ]

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

    def workflow_definitions(self) -> dict[str, dict]:
        """VR module-owned finding lifecycle extension.

        Adds the two VR-prefixed terminal domain states (``vr.false_positive``
        and ``vr.accepted_risk``) reachable from the base ``investigating``
        state, plus the re-open edges back to ``investigating``. Base
        states remain platform-owned; only the module-prefixed vocabulary
        is declared here per MODULE_STANDARD.
        """
        return {
            "finding": {
                "states": ["vr.false_positive", "vr.accepted_risk"],
                "transitions": {
                    "investigating": ["vr.false_positive", "vr.accepted_risk"],
                    "vr.false_positive": ["investigating"],
                    "vr.accepted_risk": ["investigating"],
                },
            },
        }

    async def register_tools(
        self,
        tool_registry: ToolRegistry,
        settings: Settings,
        registry: ConfigRegistry | None = None,
        schema_registry: SchemaRegistry | None = None,
    ) -> None:
        """Register VR tables, config schema, and tool instances.

        Tool construction is dependency-ordered: PatchDifferTool composes the
        already-built IDA bridge so we instantiate the bridge first and
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
        from aila.modules.vr.tools.patch_differ import PatchDifferTool
        from aila.modules.vr.tools.poc_runner import PoCRunnerTool
        from aila.platform.mcp.factory import make_bridge

        ida_bridge = make_bridge("ida_headless", module_id="vr", recorder=record_call)
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
        """No filterable reports -- return rows unchanged."""
        del filters
        return list(rows)

    def persona_router(self):
        """Return the VR :class:`PersonaRouter` subclass (req 31).

        Deferred import mirrors :meth:`route_specs` so the platform
        can list this module's persona bindings without pulling the
        VR agent stack at module-collection time.
        """
        from .agents.persona_router import PersonaRouter
        return PersonaRouter

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

        from aila.platform.contracts import utc_now
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

    async def seed_prompts(self) -> int:
        """RFC-09 activation: seed the VR file-backed prompts into the
        version store and set production aliases where none exist."""
        from .agents.vuln_researcher import seed_prompt_versions

        return await seed_prompt_versions()

    async def system_summary(self, system_id: int, session: Any) -> dict[str, Any]:
        """Return investigation counts for VR projects on ``system_id``.

        VR investigations are not directly system-scoped -- they belong
        to a VR project, and the project carries ``analysis_system_id``.
        Called by GET /systems/{id}: this scopes to projects hosted on
        the requested system and rolls up investigation status counts
        across them. Returns ``{}`` when the system hosts no VR project,
        so the platform's ``if result:`` guard hides the section.
        """
        try:
            from sqlmodel import func, select

            from aila.modules.vr.db_models import VRInvestigationRecord, VRProjectRecord
            from aila.platform.contracts.enums import InvestigationStatus

            if session is None:
                return {}

            project_count_stmt = select(func.count(VRProjectRecord.id)).where(
                VRProjectRecord.analysis_system_id == system_id,
            )
            project_count = int((await session.exec(project_count_stmt)).one() or 0)
            if project_count == 0:
                return {}

            grouped_stmt = (
                select(VRInvestigationRecord.status, func.count(VRInvestigationRecord.id))
                .join(VRProjectRecord, VRProjectRecord.id == VRInvestigationRecord.project_id)
                .where(VRProjectRecord.analysis_system_id == system_id)
                .group_by(VRInvestigationRecord.status)
            )
            rows = (await session.exec(grouped_stmt)).all()
            counts: dict[str, int] = {str(status): int(count or 0) for status, count in rows}

            total = sum(counts.values())
            active = (
                counts.get(InvestigationStatus.RUNNING.value, 0)
                + counts.get(InvestigationStatus.PAUSED.value, 0)
            )
            return {
                "vr_projects": project_count,
                "vr_investigations": total,
                "vr_active": active,
                "vr_completed": counts.get(InvestigationStatus.COMPLETED.value, 0),
            }
        except (OSError, RuntimeError, ValueError):
            _log.debug("vr.system_summary failed for system_id=%s", system_id, exc_info=True)
            return {}

    async def report_count(
        self,
        run_id: str,
        session: Any,
        *,
        team_id: str | None = None,
    ) -> dict[str, Any]:
        """Return module-wide VR investigation counts (dashboard aggregate).

        Called with an empty ``run_id`` by the platform dashboard so it
        can render a per-module summary. Returns investigation-domain
        counts rather than finding-domain counts (findings are the
        vulnerability module's responsibility) -- the dashboard sums
        keys ``total_findings`` / ``critical`` / ``high`` / ``medium``
        / ``low`` from every module, so absent finding keys correctly
        contribute zero. ``team_id`` narrows the aggregate to one
        team; ``None`` means god-tier (TEAM-06) with no team filter.
        """
        del run_id
        try:
            from datetime import UTC, datetime, timedelta

            from sqlmodel import func, select

            from aila.modules.vr.db_models import VRInvestigationRecord

            if session is None:
                return {}

            status_stmt = select(
                VRInvestigationRecord.status, func.count(VRInvestigationRecord.id),
            )
            if team_id is not None:
                status_stmt = status_stmt.where(VRInvestigationRecord.team_id == team_id)
            status_stmt = status_stmt.group_by(VRInvestigationRecord.status)
            rows = (await session.exec(status_stmt)).all()
            counts: dict[str, int] = {str(status): int(count or 0) for status, count in rows}
            total = sum(counts.values())
            if total == 0:
                return {}

            recent_cutoff = datetime.now(UTC) - timedelta(days=7)
            recent_stmt = select(func.count(VRInvestigationRecord.id)).where(
                VRInvestigationRecord.primary_outcome_id.is_not(None),
                VRInvestigationRecord.updated_at >= recent_cutoff,
            )
            if team_id is not None:
                recent_stmt = recent_stmt.where(VRInvestigationRecord.team_id == team_id)
            recent_outcomes = int((await session.exec(recent_stmt)).one() or 0)

            return {
                "total_investigations": total,
                "created": counts.get("created", 0),
                "running": counts.get("running", 0),
                "paused": counts.get("paused", 0),
                "completed": counts.get("completed", 0),
                "failed": counts.get("failed", 0),
                "abandoned": counts.get("abandoned", 0),
                "stalled": counts.get("stalled", 0),
                "recent_outcomes": recent_outcomes,
            }
        except (OSError, RuntimeError, ValueError):
            _log.debug("vr.report_count failed", exc_info=True)
            return {}

    def health_checks(self) -> dict[str, object]:
        """Probe every MCP server the VR runtime depends on.

        VR reaches ida-headless (binary analysis), audit-mcp (source-
        graph indexing), and android-mcp (APK audit) at runtime. Each
        probe resolves the current base URL through :func:`make_bridge`
        (env -> ConfigRegistry -> catalog -> default) and probes
        ``/health`` through the platform McpClient transport (bounded
        timeout) so a wedged server never blocks the platform
        ``GET /health`` response. A resolve or transport failure lands as
        a ``down`` entry; the probe never raises.
        """
        return {
            "ida_headless_reachability": _mcp_health_probe(self.module_id, "ida_headless"),
            "audit_mcp_reachability": _mcp_health_probe(self.module_id, "audit_mcp"),
            "android_mcp_reachability": _mcp_health_probe(self.module_id, "android_mcp"),
        }


def _mcp_health_probe(module_id: str, server_id: str):
    """Build a health-check callable for ``server_id`` under ``module_id``.

    The returned coroutine resolves the current base URL through
    :func:`make_bridge` (env -> ConfigRegistry -> catalog -> default) and
    probes the server via the platform :class:`McpClient` transport's
    bounded ``GET /health`` -- HTTP transport stays in the platform layer,
    not the module. A resolve failure or an unreachable server lands as
    ``down``; a reachable server is ``up`` and carries the server's own
    reported status. The probe never raises so a wedged server cannot
    break the platform ``GET /health`` collection loop.
    """
    async def _probe() -> dict[str, object]:
        from aila.platform.mcp.factory import make_bridge

        try:
            bridge = make_bridge(server_id, module_id=module_id, recorder=None)
            result = await bridge.health()
        except (OSError, RuntimeError, ValueError) as exc:
            return {
                "status": "down",
                "detail": f"{server_id} resolve failed: {type(exc).__name__}: {exc}",
            }
        if isinstance(result, dict) and result.get("status") == "error":
            return {
                "status": "down",
                "detail": f"{server_id} unreachable: {result.get('error') or 'no response'}",
            }
        reported = result.get("status") if isinstance(result, dict) else None
        return {
            "status": "up",
            "detail": (
                f"{server_id} reachable ({reported})"
                if reported else f"{server_id} reachable"
            ),
        }

    return _probe


def _register_vr_periodic_sweeps() -> None:
    """Register VR's per-tick maintenance sweeps with the platform reaper.

    Called from :func:`create_module` so the registration is a side-effect
    of module instantiation -- the same lifecycle hook the platform uses
    for capability profiles + tool keys + route specs. This is the
    operator-visible chokepoint where "VR module owns these sweeps" is
    declared; the platform iterates the registry without knowing VR
    exists.

    Idempotent: probe the registry for the well-known sentinel name
    ``vr.finalize``; if it's already there, every other VR sweep is
    registered too and re-registration would raise. Probing the registry
    rather than a module-level flag means tests that clear the registry
    in an autouse fixture automatically re-register on the next
    create_module() call.
    """
    if "vr.finalize" in all_periodic_sweeps():
        return

    # vr.stage_tracker -- reaps stuck target-analysis stages whose
    # workers never recorded a terminal transition. Returns an int
    # count of stages reaped.
    register_periodic_sweep(
        "vr.stage_tracker",
        reap_stuck_stages,
        order=SweepPriority.CAP_EXCEEDED_REAPER,
    )

    # vr.branch_reaper -- flips orphan ACTIVE branches whose parent
    # investigation is ALREADY terminal. Independent of finalize:
    # finalize drives RUNNING investigations to terminal; branch_reaper
    # cleans up branches left behind under investigations that already
    # terminated via some other path (operator DB action, legacy code
    # paths that completed an investigation without cascading to its
    # branches).
    register_periodic_sweep(
        "vr.branch_reaper",
        sweep_orphan_active_branches,
        order=SweepPriority.ORPHAN_BRANCH_REAPER,
    )

    # vr.masvs_parent_reconciler -- drives the parent batch state
    # machine (CREATED → RUNNING → COMPLETED) for MASVS audits.
    # MASVS-SPECIFIC: this sweep walks parent investigations of kind
    # masvs_audit and rolls up child statuses.
    register_periodic_sweep(
        "vr.masvs_parent_reconciler",
        sweep_masvs_audit_parents,
        order=SweepPriority.STALE_BRANCH_ABANDONMENT,
    )

    # vr.finalize -- Phase C chokepoint. Walks RUNNING investigations
    # and applies the deterministic 4-trigger picker:
    #
    #   1. all_outcomes              -> synthesis_enqueued
    #   2. rejected_quorum           -> close-rejected per-id helper
    #   3. wall_clock_idle_grace     -> cap-exceeded per-id helper
    #                                   (also covers turn / message caps)
    #   4. all_terminal_no_outcome   -> orphan audit_memo per-id helper
    #
    # Replaces the prior vr.investigation_reaper + vr.branch_reaper
    # sweeps (their work is folded into the per-id helpers finalize
    # delegates to). The sweep wrappers in
    # vr/services/investigation_reaper.py and
    # vr/services/branch_reaper.py remain importable so any operator
    # tooling that hits them directly still works, but they no longer
    # run on the cron.
    register_periodic_sweep(
        "vr.finalize",
        sweep_finalizable_investigations,
        order=SweepPriority.NO_FINDING_SYNTHESIS,
    )

    # vr.stall_recovery -- recovery backstop for tasks killed mid-
    # execution by CancelledError, worker restart, or host kill.
    # Every other cutover fix assumes the task body returns or
    # raises through Exception; CancelledError inherits from
    # BaseException and slips past all of them. This sweep finds
    # investigations stuck in status=running (or created if the
    # first enqueue was lost) with zero in-flight tasks, then re-
    # enqueues run_vr_investigate (or run_vr_nday for n_day kind)
    # per active branch. See services/stall_recovery.py for the
    # full rate-model rationale + env-tuning knobs.
    #
    # Cron interval is the same 1-minute reaper tick as every other
    # VR sweep. Per-tick submit cap defaults to 6 (env-tunable via
    # AILA_VR_STALL_RECOVERY_LIMIT). Idle threshold defaults to 15
    # minutes (env: AILA_VR_STALL_RECOVERY_IDLE_MIN).
    register_periodic_sweep(
        "vr.stall_recovery",
        sweep_stalled_investigations,
        order=SweepPriority.STALL_RECOVERY,
    )

    # vr.stuck_healer -- RFC-07 #31 criterion 6. Sibling of
    # ``vr.stall_recovery``: stall_recovery re-enqueues rows whose tasks
    # are cursor-agnostic-eligible via the operator-tuned rate model,
    # while stuck_healer targets the narrower "RUNNING with no live task
    # AND no resumable cursor" zombie the task-level state reconciler
    # cannot heal (a crashed / absent cursor gives it nothing to resume
    # from). Emits a durable ``kind='recovery'`` ledger event per heal
    # via :func:`ResilienceLayer.emit_recovery_event` so the RFC-07
    # audit trail carries every automated re-enqueue.
    register_periodic_sweep(
        "vr.stuck_healer",
        sweep_stuck_investigations,
        order=SweepPriority.STUCK_HEALER,
    )

    # vr.investigation_reconciler -- RFC-07 reconcile wave (L3.4): the
    # investigation-scoped reconciler authority pass. Runs AFTER
    # stall(500) / stuck(600) as the last-resort convergence step: it
    # reconciles every task + cursor of each non-terminal, non-paused
    # investigation and drives recovery (same-job-id resume or full
    # re-enqueue) when the row is RUNNING/CREATED-but-dead, so no path
    # can leave an investigation RUNNING-with-nothing-enqueued even when
    # every earlier sweep's eligibility window missed it. Gated by the
    # platform config key
    # ``investigation_reconciler_periodic_enabled`` (default True).
    register_periodic_sweep(
        "vr.investigation_reconciler",
        sweep_investigations_reconcile,
        order=SweepPriority.RECONCILE,
    )


# Module-load-time registration. _register_vr_periodic_sweeps() is only
# invoked from create_module(); a `from aila.modules.vr.module import VRModule`
# covering the protocol type pulls the supporting imports but does NOT fire
# registration (the side-effect lives in the function call, gated by the
# `vr.finalize` sentinel for idempotency).


def _declare_vr_mcp_descriptors() -> None:
    """Publish VR's MCP descriptors to the platform capability registry.

    RFC-11 step 3 -- the module DECLARES its servers by capability so
    every platform caller can resolve a server BY CAPABILITY, never by
    module name. Delegated to :func:`services.mcp_registry.descriptors`
    which adapts the existing ``MCP_SERVERS`` + ``SERVER_CAPABILITY_
    DEFAULTS`` declaration into the frozen descriptor shape. Idempotent:
    :meth:`aila.platform.mcp.capability_registry.McpCapabilityRegistry.declare_all`
    supersedes the previous record per ``(module_scope, name)``.
    """
    from .services.mcp_registry import get_descriptors as _vr_mcp_get_descriptors

    default_capability_registry().declare_all(
        MODULE_ID, _vr_mcp_get_descriptors(),
    )


def create_module() -> ModuleProtocol:
    """Return a new VRModule instance for the platform module loader."""
    _register_vr_periodic_sweeps()
    _declare_vr_mcp_descriptors()
    return VRModule()
