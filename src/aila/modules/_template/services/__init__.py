"""Service implementations for the template module.

Domain services -- anything that owns records this module writes -- live
here. A copier adds one file per service and re-exports its public
symbol through ``__all__``.

The platform ships parameterized generics for every investigation-shape
support service so a new module composes them rather than copying a peer
module's implementation (RFC-04). Each primitive below is generic over
the caller's record models, enums, and configuration namespace; the
module hands its residue to the constructor at wiring time. This simple-
action template does not carry investigation records of its own, so no
primitive is constructed here -- it stays a pointer list until a copier
adds the shape.

Available platform primitives (import directly, do not copy):

* ``aila.platform.services.pattern_store.PatternStore``            -- pattern rows + KnowledgeService mirror
* ``aila.platform.services.stage_tracker.StageTracker``            -- per-target stage timers with reap helpers
* ``aila.platform.services.branch_reaper``                         -- orphan branch sweeps
* ``aila.platform.services.branch_cleanup``                        -- terminal-close branch cleanup
* ``aila.platform.services.multi_target.MultiTargetService``       -- investigation <-> target join
* ``aila.platform.services.machine_readiness.MachineReadinessService`` -- MCP + install readiness probe
* ``aila.platform.services.investigation_reaper.InvestigationCapReaper`` -- cap-based investigation sweeps
* ``aila.platform.services.investigation_finalizers.InvestigationFinalizer`` -- terminal-outcome finalization
* ``aila.platform.services.stall_recovery.StallRecoverySweep``     -- workflow stall recovery
* ``aila.platform.services.outcome_review.OutcomeReviewService``   -- outcome vote + quorum kernel
* ``aila.platform.tasks.arq_purge.purge_arq_jobs_for_investigation`` -- ARQ + Redis job drop
* ``aila.platform.mcp.registry.McpRegistryService``                -- MCP server catalog probe + persist
* ``aila.platform.mcp.call_logger.McpCallLogger``                  -- MCP call recorder

Config surface: subclass
:class:`aila.platform.config_base.ModuleConfigBase` in ``config_schema.py``
so ``extra='forbid'`` is inherited (rule 37, ``module_config_schema_base``).

The honesty audit's ``service_copy_of_platform`` rule (38) treats a
module service file whose normalized content mirrors a platform service
file as a finding; import the platform generic, do not copy it.
"""
from __future__ import annotations

__all__: list[str] = []
