# honesty_whitelist.py
# Suppressions for known false positives in the AILA honesty audit.
# See also docs/MODULE_AI_CONTEXT.md §18 for absolute rules.
# Run: python -m aila.tools.honesty_audit src/ --whitelist honesty_whitelist.py
# Exit code 0 = no findings (clean).
# Exit code 1 = findings exist (investigate before ignoring).
#
# Whitelist entry format:
#   HONESTY_WHITELIST = [
#       ("filename_suffix.py", "function_name", "param_or_detail"),
#       ...
#   ]
#
# Categories of expected false positives:
#   a. Protocol/ABC abstract methods — body is ... but signature has params
#      (already skipped by auditor, but list here if edge cases arise)
#   b. Framework callbacks with mandatory signature (e.g. workflow stage handlers,
#      platform Tool.forward, or dispatch tables requiring a fixed signature)
#   c. CLI entry functions registered via @app.command() with unused ctx param
#   d. Module-level cache variables not matching the _CACHE_IMPL_IDENTIFIERS set
#      (e.g. _EMBEDDING_MODEL is a singleton cache, but name does not include "cache")
#   e. "persist" in docstrings meaning DB persistence, not in-memory caching
#   f. ModuleProtocol interface methods — mandatory one-liner overrides
#   g. Adapter interface methods — delegation is the pattern
#   h. Cache fallback patterns — silent fallback on corrupted cache is intentional

HONESTY_WHITELIST = [
    # Category (b): state_response_emit is a required workflow stage handler.
    ("_template/workflow.py", "state_response_emit", "context"),

    # Category (b): register_tools() accepts optional registry= param for backward compat.
    ("platform.py", "register_tools", "registry"),

    # Category (d): _get_embedding_model caches via module-level sentinel variable.
    ("knowledge.py", "_get_embedding_model", "caching"),

    # Category (e): ConfigRegistry.register() docstring says "Persists defaults to DB".
    ("registry.py", "register", "caching"),

    # Category (e): ConfigRegistry.set() docstring says "Persist value to DB".
    ("registry.py", "set", "caching"),

    # Category (b): honesty auditor's own docstrings mention "cach" as domain concept.
    ("honesty_audit.py", "_docstring_claims_caching", "caching"),
    ("honesty_audit.py", "_body_has_cache_impl", "caching"),

    # Category (b): CRUD lifecycle tools with cohesive resource management.
    ("scheduled_scans.py", "forward", "action-dispatch"),
    ("scoring_policy.py", "forward", "action-dispatch"),

    # Category (f): ModuleProtocol interface — required_tools and report_filter_keys
    # are one-liner overrides mandated by the protocol.
    ("_template/module.py", "required_tools", "inlining"),
    ("_template/module.py", "report_filter_keys", "inlining"),
    ("vulnerability/module.py", "report_filter_keys", "inlining"),

    # Category (g): collect_inventory delegates to build_inventory_from_command —
    # the adapter interface method IS the indirection point.
    ("adapters/base.py", "collect_inventory", "inlining"),

    # Category (b): Pydantic field validator — name is the public API contract.
    ("contracts/profile.py", "validate_display_name", "inlining"),

    # Category (f): list_run_records is a @staticmethod on ReportArtifactStore
    # providing a named query accessor on the class.
    ("report_store.py", "list_run_records", "inlining"),

    # Category (b): specialized_tools() is the named public helper used by
    # vuln_researcher prompt rendering + adapter tests. Inlining would
    # require duplicating the dict iteration in two call sites.
    ("mcp_adapters/registry.py", "specialized_tools", "inlining"),

    # Category (b): lazy imports inside _task_queue helpers avoid pulling
    # ``aila.platform.tasks`` and the VR workflow definitions at module
    # load time. Tested via the OutcomeDispatcher patch_assessment_report
    # path. Inline `# noqa: PLC0415` is required to silence ruff.
    ("vr/_task_queue.py", "default_task_queue", "noqa"),
    ("vr/_task_queue.py", "enqueue_vr_nday", "noqa"),
    ("vr/workflow/states/investigation_emit.py", "_run_pattern_extraction", "noqa"),
    ("vr/workflow/task.py", "run_target_analysis", "noqa"),

    # Category (b): builtin disclosure tracks must share a uniform render()
    # signature even when a specific track doesn't consume embargo_days
    # (blog_post defers timing to the operator outside the embargo system).
    ("vr/disclosure/builtin_tracks.py", "render", "embargo_days"),

    # Category (b): available_tracks() returns a defensive copy of the
    # private _REGISTRY dict. Inlining at call sites would leak mutable
    # internal state across the API boundary.
    ("vr/disclosure/registry.py", "available_tracks", "inlining"),

    # Category (h): router cache deserialization — silent fallback on corrupt
    # cache is intentional; the router re-routes on miss.
    ("router.py", "except Exception", "silently swallows"),

    # Category (b): Template module register_tools — registry and schema_registry
    # are ModuleProtocol contract params unused by the template.
    ("_template/module.py", "register_tools", "registry"),
    ("_template/module.py", "register_tools", "schema_registry"),

    # Category (g): hash_api_key and verify_api_key are public API accessors that
    # encapsulate the private _HASHER module-level singleton. The indirection is
    # intentional — callers should not access _HASHER directly.
    ("api/auth.py", "hash_api_key", "inlining"),
    ("api/auth.py", "verify_api_key", "inlining"),

    # Category (b): ARQ worker mandatory signature — ctx dict is required by ARQ
    # but not referenced in the handler body (ARQ injects it automatically).
    ("tasks/worker.py", "reaper", "ctx"),

    # Category (g): ServiceFactory properties are the DI injection point (D-02).
    # Each property wires self._bus to the service constructor -- the indirection
    # IS the pattern (constructor injection via factory).
    ("services/factory.py", "reports", "inlining"),
    ("services/factory.py", "storage", "inlining"),
    ("services/factory.py", "systems", "inlining"),
    ("services/factory.py", "knowledge", "inlining"),

    # Category (b): Standalone tool functions keep settings param for backward compat
    # after ServiceFactory migration (Plan 166-02). Settings is no longer used for
    # session creation but kept in public API signature per D-02.
    ("tools/blast_radius.py", "blast_radius", "settings"),
    ("tools/cve_arrivals.py", "arrivals_departures", "settings"),
    ("tools/heat_map.py", "package_heat_map", "settings"),
    ("tools/intel_cache.py", "_forward_cache_operation", "settings"),
    ("tools/intel_cache.py", "_forward_cve_cache_batch", "settings"),
    ("tools/inventory_drift.py", "inventory_drift", "settings"),
    ("tools/kb_insights.py", "kb_insights", "settings"),
    ("tools/peer_compare.py", "peer_compare", "settings"),
    ("tools/scoring_audit.py", "scoring_audit", "settings"),
    ("tools/verify_remediation.py", "verify_remediation", "settings"),

    # ── SbD NFR module ─────────────────────────────────────────
    # CLI script entrypoint: ``asyncio.run(main())`` at the ``__main__`` guard is
    # the conventional async entry point for a standalone destructive dev script.
    # The async DB layer (UnitOfWork) requires an event loop; bootstrapping it at
    # the script boundary is not a service-layer threading concern.
    ("sbd_nfr/scripts/force_reseed.py", "asyncio_in_module", "threading belongs to the platform layer"),


    # Category (g): IDABridgeTool IS the platform HTTP bridge for binary analysis.
    # httpx is its transport layer — same role as paramiko in SSHService.
    ("vr/tools/ida_bridge.py", "http_client_in_module", "HTTP clients belong to the platform layer"),
    ("vr/tools/audit_mcp_bridge.py", "http_client_in_module", "HTTP clients belong to the platform layer"),

    # Category (g): VRModule.health_checks probes the IDA MCP over HTTP.
    # This is a one-line httpx import inside an async closure, not a general HTTP client.
    ("vr/module.py", "http_client_in_module", "HTTP clients belong to the platform layer"),

    # Category (f): ModuleProtocol interface methods — returning [] or {} is the
    # correct no-op implementation for optional protocol methods. These are not
    # placeholder stubs; they are intentional "this module doesn't use this feature".
    ("protocol.py", "placeholder_return", "returns empty"),
    ("protocol.py", "placeholder_return", "returns empty dict"),
    ("platform.py", "placeholder_return", "returns empty"),
    ("_template/module.py", "placeholder_return", "returns empty"),
    ("hello_world/module.py", "placeholder_return", "returns empty"),
    ("forensics/module.py", "placeholder_return", "returns empty"),
    ("sbd_nfr/module.py", "placeholder_return", "returns empty"),
    ("vr/module.py", "placeholder_return", "returns empty"),
    ("vr/agents/nday_researcher.py", "placeholder_return", "returns empty"),

    # Category (f): Alembic baseline stamp — upgrade/downgrade are intentionally empty
    # because the baseline migration just stamps the version, no DDL needed.
    ("001_baseline_stamp.py", "pointless_pass", "implement or mark"),

    # Category (f): Service __init__ stubs — base classes with empty __init__ bodies
    # that subclasses override. Not abstract because they're usable as-is.
    ("platform/services/storage.py", "pointless_pass", "implement or mark"),
    ("platform/services/system.py", "pointless_pass", "implement or mark"),

    # Category (h): Template file has commented-out code as intentional examples.
    ("_template/module.py", "commented_out_code", "commented-out Python"),
    ("_template/module.py", "commented_out_code", "commented-out Python"),
    ("_template/module.py", "commented_out_code", "commented-out Python"),

    # ──────────────────────────────────────────────────────────────────
    # Category (h): Intentional error boundaries — broad_exception_catch.
    # The platform/API surface logs the exception and degrades gracefully
    # to keep the request, task, or worker pipeline alive. Narrowing the
    # catches would risk crashing a service on an unforeseen failure mode
    # at the system boundary; the breadth is the design.
    # ──────────────────────────────────────────────────────────────────

    # api/ — FastAPI app, middleware, and routers. Each catch logs and
    # returns a typed error response or degrades a single endpoint.
    ("api/app.py", "broad_exception_catch", "catches everything"),
    ("api/middleware/idempotency.py", "broad_exception_catch", "catches everything"),
    ("api/routers/dashboard.py", "broad_exception_catch", "catches everything"),
    ("api/routers/executive.py", "broad_exception_catch", "catches everything"),
    ("api/routers/findings_workflow.py", "broad_exception_catch", "catches everything"),
    ("api/routers/health.py", "broad_exception_catch", "catches everything"),
    ("api/routers/oidc.py", "broad_exception_catch", "catches everything"),
    ("api/routers/scans.py", "broad_exception_catch", "catches everything"),
    ("api/routers/scheduled_reports.py", "broad_exception_catch", "catches everything"),
    ("api/routers/search.py", "broad_exception_catch", "catches everything"),
    ("api/routers/sessions.py", "broad_exception_catch", "catches everything"),
    ("api/routers/systems.py", "broad_exception_catch", "catches everything"),
    ("api/routers/tasks.py", "broad_exception_catch", "catches everything"),
    ("api/routers/tools.py", "broad_exception_catch", "catches everything"),
    ("api/routers/topology.py", "broad_exception_catch", "catches everything"),
    ("api/routers/users.py", "broad_exception_catch", "catches everything"),

    # platform/ — LLM client, routing/runtime, services, task queue, and
    # workflow engine. These are the platform's outermost frames and
    # supervisors; they MUST keep running across model/provider/runner
    # failures and emit structured events instead of propagating.
    ("platform/llm/client.py", "broad_exception_catch", "catches everything"),
    ("platform/llm/pipeline.py", "broad_exception_catch", "catches everything"),
    ("platform/llm/verify.py", "broad_exception_catch", "catches everything"),
    ("platform/modules/platform.py", "broad_exception_catch", "catches everything"),
    ("platform/routing/router.py", "broad_exception_catch", "catches everything"),
    ("platform/runtime/orchestrator.py", "broad_exception_catch", "catches everything"),
    ("platform/services/health_probes.py", "broad_exception_catch", "catches everything"),
    ("platform/tasks/discovery.py", "broad_exception_catch", "catches everything"),
    ("platform/tasks/hooks.py", "broad_exception_catch", "catches everything"),
    ("platform/tasks/queue.py", "broad_exception_catch", "catches everything"),
    ("platform/tasks/report_tasks.py", "broad_exception_catch", "catches everything"),
    ("platform/tasks/worker.py", "broad_exception_catch", "catches everything"),
    ("platform/workflows/engine.py", "broad_exception_catch", "catches everything"),
    ("platform/workflows/log.py", "broad_exception_catch", "catches everything"),

    # storage/ — secret store catches keyring backend failures so a missing
    # platform-level keyring service does not break the API at startup.
    ("storage/secrets.py", "broad_exception_catch", "catches everything"),

    # modules/ — best-effort SSE emission failure boundaries. SbD-NFR session
    # completion notifications are non-critical; SILENT_FAILURE_TOTAL counter is
    # incremented and a warning is logged so the operator can investigate without
    # blocking the resolution workflow.
    ("sbd_nfr/services/resolution_service.py", "broad_exception_catch", "catches everything"),

    # ──────────────────────────────────────────────────────────────────
    # Category (h): except_return_default — mechanical typed catches whose
    # documented contract IS the empty default. These are pure parser /
    # coercion / cache-lookup utilities; the empty return is the public
    # contract, not an error swallow. Logging on every parse failure
    # would create unbounded log spam against external/user input.
    # ──────────────────────────────────────────────────────────────────

    # _dotenv.load_project_env: optional dotenv dependency check + missing
    # .env file is the documented "no .env loaded" contract.
    ("_dotenv.py", "except_return_default", "silently hides failures"),

    # api/routers/tools.py: registry.require() raises KeyError when the
    # tool key is unknown; the inner closure returns None to signal a 404
    # to the outer route handler.
    ("api/routers/tools.py", "except_return_default", "silently hides failures"),

    # forensics parser/coercion utilities — ill-formed input is the contract.
    ("forensics/api_router.py", "except_return_default", "silently hides failures"),
    ("workflow/states/collectors/_ghidra_stage.py", "except_return_default", "silently hides failures"),
    ("workflow/states/collectors/memory.py", "except_return_default", "silently hides failures"),
    ("workflow/states/collectors/memory_enrich.py", "except_return_default", "silently hides failures"),
    ("workflow/states/collectors/network.py", "except_return_default", "silently hides failures"),

    # SbD NFR scoring: numeric-string answer parser; non-numeric is
    # documented as "excluded from average" — returning None is the rule.
    ("sbd_nfr/services/scoring_service.py", "except_return_default", "silently hides failures"),

    # VR n-day researcher: structured-output JSON extraction. Failure means
    # the LLM produced unparseable text; the caller treats None as "no
    # submission" and the surrounding retry / scoring pipeline owns logging.
    ("vr/agents/nday_researcher.py", "except_return_default", "silently hides failures"),

    # vulnerability adapters: cache lookups & advisory fetch fallbacks.
    # arch.py: SQLAlchemyError on DB cache read → empty cache map (cold start).
    # osv.py: AILAError on remote advisory fetch → None to skip the entry.
    ("vulnerability/adapters/arch.py", "except_return_default", "silently hides failures"),
    ("vulnerability/adapters/osv.py", "except_return_default", "silently hides failures"),

    # Scoring agent prior-knowledge fetch — retrieval miss returns empty
    # context, which the prompt builder handles transparently.
    ("vulnerability/agents/scoring/agent.py", "except_return_default", "silently hides failures"),

    # vulnerability coercion utilities — the return-on-bad-input default is
    # the entire purpose of these functions (coerce_int, coerce_float,
    # coerce_non_negative_int).
    ("vulnerability/workflow/utils/coercion.py", "except_return_default", "silently hides failures"),

    # platform/contracts: numeric coercion for run-summary counts.
    ("platform/contracts/reporting.py", "except_return_default", "silently hides failures"),

    # platform/llm: budget guard rails treat unparseable / unset config as
    # "no ceiling" (early return); cost.py treats unparseable token caps as
    # "unlimited (0)" per the documented contract.
    ("platform/llm/budget_alert.py", "except_return_default", "silently hides failures"),
    ("platform/llm/cost.py", "except_return_default", "silently hides failures"),

    # platform/services/report._extract_target_from_run: malformed route_json
    # → empty target list, treated as "fleet-wide" by callers.
    ("platform/services/report.py", "except_return_default", "silently hides failures"),

    # platform/services/team_scope: SQLAlchemy listener fallback — statements
    # that don't expose a mapper / column descriptions are global queries.
    ("platform/services/team_scope.py", "except_return_default", "silently hides failures"),

    # platform/tasks/discovery: parser utilities for nproc, free, df, uptime
    # output — None is the documented "unparseable" contract.
    ("platform/tasks/discovery.py", "except_return_default", "silently hides failures"),

    # platform/tools/artifacts: JSON content-type parser fallback returns
    # the raw body when the payload is not valid JSON; _parse_json_object
    # returns {} when the stored payload is missing or malformed.
    ("platform/tools/artifacts.py", "except_return_default", "silently hides failures"),

    # platform/tools/audit._parse_json: malformed audit-record details → {}.
    ("platform/tools/audit.py", "except_return_default", "silently hides failures"),

    # platform/tools/http: SSRF DNS-fail short-circuit (downstream httpx
    # surfaces the error) and JSON-response decoder (None when not JSON).
    ("platform/tools/http.py", "except_return_default", "silently hides failures"),

    # storage/report_repository._parse_json_object: malformed report payload
    # → {} so callers see an empty dict instead of crashing.
    ("storage/report_repository.py", "except_return_default", "silently hides failures"),

    # tools/honesty_audit: source-text unparse fallback (line 1501) and
    # SyntaxError tolerance during directory walks (line 1716).
    ("tools/honesty_audit.py", "except_return_default", "silently hides failures"),

    # ---- Rules 1-23 residual (pre-existing, verified legitimate) --------

    # Category (g): Vulnerability module HTTP providers/adapters are the data-fetch
    # boundary itself — the module's equivalent of IDA bridge. httpx is their transport.
    ("vulnerability/adapters/ghsa.py", "http_client_in_module", "HTTP clients belong to the platform"),
    ("vulnerability/providers/_http.py", "http_client_in_module", "HTTP clients belong to the platform"),
    ("vulnerability/providers/alpine_secdb.py", "http_client_in_module", "HTTP clients belong to the platform"),
    ("vulnerability/providers/epss.py", "http_client_in_module", "HTTP clients belong to the platform"),
    ("vulnerability/providers/nvd.py", "http_client_in_module", "HTTP clients belong to the platform"),
    ("vulnerability/providers/osv.py", "http_client_in_module", "HTTP clients belong to the platform"),
    ("vulnerability/services/advisory.py", "http_client_in_module", "HTTP clients belong to the platform"),
    ("vulnerability/workflow/definitions.py", "http_client_in_module", "HTTP clients belong to the platform"),

    # Category (g): Vulnerability workflow imports psycopg for typed serialization-error
    # retry, not for direct DB connections. The exception type is the import target.
    ("vulnerability/workflow/definitions.py", "direct_db_in_module", "use UnitOfWork"),

    # Category (b): CLI sync-to-async bridge functions — Click/Typer requires sync
    # entry points. These thin wrappers call run_until_complete() which is the mandatory
    # pattern for invoking async code from a sync CLI handler.
    ("cli.py", "run_until_complete", "consider inlining"),

    # Category (b): Forensics tool_catalog factory function — the indirection is the
    # registry pattern (tool alias → factory callable → tool instance).
    ("forensics/tool_catalog.py", "factory_fn", "consider inlining"),

    # Category (b): CLI functions with unused parameters required by Typer's command
    # signature contract.
    ("cli.py", "report_findings", "unused parameter"),
    ("cli.py", "restore_db", "unused parameter"),
]

