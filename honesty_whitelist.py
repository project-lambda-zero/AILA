# honesty_whitelist.py
# Suppressions for known false positives in the AILA honesty audit.
# See also docs/MODULE_AGENT_GUIDE.md §18 for absolute rules.
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
#   a. Protocol/ABC abstract methods -- body is ... but signature has params
#      (already skipped by auditor, but list here if edge cases arise)
#   b. Framework callbacks with mandatory signature (e.g. workflow stage handlers,
#      platform Tool.forward, or dispatch tables requiring a fixed signature)
#   c. CLI entry functions registered via @app.command() with unused ctx param
#   d. Module-level cache variables not matching the _CACHE_IMPL_IDENTIFIERS set
#      (e.g. _EMBEDDING_MODEL is a singleton cache, but name does not include "cache")
#   e. "persist" in docstrings meaning DB persistence, not in-memory caching
#   f. ModuleProtocol interface methods -- mandatory one-liner overrides
#   g. Adapter interface methods -- delegation is the pattern
#   h. Cache fallback patterns -- silent fallback on corrupted cache is intentional

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

    # Category (f): ModuleProtocol interface -- required_tools and report_filter_keys
    # are one-liner overrides mandated by the protocol.
    ("_template/module.py", "required_tools", "inlining"),
    ("_template/module.py", "report_filter_keys", "inlining"),
    ("vulnerability/module.py", "report_filter_keys", "inlining"),

    # Category (g): collect_inventory delegates to build_inventory_from_command --
    # the adapter interface method IS the indirection point.
    ("adapters/base.py", "collect_inventory", "inlining"),

    # Category (b): Pydantic field validator -- name is the public API contract.
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
    ("vr/_task_queue.py", "enqueue_downstream_target_stages", "noqa"),
    # Category (b): same lazy-import pattern in the malware module's
    # outcome dispatcher. _dispatch_sub_investigation defers the
    # ``aila.modules.malware._task_queue`` + ``workflow.task`` imports
    # until the dispatch actually fires (after registration completes)
    # so the state-file registration cycle stays unbroken.
    ("malware/agents/outcome_dispatcher.py", "_dispatch_sub_investigation", "noqa"),
    ("vr/workflow/states/investigation_emit.py", "_run_pattern_extraction", "noqa"),
    ("vr/workflow/task.py", "run_target_analysis", "noqa"),
    ("vr/workflow/task.py", "run_fuzz_campaign_launch", "noqa"),
    ("vr/services/target_analysis.py", "_run_git", "noqa"),
    # Bridges hoisted to platform/mcp/bridges/ -- these noqa entries follow the move.
    ("platform/mcp/bridges/audit_mcp.py", "_resolve_base_url", "noqa"),
    ("platform/mcp/bridges/ida_headless.py", "_resolve_base_url", "noqa"),
    ("platform/mcp/bridges/audit_mcp.py", "forward", "noqa"),
    ("platform/mcp/bridges/ida_headless.py", "forward", "noqa"),
    ("platform/mcp/bridges/android_mcp.py", "_resolve_base_url", "noqa"),
    ("platform/mcp/bridges/android_mcp.py", "forward", "noqa"),

    # Category (b): _enqueue_next_investigation_run lives in
    # workflow/states/investigation_emit.py -- a state file. Workflow
    # registration loads every state file, then loads workflow.task
    # which imports those state functions to build the definition.
    # Top-level importing default_task_queue (which lazy-loads
    # workflow.task internally) or run_vr_investigate directly would
    # create a cycle during registration. The lazy import here defers
    # those references until the state actually runs, by which point
    # registration is complete.
    ("vr/workflow/states/investigation_emit.py", "_enqueue_next_investigation_run", "noqa"),
    ("vr/agents/outcome_dispatcher.py", "_int_or_none", "inlining"),
    ("vr/api_router.py", "_fuzz_proposal_summary", "inlining"),

    # Category (b): Phase C surgical (orphan-branch close on terminal flip).
    # services/branch_cleanup.py is imported inline at every COMPLETED/FAILED/
    # ABANDONED transition site so the helper lands in the SAME UoW that the
    # caller already opened. Top-level import would force every caller to
    # import it, and the helper has a circular dependency risk via
    # vr.contracts (which branch_cleanup deliberately avoids by reading
    # status enum values directly from the platform contract layer).
    # See an earlier audit pass for the observed BLOCK bug rationale.
    ("vr/workflow/states/investigation_emit.py", "state_investigation_emit", "noqa"),
    ("vr/services/investigation_finalizers.py", "synthesize_no_finding_outcomes", "noqa"),
    ("vr/masvs/parent_reconciler.py", "_enforce_total_turn_cap", "noqa"),
    ("vr/masvs/parent_reconciler.py", "sweep_masvs_audit_parents", "noqa"),
    ("vr/agents/outcome_dispatcher.py", "_mark_investigation_completed", "noqa"),
    ("vr/agents/synthesis_agent.py", "run", "noqa"),

    # Category (b): builtin disclosure tracks must share a uniform render()
    # signature even when a specific track doesn't consume embargo_days
    # (blog_post defers timing to the operator outside the embargo system).
    ("vr/disclosure/builtin_tracks.py", "render", "embargo_days"),

    # Category (b): available_tracks() returns a defensive copy of the
    # private _REGISTRY dict. Inlining at call sites would leak mutable
    # internal state across the API boundary.
    ("vr/disclosure/registry.py", "available_tracks", "inlining"),

    # Category (h): router cache deserialization -- silent fallback on corrupt
    # cache is intentional; the router re-routes on miss.
    ("router.py", "except Exception", "silently swallows"),

    # Category (b): Template module register_tools -- registry and schema_registry
    # are ModuleProtocol contract params unused by the template.
    ("_template/module.py", "register_tools", "registry"),
    ("_template/module.py", "register_tools", "schema_registry"),

    # Category (g): hash_api_key and verify_api_key are public API accessors that
    # encapsulate the private _HASHER module-level singleton. The indirection is
    # intentional -- callers should not access _HASHER directly.
    ("api/auth.py", "hash_api_key", "inlining"),
    ("api/auth.py", "verify_api_key", "inlining"),

    # Category (b): ARQ worker mandatory signature -- ctx dict is required by ARQ
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

    # The three MCP bridges hoisted to platform/mcp/bridges/ no longer trigger
    # http_client_in_module (the rule only fires inside modules/), so the
    # previous vr/tools/ entries here were dropped during the hoist.
    ("vr/services/mcp_registry.py", "http_client_in_module", "HTTP clients belong to the platform layer"),

    # Category (g): VRModule.health_checks probes the IDA MCP over HTTP.
    # This is a one-line httpx import inside an async closure, not a general HTTP client.
    ("vr/module.py", "http_client_in_module", "HTTP clients belong to the platform layer"),

    # Category (f): ModuleProtocol interface methods -- returning [] or {} is the
    # correct no-op implementation for optional protocol methods. These are not
    # placeholder stubs; they are intentional "this module doesn't use this feature".
    ("protocol.py", "placeholder_return", "returns empty"),
    ("protocol.py", "placeholder_return", "returns empty dict"),
    ("platform.py", "placeholder_return", "returns empty"),
    ("_template/module.py", "placeholder_return", "returns empty"),
    ("hello_world/module.py", "placeholder_return", "returns empty"),
    ("forensics/module.py", "placeholder_return", "returns empty"),
    ("vr/module.py", "placeholder_return", "returns empty"),
    ("vr/agents/nday_researcher.py", "placeholder_return", "returns empty"),

    # Category (f): Alembic baseline stamp -- upgrade/downgrade are intentionally empty
    # because the baseline migration just stamps the version, no DDL needed.
    ("001_baseline_stamp.py", "pointless_pass", "implement or mark"),

    # Category (f): Service __init__ stubs -- base classes with empty __init__ bodies
    # that subclasses override. Not abstract because they're usable as-is.
    ("platform/services/storage.py", "pointless_pass", "implement or mark"),
    ("platform/services/system.py", "pointless_pass", "implement or mark"),

    # Category (h): Template file has commented-out code as intentional examples.
    ("_template/module.py", "commented_out_code", "commented-out Python"),
    ("_template/module.py", "commented_out_code", "commented-out Python"),
    ("_template/module.py", "commented_out_code", "commented-out Python"),

    # ──────────────────────────────────────────────────────────────────
    # Category (h): Intentional error boundaries -- broad_exception_catch.
    # The platform/API surface logs the exception and degrades gracefully
    # to keep the request, task, or worker pipeline alive. Narrowing the
    # catches would risk crashing a service on an unforeseen failure mode
    # at the system boundary; the breadth is the design.
    # ──────────────────────────────────────────────────────────────────

    # api/ -- FastAPI app, middleware, and routers. Each catch logs and
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

    # platform/ -- LLM client, routing/runtime, services, task queue, and
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

    # storage/ -- secret store catches keyring backend failures so a missing
    # platform-level keyring service does not break the API at startup.
    ("storage/secrets.py", "broad_exception_catch", "catches everything"),

    # ──────────────────────────────────────────────────────────────────
    # Category (h): except_return_default -- mechanical typed catches whose
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

    # forensics parser/coercion utilities -- ill-formed input is the contract.
    ("forensics/api_router.py", "except_return_default", "silently hides failures"),
    ("workflow/states/collectors/_ghidra_stage.py", "except_return_default", "silently hides failures"),
    ("workflow/states/collectors/memory.py", "except_return_default", "silently hides failures"),
    ("workflow/states/collectors/memory_enrich.py", "except_return_default", "silently hides failures"),
    ("workflow/states/collectors/network.py", "except_return_default", "silently hides failures"),

    # VR n-day researcher: structured-output JSON extraction. Failure means
    # the LLM produced unparseable text; the caller treats None as "no
    # submission" and the surrounding retry / scoring pipeline owns logging.
    ("vr/agents/nday_researcher.py", "except_return_default", "silently hides failures"),

    # vulnerability adapters: cache lookups & advisory fetch fallbacks.
    # arch.py: SQLAlchemyError on DB cache read → empty cache map (cold start).
    # osv.py: AILAError on remote advisory fetch → None to skip the entry.
    ("vulnerability/adapters/arch.py", "except_return_default", "silently hides failures"),
    ("vulnerability/adapters/osv.py", "except_return_default", "silently hides failures"),

    # Scoring agent prior-knowledge fetch -- retrieval miss returns empty
    # context, which the prompt builder handles transparently.
    ("vulnerability/agents/scoring/agent.py", "except_return_default", "silently hides failures"),

    # vulnerability coercion utilities -- the return-on-bad-input default is
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

    # platform/services/team_scope: SQLAlchemy listener fallback -- statements
    # that don't expose a mapper / column descriptions are global queries.
    ("platform/services/team_scope.py", "except_return_default", "silently hides failures"),

    # platform/tasks/discovery: parser utilities for nproc, free, df, uptime
    # output -- None is the documented "unparseable" contract.
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
    # boundary itself -- the module's equivalent of IDA bridge. httpx is their transport.
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

    # Category (b): CLI sync-to-async bridge functions -- Click/Typer requires sync
    # entry points. These thin wrappers call run_until_complete() which is the mandatory
    # pattern for invoking async code from a sync CLI handler.
    ("cli.py", "run_until_complete", "consider inlining"),

    # Category (b): Forensics tool_catalog factory function -- the indirection is the
    # registry pattern (tool alias → factory callable → tool instance).
    ("forensics/tool_catalog.py", "factory_fn", "consider inlining"),

    # Category (b): CLI functions with unused parameters required by Typer's command
    # signature contract.
    ("cli.py", "report_findings", "unused parameter"),
    ("cli.py", "restore_db", "unused parameter"),

    # -------------------------------------------------------------------
    # Structural patterns -- documented exceptions to audit rules 16-22.
    # -------------------------------------------------------------------

    # Category (i): http_client_in_module. The platform has no centralized
    # httpx wrapper yet (the eventual goal is one shared transport with
    # uniform retry / call-log policy). Until that ships, modules call
    # httpx directly with response logging via services/mcp_call_logger
    # OR services/arq_purge (per-call recording). Each occurrence below
    # is a documented direct httpx use, not negligence.
    ("malware/agents/auto_steering.py", "http_client_in_module", "import httpx"),
    ("malware/agents/claim_verifier.py", "http_client_in_module", "import httpx"),
    ("malware/agents/narrative_agent.py", "http_client_in_module", "import httpx"),
    ("malware/agents/pattern_extractor.py", "http_client_in_module", "import httpx"),
    ("malware/agents/synthesis_agent.py", "http_client_in_module", "import httpx"),
    ("malware/agents/tool_executor.py", "http_client_in_module", "import httpx"),
    ("malware/api_router.py", "http_client_in_module", "import httpx"),
    ("malware/services/mcp_registry.py", "http_client_in_module", "import httpx"),
    ("malware/workflow/finalize.py", "http_client_in_module", "import httpx"),
    ("malware/workflow/task.py", "http_client_in_module", "import httpx"),
    ("vr/agents/auto_steering.py", "http_client_in_module", "import httpx"),
    ("vr/agents/claim_verifier.py", "http_client_in_module", "import httpx"),
    ("vr/agents/pattern_extractor.py", "http_client_in_module", "import httpx"),
    ("vr/agents/synthesis_agent.py", "http_client_in_module", "import httpx"),
    ("vr/agents/tool_executor.py", "http_client_in_module", "import httpx"),
    ("vr/api_router.py", "http_client_in_module", "import httpx"),
    ("vr/services/cve_intel_resolver.py", "http_client_in_module", "import httpx"),
    ("vr/workflow/finalize.py", "http_client_in_module", "import httpx"),
    ("vr/workflow/task.py", "http_client_in_module", "import httpx"),

    # Category (g): do_nothing_wrapper. Each entry is a public facade kept
    # for API stability and call-site clarity, NOT an oversight.
    # default_task_queue: the module's canonical factory; inlining the
    # TaskQueue(...) constructor at every call site would scatter the
    # module_id binding across 40+ callsites.
    ("malware/_task_queue.py", "default_task_queue", "consider inlining"),
    ("vr/_task_queue.py", "default_task_queue", "consider inlining"),
    # contracts.target_stages.get: typed getattr facade exposed so
    # consumers don't reach into the StageDescriptor internals; the
    # ``return getattr(...)`` is the simplest signature that satisfies
    # the typing contract.
    ("malware/contracts/target_stages.py", "get", "consider inlining"),
    ("vr/contracts/target_stages.py", "get", "consider inlining"),
    # personas.role_notes_for: registry-style lookup facade, two-call
    # path lets the role_notes_for caller stay agnostic of the backing
    # registry shape.
    ("malware/personas/role_notes.py", "role_notes_for", "consider inlining"),
    # mcp_registry.probe_all: tuple wrapper around the iterator return
    # so callers get a stable list[ServerSummary] return type.
    ("malware/services/mcp_registry.py", "probe_all", "consider inlining"),
    ("vr/services/mcp_registry.py", "probe_all", "consider inlining"),
    # disclosure.info: dataclass-like accessor returning the bound
    # DisclosureTrackInfo singleton.
    ("vr/disclosure/base.py", "info", "consider inlining"),
    # fuzz_launcher.serialize_for_log: typed json.dumps wrapper that
    # carries the canonical sort_keys + default kwargs for log payloads.
    ("vr/services/fuzz_launcher.py", "serialize_for_log", "consider inlining"),
    # mcp_adapters_registry.specialized_tools: sorted-tuple accessor
    # exposed for deterministic ordering in dispatch.
    ("platform/mcp/adapters/registry.py", "specialized_tools", "consider inlining"),
    # tasks.all_periodic_sweeps: dict-copy accessor so callers can't
    # mutate the registry by accident.
    ("platform/tasks/sweeps.py", "all_periodic_sweeps", "consider inlining"),

    # Category (f): malware module.py protocol stubs. The ModuleProtocol
    # requires these methods but the malware module legitimately has
    # nothing to add. Documented empty returns are the honest answer;
    # raising NotImplementedError would break the platform's batch
    # iteration over modules.
    ("malware/module.py", "report_filter_keys", "placeholder_return"),
    ("malware/module.py", "health_checks", "placeholder_return"),

    # Category (i): asyncio_in_module. asyncio.to_thread is the standard
    # async-bridge for blocking CPU-heavy work (java decompilation /
    # archive extraction). The platform has no replacement primitive.
    ("malware/services/target_analysis.py", "asyncio_in_module", "asyncio.to_thread"),
    ("vr/services/target_analysis.py", "asyncio_in_module", "asyncio.to_thread"),

    # Category (i): module_imports_session_scope. Sweep services need
    # cross-investigation iteration that the per-row UnitOfWork pattern
    # cannot express; async_session_scope is the only currently-supported
    # primitive for that access pattern. SDA-05 documents the carve-out.
    ("malware/services/stall_recovery.py", "module_imports_session_scope", "async_session_scope"),
    ("vr/services/stall_recovery.py", "module_imports_session_scope", "async_session_scope"),

    # Category (i): VR-specific structural exceptions.
    # pdf_report.py uses raw psycopg for the report-export path -- the
    # writer streams chunks larger than the UnitOfWork session limit
    # and needs raw cursor access.
    ("vr/reporting/pdf_report.py", "direct_db_in_module", "import psycopg"),
    # reverify_investigation: the rate-limited operator-trigger endpoint
    # returns a raw dict because the response shape is unstable across
    # verifier versions and Pydantic projection would lock it in.
    ("vr/api_router.py", "reverify_investigation", "bare_dict_return_endpoint"),
    # disclosure/service.py uses assert as an invariant guard inside
    # an integration with a 3rd-party disclosure tracker; the assert is
    # never reached under normal operation, and stripping under -O is
    # acceptable here (the path is hot-debugger-only).
    ("vr/disclosure/service.py", "'assert'", "in production code"),

    # Category (b): platform audit_mcp bridge dispatch. The 7-action
    # dispatch is the bridge's defining contract -- splitting it into
    # 7 single-action tools would require 7 separate registrations and
    # break the existing operator-side tool registry expectations.
    ("platform/mcp/bridges/audit_mcp.py", "'forward'", "action-dispatch branches"),
]

