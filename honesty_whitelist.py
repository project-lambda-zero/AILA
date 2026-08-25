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
    ("_template/workflow/__init__.py", "state_response_emit", "context"),

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

    # Category (g): bind_index_id is the public seam for the private
    # _bound_index_id_ctx ContextVar -- peer modules (VR tool executor,
    # speculator, claim verifier) bind the resolved audit_mcp index_id
    # without importing the private ContextVar. The returned token is the
    # stdlib ContextVar.set() token consumed by reset_index_id; inlining
    # at call sites would leak the private variable across modules.
    ("middleware/audit.py", "bind_index_id", "inlining"),

    # Category (g): stream_key is the single public accessor for the private
    # _KEY_FMT stream-key format. Inlining it at call sites reinstates the
    # module->platform private-attr coupling the accessor closes (RFC-05).
    ("tasks/progress.py", "stream_key", "inlining"),

    # Category (b): _extra_user_prompt_kwargs is an optional template-method
    # hook on AgentTurnRunnerBase. The base default contributes no extra
    # user-prompt kwargs; VR overrides it to add cve_intel. Empty is real.
    ("agents/turn_runner.py", "_extra_user_prompt_kwargs", "empty dict"),

    # Category (g): encode_case_state is the serialization half of the
    # case-state codec (paired with decode_case_state). Inlining the
    # json.dumps at call sites re-scatters the serialization format the
    # module exists to own as a single source of truth (RFC-03).
    ("agents/turn_helpers.py", "encode_case_state", "inlining"),

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
    # body_size_limit wraps an arbitrary downstream ASGI app; once the body
    # is force-disconnected over the limit, the app can raise any type. The
    # catch re-raises when the request did not overflow, so real faults still
    # propagate -- only truncation-induced exceptions are suppressed.
    ("api/middleware/body_size_limit.py", "broad_exception_catch", "catches everything"),
    ("api/routers/dashboard.py", "broad_exception_catch", "catches everything"),
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
    ("platform/tasks/sweeps.py", "broad_exception_catch", "catches everything"),
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

    # platform/apk/apk_signing._read_apk_layout: a malformed / zip64 / non-APK
    # file returns None, which parse_signing surfaces as a fail-closed
    # signature_verified=False plus a concrete verification_reason. The empty
    # return is the fail-closed security contract, not a swallow.
    ("platform/apk/apk_signing.py", "except_return_default", "silently hides failures"),

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
    ("vr/agents/narrative_agent.py", "http_client_in_module", "import httpx"),
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
    # forensics/_task_queue.default_task_queue: introduced in #18
    # alongside the panel spine so persona_spawn (which enqueues sibling
    # branch worker tasks) has a factory to bind ConfigRegistry +
    # module_id at. Same public facade shape as vr / malware; inlining
    # would scatter the module_id binding across every panel spawn site.
    ("forensics/_task_queue.py", "default_task_queue", "consider inlining"),
    # _template/_task_queue.default_task_queue: same public factory shape
    # as vr / malware / forensics; the scaffold ships it so a copier's
    # ``from aila.modules.<mod>._task_queue import default_task_queue``
    # site keeps working after the rename, without scattering the
    # ConfigRegistry + module_id binding across every callsite.
    ("_template/_task_queue.py", "default_task_queue", "consider inlining"),
    # _template/workflow/finalize.finalize_investigation: template ships a
    # NO-OP finalize chokepoint (a copier wires the four-trigger detector).
    # The single ``return FinalizeResult(no_trigger)`` is deliberate --
    # inlining at the emit call site would force every copier to
    # rediscover the FinalizeResult shape instead of extending the seed.
    ("_template/workflow/finalize.py", "finalize_investigation", "consider inlining"),
    # _template/workflow/services.TemplateWorkflowServices.build: the
    # per-run services factory shape mandated by the WorkflowServices
    # protocol (D-15 freshness contract). Same shape as vr / malware
    # BuildableServices.build; inlining at the definition site would
    # violate the factory-per-run contract.
    ("_template/workflow/services.py", "build", "consider inlining"),
    # platform/contracts/target_stages.get: typed getattr facade exposed so
    # consumers don't reach into the StageDescriptor internals; the
    # ``return getattr(...)`` is the simplest signature that satisfies
    # the typing contract.
    ("platform/contracts/target_stages.py", "get", "consider inlining"),
    # personas.role_notes_for: registry-style lookup facade, two-call
    # path lets the role_notes_for caller stay agnostic of the backing
    # registry shape.
    ("malware/personas/role_notes.py", "role_notes_for", "consider inlining"),
    # mcp_registry.probe_all: tuple wrapper around the iterator return
    # so callers get a stable list[ServerSummary] return type. Lifted to
    # the platform base in RFC-04 Phase 1; the module subclasses inherit it.
    ("platform/mcp/registry.py", "probe_all", "consider inlining"),
    # reasoning.StrategyRegistry.sorted_declarations: public accessor that
    # hides the private _by_family dict and owns the (match_priority,
    # family) classification order consumed by select_strategy_family.
    # Inlining would leak the registry's internal representation into the
    # reasoning engine (RFC-05 crit 6). Same stable-return-type shape as
    # probe_all above.
    ("platform/services/reasoning.py", "sorted_declarations", "consider inlining"),
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
    # RFC-02 Phase 2: module bindings of the shared platform investigation
    # summary builder. Each supplies only its own *InvestigationSummary
    # contract class; keeping the facade leaves the ~10 call sites per
    # module unchanged (list, detail, and every lifecycle handler return).
    ("vr/api_router.py", "_investigation_summary", "consider inlining"),
    ("malware/api_router.py", "_investigation_summary", "consider inlining"),

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

    # Category (b): RFC-11 Tier C -- the audit-mcp MIDDLEWARE forward is a
    # verbatim port of the old bridge's multi-action dispatch (its defining
    # contract; splitting into single-action tools would break the operator
    # tool registry). The read_function not-indexed auto-fallback chain
    # nests a readability-flagged ``if`` that stays as a faithful port.
    ("platform/mcp/middleware/audit.py", "'forward'", "action-dispatch branches"),
    ("platform/mcp/middleware/audit.py", "nested if with no else", "combine with 'and'"),

    # Category (b): current_team_context() is the typed public accessor for
    # the ambient TeamContext ContextVar (#53). Inlining ``_CURRENT_TEAM_CONTEXT.get()``
    # at every call site would leak the private module-level ContextVar into
    # the public API surface (async_session_scope, UnitOfWork, tests) and
    # break the type contract -- the ContextVar stores ``object | None`` to
    # avoid a circular import; the wrapper re-attaches the ``TeamContext``
    # type. It is the single import boundary tests can monkeypatch.
    ("platform/services/team_scope.py", "current_team_context", "inlining"),

    # ------------------------------------------------------------------
    # Category (h): except_return_default residual after rule 25 tightening.
    # Each site is a documented fail-closed / coerce path where the
    # empty return is the public contract, not a swallow.
    # ------------------------------------------------------------------
    # api/sse_gate._current_active_sse: Prometheus internal-attr fallback.
    # Returns 0 when both the fast ``Gauge._value.get()`` path AND the
    # slower ``collect()`` fallback fail; 0 means "no live SSE streams"
    # which is the fail-closed answer for the cap check (never denies
    # a new connection on a bad reading).
    ("api/sse_gate.py", "except_return_default",
     "silently hides failures"),
    # vr/tools/poc_runner.run_dir_of: PurePosixPath.relative_to raises
    # ValueError when the path is outside _REMOTE_DIR; the None return
    # signals "no per-run parent to clean up", which callers handle.
    ("vr/tools/poc_runner.py", "except_return_default",
     "silently hides failures"),

    # Category (b): PromptRegistry.load is the sync file-backed entry
    # point paired with async ``resolve()`` (DB-then-file). Inlining
    # ``_resolve_from_file(...)`` at call sites would scatter the
    # sync/async split contract that PromptRegistry exists to enforce.
    ("platform/prompts/registry.py", "load",
     "consider inlining"),

    # Category (b): RFC-09 activation bootstrap. seed_prompt_versions sets the
    # production alias ONLY when the key has none yet (alias-if-absent). It
    # establishes the initial file baseline, never promotes a candidate over
    # an existing baseline, so there is nothing to eval against. The RFC-10
    # gate (AgentLifecycleController.promote) governs candidate promotions and
    # requires eval evidence that does not exist at first-boot bootstrap.
    ("vr/agents/vuln_researcher.py", "seed_prompt_versions",
     "promotion_without_gate"),
    ("malware/agents/malware_researcher.py", "seed_prompt_versions",
     "promotion_without_gate"),
    ("forensics/agents/investigator.py", "seed_prompt_versions",
     "promotion_without_gate"),

    # Category (b): rule 68 content_slice_truncation. These cap the query
    # string written to an AUDIT-LOG detail field (record_audit_event
    # details), not knowledge-base content. The audit row is a bounded
    # metadata record, so a 200-char query snippet is the intended shape --
    # no stored or retrieved knowledge data is trimmed here.
    ("api/routers/scans.py", "_audit", "[:200]"),
    ("api/routers/tasks.py", "_audit_submit", "[:200]"),

    # Category (g): rule 54 heal_without_journal. The three module
    # re-enqueue HTTP endpoints below are thin dispatchers that call the
    # platform lifecycle service ``reenqueue_investigation``. The
    # underlying service now emits the durable RFC-07 recovery event on
    # every successful re-enqueue, so a second journal call from the
    # router would just duplicate the same ledger row. Narrow per-
    # function exemption (RFC-07 #31 pattern) rather than a blanket file
    # exemption in _JOURNAL_SELF_EXEMPT_SUFFIXES; a router that grows a
    # NEW mutation path must journal that path directly.
    ("_template/api_router.py", "reenqueue_template_investigation",
     "heal_without_journal"),
    ("malware/api_router.py", "reenqueue_investigation",
     "heal_without_journal"),
    ("vr/api_router.py", "reenqueue_investigation",
     "heal_without_journal"),

    # Category (g): rule do_nothing_wrapper. RFC #153 RetrieverBackend
    # Protocol impl. ``availability`` is the concrete local-backend
    # implementation of the abstract async availability() contract
    # (always-available, cost 0); it is the interface method, not a
    # forwarding wrapper. Inlining would erase the Protocol seam that
    # lets voyage/jina/qwen backends report unconfigured.
    ("eval/retrieval_bench.py", "availability", "consider inlining"),
    # Category (a): rule unused_parameter. ``_embed`` is the abstract
    # embedding hook on the rerank-backend base -- it raises
    # NotImplementedError and its (query, docs) params define the
    # contract every concrete backend overrides. The params are the
    # signature, not dead locals.
    ("eval/retrieval_bench.py", "_embed", "query"),
    ("eval/retrieval_bench.py", "_embed", "docs"),

    # Category (g): rule do_nothing_wrapper. RFC #155 PromptLayoutBuilder
    # fluent API. add_immutable / add_mutable / build are the builder's
    # public surface (each returns the accumulated layout); inlining the
    # single-line bodies at call sites reinstates the manual segment
    # bookkeeping the builder exists to hide.
    ("llm/prompt_layout.py", "add_immutable", "consider inlining"),
    ("llm/prompt_layout.py", "add_mutable", "consider inlining"),
    ("llm/prompt_layout.py", "build", "consider inlining"),

    # Category: rule 68 content_slice_truncation. RFC #149 auto-patch.
    # These two caps bound LLM-SYNTHESIS PROMPT INPUT, not stored or
    # retrieved knowledge. root_cause[:8000] and the source-context
    # content[:16000] are fed straight into the patch-coder model's
    # prompt; the PlatformPatchAttemptRecord table has no root_cause /
    # source-content column, so nothing persisted is trimmed. Bounding
    # the prompt is required to keep the synth call inside context.
    ("vr/workflow/task.py", "_run_vr_auto_patch", "[:8000]"),
    ("vr/workflow/task.py", "_fetch_vr_source_ctx", "[:16000]"),

    # ------------------------------------------------------------------
    # req 25 -- dante console conversational agent.
    # ------------------------------------------------------------------
    # api/routers/sessions.py::_decode_actions: parses the persisted
    # ``actions_json`` blob for the response serializer. NULL / blank /
    # malformed values MUST degrade to an empty list because the frontend
    # treats "no proposed actions" as the same shape regardless of source;
    # an assistant reply with unparseable actions is still a valid message.
    ("api/routers/sessions.py", "except_return_default",
     "silently hides failures"),
]


# ---------------------------------------------------------------------------
# Orphan-export allowlist (advisory ``--orphans`` cross-file report).
#
# Each entry is a (filename_suffix, exported_name) pair.  The report
# prints every name in a module's ``__all__`` with no importer elsewhere
# under the audit root (``src/aila``); this list suppresses names that
# ARE legitimately part of the public API but are only consumed from
# outside the audited tree (tests/, scripts/, external SDK users).
# See the top of ``src/aila/tools/honesty_audit.py`` for the full
# semantics.  The pass is advisory and never blocks CI, so an entry
# here is a documentation aid rather than a hard requirement.
# ---------------------------------------------------------------------------

HONESTY_ORPHAN_ALLOWLIST = [
    # The auditor's own public API. HonestyAuditor is imported by
    # src/aila/tools/__init__.py; every other name is consumed only by
    # tests/ (test_honesty_audit.py, test_module_standards_compliance.py,
    # test_honesty_guardrails_rfc.py, ...).
    ("tools/honesty_audit.py", "Finding"),
    ("tools/honesty_audit.py", "ImportGraph"),
    ("tools/honesty_audit.py", "OrphanFinding"),
    ("tools/honesty_audit.py", "build_import_graph"),
    ("tools/honesty_audit.py", "load_orphan_allowlist"),
    ("tools/honesty_audit.py", "load_whitelist"),
    # HONESTY_WHITELIST is the whitelist binding itself; it is read
    # via AST by load_whitelist, never via `from ... import`.
    ("tools/honesty_whitelist.py", "HONESTY_WHITELIST"),
]

