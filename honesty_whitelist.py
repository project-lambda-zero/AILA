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

    # Category (g): VRModule.health_checks probes the IDA MCP over HTTP.
    # This is a one-line httpx import inside an async closure, not a general HTTP client.
    ("vr/module.py", "http_client_in_module", "HTTP clients belong to the platform layer"),
]
