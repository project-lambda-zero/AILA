"""Honesty audit whitelist — central registry for accepted rule suppressions.

Each entry is a tuple of (filename_suffix, rule_id, justification):
  - filename_suffix: matches the END of the file path (forward slashes; cross-platform).
  - rule_id:         the linter/audit rule identifier (e.g., "BLE001", "E712", "PLC0415", "N802").
  - justification:   human-readable reason the suppression is accepted.

Validation contract:
  - Every entry MUST have exactly 3 elements.
  - All three elements MUST be non-empty strings.
  - Entries violating this contract raise ValueError at import time (enforces honesty).

Maintenance:
  - To add a new suppression: append a tuple here with a meaningful justification.
  - To remove a suppression: delete the tuple and fix the underlying code.
  - Do NOT add # noqa: <rule> inline in source files — use this registry instead.
"""

from __future__ import annotations


def _validate(entries: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """Validate all whitelist entries at import time.

    Raises ValueError if any entry has wrong arity or empty strings.
    This prevents silently adding unreviewed suppressions.
    """
    for i, entry in enumerate(entries):
        if not isinstance(entry, tuple) or len(entry) != 3:
            raise ValueError(
                f"HONESTY_WHITELIST[{i}] must be a 3-element tuple, got: {entry!r}"
            )
        if not all(isinstance(s, str) and s for s in entry):
            raise ValueError(
                f"HONESTY_WHITELIST[{i}] all elements must be non-empty strings, got: {entry!r}"
            )
    return entries


HONESTY_WHITELIST: list[tuple[str, str, str]] = _validate([

    # ---------------------------------------------------------------------------
    # N802 — function name not lowercase
    # These are required by ast.NodeVisitor which mandates visit_<NodeType> names.
    # ---------------------------------------------------------------------------
    (
        "aila/tools/honesty_audit.py",
        "N802",
        "ast.NodeVisitor interface mandates visit_ClassDef, visit_FunctionDef, "
        "visit_AsyncFunctionDef as PascalCase method names; renaming would break "
        "the NodeVisitor dispatch protocol",
    ),

    # ---------------------------------------------------------------------------
    # BLE001 — broad exception catches at isolation boundaries
    # Each site is the outermost handler for an unbounded call surface.
    # Narrowing is not feasible because the raise surface is unbounded.
    # ---------------------------------------------------------------------------
    (
        "aila/api/routers/health.py",
        "BLE001",
        "BOUNDARY: health.py catch-all at line 192 wraps arbitrary module.health_check() "
        "callables — modules can raise any exception type. Catching Exception here prevents "
        "one broken module from killing the health endpoint for all others. "
        "_log.exception() preserves the trace for audit.",
    ),
    (
        "aila/api/routers/health.py",
        "BLE001",
        "BOUNDARY: health.py catch-all at line 238 is the same pattern — outermost guard "
        "for dynamic module health callables whose raise surface is unbounded.",
    ),
    (
        "aila/modules/vulnerability/adapters/ghsa.py",
        "BLE001",
        "BOUNDARY: __del__ destructor — silent cleanup is idiomatic in Python destructors. "
        "Propagating exceptions from __del__ causes RuntimeError and is explicitly warned "
        "against in CPython docs. The resource is best-effort closed.",
    ),
    (
        "aila/modules/vulnerability/providers/_base_client.py",
        "BLE001",
        "BOUNDARY: __del__ destructor — same rationale as ghsa.py: silent cleanup in "
        "__del__ is idiomatic; exceptions from __del__ propagate as RuntimeError warnings.",
    ),
    (
        "aila/platform/llm/client.py",
        "BLE001",
        "BOUNDARY: Prometheus counter increment — PrometheusException hierarchy is not "
        "documented and can vary by registry state; broad catch prevents metric errors "
        "from surfacing to the caller. Failures are suppressed silently (counter is "
        "best-effort instrumentation, not business logic).",
    ),
    (
        "aila/platform/workflows/engine.py",
        "BLE001",
        "BOUNDARY: ARQ worker outermost BaseException handler at line 569 — the ARQ "
        "job runner submits arbitrary async callables and cannot know their raise surface. "
        "Catching BaseException here prevents worker death on unexpected errors. "
        "_log.exception() preserves the full trace. Narrower types are not feasible.",
    ),

    # ---------------------------------------------------------------------------
    # E712 — comparison to True/False using == instead of is
    # SQLAlchemy ORM column expressions (col == True) produce a SQL boolean clause,
    # not a Python equality. Using `is True` would produce a Python bool, breaking
    # the SQL query generation. Each entry cites the exact model and column.
    # ---------------------------------------------------------------------------

    # api/routers/notifications.py — NotificationRecord.is_read
    (
        "aila/api/routers/notifications.py",
        "E712",
        "SQLAlchemy column expression: NotificationRecord.is_read == False produces "
        "a SQL WHERE clause (col IS FALSE / col = FALSE), not a Python bool comparison. "
        "Replacing with `is False` would break ORM query generation.",
    ),

    # api/routers/oidc.py — OIDCProviderRecord.is_enabled
    (
        "aila/api/routers/oidc.py",
        "E712",
        "SQLAlchemy column expression: OIDCProviderRecord.is_enabled == True produces "
        "a SQL WHERE clause; `is True` would break ORM query generation.",
    ),

    # api/routers/saved_filters.py — SavedFilterRecord.shared_with_team
    (
        "aila/api/routers/saved_filters.py",
        "E712",
        "SQLAlchemy column expression: SavedFilterRecord.shared_with_team == True "
        "produces a SQL WHERE clause; `is True` would break ORM query generation.",
    ),


    (
        "aila/modules/vulnerability/api_router.py",
        "E712",
        "SQLAlchemy column expression: LatestFindingRecord.is_kev == True produces "
        "a SQL WHERE clause; `is True` would break ORM query generation.",
    ),

    # platform/automation/runner.py — AutomationScheduleRecord.enabled
    (
        "aila/platform/automation/runner.py",
        "E712",
        "SQLAlchemy column expression: AutomationScheduleRecord.enabled == True produces "
        "a SQL WHERE clause; `is True` would break ORM query generation.",
    ),

    # ---------------------------------------------------------------------------
    # PLC0415 — import not at top-level of file
    # All entries below are genuine circular-import deferrals or intentional
    # lazy-load patterns (startup functions, optional dependencies, script CLI).
    # The per-file-ignores in pyproject.toml suppresses ruff for these files;
    # this whitelist documents the justification for the honesty audit.
    # ---------------------------------------------------------------------------

    # api/app.py — lazy router imports inside factory/startup functions
    (
        "aila/api/app.py",
        "PLC0415",
        "Intentional lazy-load pattern: routers are imported inside startup/factory "
        "functions to avoid circular imports at module load time (app.py is the root "
        "module that assembles all routers; importing routers at top-level would cause "
        "circular dependencies through the platform singleton).",
    ),

    # api/deps.py — lazy platform imports
    (
        "aila/api/deps.py",
        "PLC0415",
        "Intentional lazy-load: platform dependencies imported inside FastAPI Depends "
        "functions to avoid circular import at module load time.",
    ),

    # api/routers/* — lazy platform/storage imports in endpoint handlers
    (
        "aila/api/routers/cost.py",
        "PLC0415",
        "Intentional lazy-load: storage model imported inside endpoint function to avoid "
        "circular import through api -> platform -> storage -> api chain.",
    ),
    (
        "aila/api/routers/dashboard.py",
        "PLC0415",
        "Intentional lazy-load: platform service imported inside endpoint function to "
        "break circular import chain.",
    ),
    (
        "aila/api/routers/health.py",
        "PLC0415",
        "Intentional lazy-load: module registry imported inside startup check to avoid "
        "circular import at module load time.",
    ),
    (
        "aila/api/routers/scans.py",
        "PLC0415",
        "Intentional lazy-load: platform import inside endpoint handler to break circular "
        "import chain.",
    ),
    (
        "aila/api/routers/systems.py",
        "PLC0415",
        "Intentional lazy-load: storage models imported inside endpoint handlers to break "
        "circular import chain.",
    ),

    # api/schemas/cost.py
    (
        "aila/api/schemas/cost.py",
        "PLC0415",
        "Intentional lazy-load: model import inside schema method to break circular "
        "import chain.",
    ),

    # cli.py — click command functions with lazy imports
    (
        "aila/cli.py",
        "PLC0415",
        "Intentional lazy-load in CLI command functions: importing heavy platform modules "
        "at top-level would slow down all CLI invocations including --help. Each command "
        "imports only what it needs at invocation time.",
    ),

    # modules/_template/module.py — template module lazy imports
    (
        "aila/modules/_template/module.py",
        "PLC0415",
        "Intentional lazy-load in module template: db_models and tool imports deferred "
        "inside methods to break circular import cycle: module.py -> db_models.py -> "
        "module.py (db_models imports from module for forward references).",
    ),

    # modules/hello_world/module.py
    (
        "aila/modules/hello_world/module.py",
        "PLC0415",
        "Intentional lazy-load: db_models import deferred inside method to break "
        "circular import cycle (module -> db_models -> module).",
    ),


    (
        "aila/modules/vulnerability/adapters/arch.py",
        "PLC0415",
        "Intentional lazy-load: sqlmodel and db_model imports deferred inside adapter "
        "methods to break circular import cycle (arch.py -> db_models.py -> arch.py "
        "via advisory_tool references).",
    ),

    # modules/vulnerability/adapters/ghsa.py
    (
        "aila/modules/vulnerability/adapters/ghsa.py",
        "PLC0415",
        "Intentional lazy-load: httpx import deferred inside request method to avoid "
        "import-time side effects and break circular import through platform client chain.",
    ),

    # modules/vulnerability/evidence_validator.py
    (
        "aila/modules/vulnerability/evidence_validator.py",
        "PLC0415",
        "Intentional lazy-load: pydantic model import deferred inside validation function "
        "to break circular import cycle (evidence_validator -> db_models -> evidence_validator).",
    ),

    # modules/vulnerability/module.py — large module with deferred db_model imports
    (
        "aila/modules/vulnerability/module.py",
        "PLC0415",
        "Intentional lazy-load: sqlmodel and db_model imports deferred inside async "
        "query functions to break circular import cycle: module.py -> db_models.py -> "
        "module.py (db_models imports tools/definitions from module package). "
        "Also: tool and reporting imports deferred in route_specs/health_check to avoid "
        "premature initialization before platform is ready.",
    ),

    # modules/vulnerability/reporting/pdf.py
    (
        "aila/modules/vulnerability/reporting/pdf.py",
        "PLC0415",
        "Intentional lazy-load: weasyprint, jinja2, and db_model imports deferred inside "
        "render functions — weasyprint is an optional heavy dependency; db_model import "
        "breaks circular import cycle (pdf.py -> db_models.py -> pdf.py via "
        "PrioritizedFindingRecord references).",
    ),

    # modules/vulnerability/tools/* — all tool files use lazy db_model imports
    (
        "aila/modules/vulnerability/tools/asset_tags.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle (tools -> db_models -> tools via tool registry).",
    ),
    (
        "aila/modules/vulnerability/tools/baseline.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/blast_radius.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/cve_arrivals.py",
        "PLC0415",
        "Intentional lazy-load: sqlmodel Session and select imported inside sync query "
        "functions to break circular import cycle: cve_arrivals.py -> db_models.py -> "
        "cve_arrivals.py (db_models imports LatestFindingRecord from same package). "
        "Comment in source says: 'local to avoid circular'.",
    ),
    (
        "aila/modules/vulnerability/tools/heat_map.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/intel_cache.py",
        "PLC0415",
        "Intentional lazy-load: db_model and sqlmodel imports deferred inside cache "
        "functions to break circular import cycle (intel_cache -> db_models -> "
        "intel_cache via CVEKnowledge model references).",
    ),
    (
        "aila/modules/vulnerability/tools/inventory_drift.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/kb_insights.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/mttr.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/patch_playbook.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/peer_compare.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/profiles.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/remediation.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/risk_posture.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/scheduled_scans.py",
        "PLC0415",
        "Intentional lazy-load: db_model and sqlmodel imports deferred inside scheduler "
        "functions to break circular import cycle (scheduled_scans -> db_models -> "
        "scheduled_scans via scan record references).",
    ),
    (
        "aila/modules/vulnerability/tools/scoring_audit.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/scoring_policy.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/service_check.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/sla_breach.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/tag_risk.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/verify_remediation.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),
    (
        "aila/modules/vulnerability/tools/what_if.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside tool function to break "
        "circular import cycle.",
    ),

    # modules/vulnerability/workflow/utils/row_helpers.py
    (
        "aila/modules/vulnerability/workflow/utils/row_helpers.py",
        "PLC0415",
        "Intentional lazy-load: db_model import deferred inside helper function to break "
        "circular import cycle (row_helpers -> db_models -> workflow -> row_helpers).",
    ),

    # platform/contracts/persist.py
    (
        "aila/platform/contracts/persist.py",
        "PLC0415",
        "Intentional lazy-load: storage import deferred inside protocol method to break "
        "circular import cycle (contracts -> storage -> contracts via persist protocol).",
    ),

    # platform/events/emitter.py
    (
        "aila/platform/events/emitter.py",
        "PLC0415",
        "Intentional lazy-load: storage and redis imports deferred inside emit methods "
        "to break circular import cycle (emitter -> storage -> emitter via event records).",
    ),

    # platform/llm/* — heavy LLM platform files
    (
        "aila/platform/llm/classify.py",
        "PLC0415",
        "Intentional lazy-load: OmniRoute client import deferred inside classification "
        "function to avoid import-time HTTP client initialization.",
    ),
    (
        "aila/platform/llm/client.py",
        "PLC0415",
        "Intentional lazy-load: heavy LLM provider imports deferred inside initialization "
        "to allow client to load without all providers installed.",
    ),
    (
        "aila/platform/llm/config.py",
        "PLC0415",
        "Intentional lazy-load: config import deferred inside config method to break "
        "circular import cycle (llm.config -> platform.config -> llm.config).",
    ),
    (
        "aila/platform/llm/drift.py",
        "PLC0415",
        "Intentional lazy-load: storage model imports deferred inside drift detection "
        "functions to break circular import cycle.",
    ),
    (
        "aila/platform/llm/gate.py",
        "PLC0415",
        "Intentional lazy-load: consensus client import deferred to avoid import-time "
        "initialization of HTTP connections.",
    ),
    (
        "aila/platform/llm/seal.py",
        "PLC0415",
        "Intentional lazy-load: cryptography and storage imports deferred inside seal/unseal "
        "functions to break circular import cycle and avoid heavy import at module load.",
    ),
    (
        "aila/platform/llm/validate.py",
        "PLC0415",
        "Intentional lazy-load: pydantic model import deferred inside validation function "
        "to break circular import cycle.",
    ),
    (
        "aila/platform/llm/verify.py",
        "PLC0415",
        "Intentional lazy-load: storage and HTTP client imports deferred inside "
        "verification functions to break circular import cycle.",
    ),

    # platform/modules/builtin.py and platform.py
    (
        "aila/platform/modules/builtin.py",
        "PLC0415",
        "Intentional lazy-load: module factory imports deferred inside factory functions "
        "to allow platform to load without all module packages installed (optional modules).",
    ),
    (
        "aila/platform/modules/platform.py",
        "PLC0415",
        "Intentional lazy-load: module-specific imports deferred inside platform methods "
        "to break circular import cycle (platform -> modules -> platform via module registration).",
    ),
    (
        "aila/platform/modules/registry.py",
        "PLC0415",
        "Intentional lazy-load: module import deferred inside registry method to allow "
        "lazy module resolution.",
    ),

    # platform/runtime/builder.py
    (
        "aila/platform/runtime/builder.py",
        "PLC0415",
        "Intentional lazy-load: platform service import deferred inside builder function "
        "to break circular import cycle (builder -> services -> builder via runtime).",
    ),

    # platform/services/*
    (
        "aila/platform/services/embedding.py",
        "PLC0415",
        "Intentional lazy-load: sentence_transformers import deferred inside embedding "
        "function — optional heavy ML dependency; module remains importable without it.",
    ),
    (
        "aila/platform/services/knowledge.py",
        "PLC0415",
        "Intentional lazy-load: storage model import deferred inside knowledge service "
        "method to break circular import cycle.",
    ),
    (
        "aila/platform/services/report.py",
        "PLC0415",
        "Intentional lazy-load: jinja2/reporting imports deferred inside report generation "
        "functions to allow service to load without all reporting dependencies installed.",
    ),
    (
        "aila/platform/services/system.py",
        "PLC0415",
        "Intentional lazy-load: storage model imports deferred inside system service "
        "methods to break circular import cycle.",
    ),

    # platform/tasks/*
    (
        "aila/platform/tasks/hooks.py",
        "PLC0415",
        "Intentional lazy-load: platform service and storage imports deferred inside "
        "task hook functions to break circular import cycle (hooks -> tasks -> hooks "
        "via task queue references).",
    ),
    (
        "aila/platform/tasks/queue.py",
        "PLC0415",
        "Intentional lazy-load: ARQ and storage imports deferred inside queue methods "
        "to break circular import cycle (queue -> worker -> queue via ARQ settings).",
    ),
    (
        "aila/platform/tasks/template.py",
        "PLC0415",
        "Intentional lazy-load: platform service and storage imports deferred inside "
        "task template decorator to break circular import cycle (template -> platform -> "
        "template via task registration).",
    ),
    (
        "aila/platform/tasks/worker.py",
        "PLC0415",
        "Intentional lazy-load: platform runtime imports deferred inside worker startup "
        "function to break circular import cycle (worker -> platform -> worker via ARQ).",
    ),

    # platform/tools/knowledge.py
    (
        "aila/platform/tools/knowledge.py",
        "PLC0415",
        "Intentional lazy-load: sentence_transformers import deferred inside embedding "
        "function — optional heavy ML dependency.",
    ),

    # storage/*
    (
        "aila/storage/operations.py",
        "PLC0415",
        "Intentional lazy-load: db_model imports deferred inside storage operation "
        "functions to break circular import cycle (operations -> db_models -> operations).",
    ),
    (
        "aila/storage/registry.py",
        "PLC0415",
        "Intentional lazy-load: db_model imports deferred inside registry methods to "
        "break circular import cycle.",
    ),
    (
        "aila/storage/secrets.py",
        "PLC0415",
        "Intentional lazy-load: platform import deferred inside secret resolution to "
        "break circular import cycle (secrets -> platform -> secrets via config).",
    ),

    # -------------------------------------------------------------------------
    # Rule 18: asyncio_in_module — designated threading bridge files
    #
    # These files ARE the threading boundary for their respective sync libraries.
    # They expose async def wrappers to callers; the asyncio.to_thread call is
    # correctly placed here, not in their callers. Documented in 183-08-BOUNDARY-MAP.md.
    # -------------------------------------------------------------------------
    (
        "aila/modules/vulnerability/adapters/ghsa.py",
        "asyncio_in_module",
        "threading belongs to the platform layer",
        # Designated bridge: wraps sync GHSA/httpx client for async callers.
        # async_lookup_for_packages correctly isolates asyncio.to_thread here.
    ),
    (
        "aila/modules/vulnerability/providers/osv.py",
        "asyncio_in_module",
        "threading belongs to the platform layer",
        # Designated bridge: wraps sync OSV/httpx client for async callers.
        # async query/extract/get methods correctly isolate asyncio.to_thread here.
    ),
    (
        "aila/modules/vulnerability/reporting/pdf.py",
        "asyncio_in_module",
        "threading belongs to the platform layer",
        # Designated bridge: wraps sync weasyprint for async callers.
        # render_bytes_async correctly isolates asyncio.to_thread here.
    ),
])

__all__ = ["HONESTY_WHITELIST"]
