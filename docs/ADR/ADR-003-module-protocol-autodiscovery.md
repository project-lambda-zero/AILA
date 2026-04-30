# ADR-003: Module Protocol and Auto-Discovery Pattern

**Status:** Accepted
**Date:** 2025 (v1.5), updated v1.7
**Supersedes:** None

## Context

AILA is designed as a modular security platform where feature modules (vulnerability scanning,
compliance checking, etc.) can be added without modifying platform code. The platform needs to:

- Discover modules at startup
- Mount module-owned HTTP routes
- Delegate domain operations (system summaries, findings, reports) to the correct module
- Enforce auth on all module endpoints without per-module auth wiring

Options considered:

1. **Plugin registry with explicit registration** -- Modules call `platform.register(self)` at
   import time. Fragile ordering, import-time side effects.
2. **Filesystem discovery with naming convention** -- Scan `modules/` for `module.py` files.
   Implicit, hard to control ordering.
3. **Factory-based discovery with protocol interface** -- Each module provides a factory function;
   platform iterates factories and calls protocol methods. Explicit, testable, no import-time
   side effects.

## Decision

Use a **protocol-based module interface** (`ModuleProtocol`) with **factory-based auto-discovery**.

### ModuleProtocol

Every module implements `ModuleProtocol` (defined in `platform/modules/protocol.py`):

```
module_id: str                          -- Unique identifier (e.g., "vulnerability")
route_specs() -> list[ModuleRouteSpec]  -- HTTP routes this module owns
system_summary(system_id) -> dict       -- Module-specific data for a system
system_findings(system_id) -> list      -- Module-specific findings for a system
report_count(run_id) -> int             -- Count of report items for a run
health_checks() -> dict                 -- Module health status
register_tools(tool_registry, ...)      -- Register tools, config schemas, DB models
seed_data() -> None                     -- Seed initial data (with version tracking)
report_filter_keys() -> list[str]       -- Valid filter keys for reports
filter_report_rows(rows, filters) -> list -- Apply module-specific report filters
```

All optional methods have safe defaults (empty lists, zero counts, etc.) so modules
only implement what they need.

### ModuleRouteSpec

Each module declares its HTTP surface via `route_specs()`:

```
prefix: str                             -- URL prefix (e.g., "/vulnerability")
router_factory: Callable[[], APIRouter]  -- Returns a configured FastAPI router
```

Tags and dependencies are NOT part of ModuleRouteSpec -- tags are router-owned,
auth dependencies are platform-owned (applied uniformly by the platform at mount time).

### Auto-discovery

1. `builtin_module_factories()` returns a list of factory callables (one per module)
2. `_mount_module_routers()` in `app.py` iterates factories, calls `route_specs()`,
   and mounts each router with `dependencies=[Depends(require_api_key)]`
3. If a module factory raises during `route_specs()`, that module is skipped with a
   warning -- the platform continues starting

### Auth enforcement

The platform applies `Depends(require_api_key)` at mount time for every module router.
Modules never wire their own auth -- this prevents the pitfall where a developer forgets
to add auth to internal routes (Pitfall 5).

## Consequences

### Positive

- Adding a module requires zero platform code changes
- Auth is guaranteed on all module endpoints (platform-enforced)
- Each module owns its domain logic entirely (reports, findings, summaries)
- Safe defaults mean a minimal module only needs `module_id` and `route_specs()`
- Module isolation: one module failing at startup does not break others

### Negative

- Protocol is not formally enforced by Python's type system at runtime (duck typing)
- All modules loaded at startup even if unused (acceptable for <10 modules)

### Neutral

- `_template/` module provides a scaffold matching the protocol
- `hello_world/` module serves as a minimal working example
- `MODULE_STANDARD.md` documents the canonical module shape

## References

- `src/aila/platform/modules/protocol.py` -- ModuleProtocol, ModuleRouteSpec
- `src/aila/platform/modules/builtin.py` -- builtin_module_factories()
- `src/aila/api/app.py` -- _mount_module_routers()
- `src/aila/modules/vulnerability/module.py` -- Full module implementation
- `src/aila/modules/hello_world/` -- Minimal module example
- `docs/MODULE_STANDARD.md` -- Module authoring standard
- Phase 85: ModuleProtocol defaults review
- Phase 92: hello_world and _template deep review
