# Module Development Standard (v2)

This document defines the required structure and contract for every feature module under `src/aila/modules`.

**Version:** 2.1 (updated 2026-04-07)
**Previous:** v1 (2026-04-03)

If a module does not match this standard, runtime discovery fails fast at platform boot.

## Required Directory Layout

For a module package `src/aila/modules/<module_id>/`:

```text
<module_id>/
  __init__.py
  module.py
  runtime.py
  capabilities.py
  api_router.py         # Optional: module HTTP routes for frontend/API surface
  workflow.py           # Simple modules: single file
  workflow/             # Complex state machines: package (alternative to workflow.py)
    __init__.py
    models.py
    orchestrator.py
    planning.py
    helpers.py
    states/
      __init__.py
      analysis.py
      reporting.py
      lookup.py
    utils/
      ...
  tool_keys.py
  contracts/
    __init__.py
  tools/
    __init__.py
  services/
    __init__.py
  reporting/
    __init__.py
```

**Workflow Implementation Options:** Simple feature modules use `workflow.py` (single file). Modules with multi-stage state machines may use a `workflow/` package instead. If using a package, `workflow/__init__.py` must re-export `AnalysisWorkflow` (or the equivalent class) so external callers continue to use `from module.workflow import AnalysisWorkflow` without knowing the internal structure.

## Required Module Contract

`module.py` must expose:

```python
def create_module() -> ModuleProtocol:
    ...
```

Rules:
- `create_module` must be zero-argument.
- It must return an object implementing `ModuleProtocol`.
- Returned `module_id` must match folder name `<module_id>`.

## Module Discovery

The platform auto-discovers feature modules by scanning
`src/aila/modules/` with `pkgutil.iter_modules`:

- Only sub-packages are considered (a bare `.py` file under `modules/` is
  ignored).
- Packages whose short name starts with `_` are skipped (this is how
  `_template` is excluded from the live registry).
- The synthetic `PlatformModule` is always first, then feature modules
  follow in filesystem (alphabetical) order.
- Each discovered package is passed through `build_module_factory()`,
  which calls `validate_module_layout()` before returning the
  `create_module` callable.

There is no central manifest to edit. Drop a new package under
`src/aila/modules/<your_module>/` that satisfies the required layout and
the platform picks it up at the next boot.

If the module's `create_module()` raises or fails validation, the
platform logs a WARNING (`Module '<id>' failed validation -- disabled`)
and continues startup with reduced functionality rather than crashing.
The discovery code catches `(AILAError, ValueError)` specifically -- bare
`except Exception` is banned everywhere, including this path.

## Registration Validation Rules

At registration time, the platform enforces:
- `module_id` uses lowercase letters/digits/underscore and starts with a letter.
- `capability_profiles()` is non-empty.
- Every profile has matching `profile.module_id == module.module_id`.
- Every `action_id` starts with `<module_id>.`.
- No duplicate action IDs.
- Every capability profile has a non-empty description.
- `required_tools()` is non-empty.
- No empty tool keys and no duplicate tool keys.
- Every tool key is prefixed `<module_id>.<tool_name>` (e.g.
  `vulnerability.osv_advisory`, `hello_world.greet`). The prefix
  prevents collisions across modules in the shared `ToolRegistry`.

## Ownership Rules

- Module-specific provider clients, services, adapters, scoring logic, and reporting must live inside the module package.
- Cross-module platform utilities (example: shared HTTP client, SSH transport, registry core) stay in top-level platform/shared packages.
- Module data defaults should be stored in module-owned data files and seeded into DB via module migrations.

## Tool Design Rules

### One Tool Per Concern

Each tool file must contain exactly one `Tool` subclass scoped to a single data source or operation concern. God Object tools (one class with 5+ unrelated actions) are a violation.

- CORRECT: `advisories_osv.py` contains `OSVAdvisoryTool` (OSV.dev only)
- CORRECT: `intel_nvd.py` contains `NVDIntelTool` (NVD only)
- WRONG: `advisories.py` contains `VulnerabilityAdvisoryTool` (OSV + Arch + Alpine + caches)

Rationale: The LLM agent selects tools by name and description. A tool named "unified_advisory" gives the agent no signal about when to call it. Split by data source or operation, not by domain.

---

## Contract Organization Rules

### Barrel-Only `__init__.py`

`contracts/__init__.py` must be a barrel re-export only -- no model definitions inline. Models live in domain submodules (`matching.py`, `scoring.py`, `reporting.py`, `analysis.py`). The barrel re-exports all public names so external callers use:

```python
from module.contracts import ModelName
```

without knowing the internal submodule.

### No Private Names in __all__

`__all__` must list only public names. Names starting with `_` must not appear in any `__all__` list. Private functions are still importable by explicit name; `__all__` only controls `from module import *` behaviour and signals the public API.

### Cross-Component Contract Boundary Rule

Models that cross component boundaries MUST live in `contracts/`. Models internal to one component stay with that component. Never define a contract model in the same file as the class that consumes it.

**What "crosses a component boundary" means:**
- A payload model that a handler deserializes from an external caller's request
- A result model returned across a package boundary (e.g., from `storage/` consumed by `modules/`)
- A structured response model used as the `response_model=` argument in an agent call when the result is passed to another component
- Any model imported by more than one package

**What may stay in the implementation file:**
- A model used exclusively inside one method/class as an internal parsing detail, never exported or imported elsewhere
- A dataclass used only within one file for computation purposes

**Examples:**

- CORRECT: `AnalyzePayload` (the vulnerability module's action input) lives in `vulnerability/contracts/analysis.py`
- CORRECT: `LatestReportResult` (returned from `storage/` and consumed by `modules/`) lives in `platform/contracts/reporting.py`
- WRONG: `DeleteIntegrationsPayload` defined in `platform/modules/platform.py` alongside the class that parses it
- WRONG: `RoutingSelection` defined in `platform/routing/router.py` alongside the router that creates it

---

## DB Model Organization

For modules with more than 5 SQLModel tables, `db_models.py` must be converted to a `db_models/` package with domain submodules:

```text
db_models/
  __init__.py         # barrel re-export only
  operations.py       # cache, queue, shared helpers
  distribution.py     # distribution profiles, inventory, scheduling
  findings.py         # finding records, remediation, asset tags
```

`db_models/__init__.py` is a barrel re-export only. External callers use:

```python
from module.db_models import SomeRecord
```

without knowing which submodule defines it. Internal helpers shared between submodules (e.g., `_enum_sql_values`) live in one submodule and are imported by others -- no duplication.

---

## Platform-Module Boundary

### Auto-Discovered (Platform Owns)

The platform automatically discovers and registers:

- Tools listed in `required_tools()` via `capabilities.py`
- DB schemas via `schema_registry.push(SCHEMA_REGISTRATION)` called inside `register_tools()`
- Config schemas via `registry.register(spec)` called inside `register_tools()`
- Seed data via `seed_data()` in `module.py`
- The module itself via `create_module()` in `module.py`

### Manually Wired (Module Owns Inside `module.py`)

The module is responsible for explicitly wiring:

- Agent construction and knowledge namespace assignment
- Service instantiation (e.g., SSH transport, provider clients)
- Injecting module-specific query callables into platform repositories
  (e.g., `ReportRepository(materialized_query=_query_latest_findings)`)

Wiring happens at `register_tools()` time or `build_runtime()` time -- not inside platform infrastructure.

### Storage Layer Isolation Rule

The platform `storage/` layer must NOT import from any `modules/<module_id>/` package. If a storage component needs module-specific behaviour, the module injects it via:

- A callable parameter on the storage class constructor
- A `register_*` method on the storage class

Never via a direct model import crossing the platform-to-module boundary.

```python
# CORRECT -- module owns the coupling to its own DB model
def _query_latest_findings(session, target):
    from aila.modules.vulnerability.db_models import LatestFindingRecord
    ...

# WRONG -- storage layer imports module model directly
from ..modules.vulnerability.db_models import LatestFindingRecord
```

---

## Developer Workflow

1. Copy `src/aila/modules/_template/`.
2. Rename `_template` to your module ID.
3. Implement contracts, tools, services, workflow, runtime, and module entrypoint.
4. Ensure `create_module()` returns your module object.
5. Start the platform; discovery validation will fail fast if structure/contract is wrong.

---

## Lifecycle Methods

Every module must implement all four methods of `ModuleProtocol`.

### `create_module() -> ModuleProtocol`

Zero-argument factory function at module scope (not a class method). Returns a fully initialized instance.

```python
def create_module() -> ModuleProtocol:
    return MyModule()
```

The returned `module.module_id` **must** match the folder name exactly (e.g., folder `vulnerability` → `module_id = "vulnerability"`). Platform discovery enforces this.

### `async register_tools(tool_registry, settings, registry, schema_registry)`

Called once at startup. Register all tools, schemas, and config the module
needs. The method is `async def` so it can await async setup (provider
warm-up, config materialization). Synchronous `register_*` calls inside
the body stay synchronous; no `await` is required for them.

```python
async def register_tools(
    self,
    tool_registry: ToolRegistry,
    settings: Settings,
    registry: ConfigRegistry | None = None,
    schema_registry: SchemaRegistry | None = None,
) -> None:
    if schema_registry is not None:
        schema_registry.push(MyTableRecord, ...)
    if registry is not None:
        registry.register(self.module_id, MyConfigSchema)
    for spec in iter_tool_specs():
        tool_registry.register(spec.key(), spec.factory(settings))
```

Note: the Protocol declares `settings: ApplicationSettings`; the concrete `Settings` class in `aila.config` satisfies the protocol.

See "SchemaRegistry Usage" and "Tool Registration Pattern" sections below.

### `async seed_data(session: AsyncSession) -> None`

Called once per startup after `register_tools`. Seeds default data into
the DB (scoring policies, distribution profiles, lookup tables, etc.).
The `session` is an `AsyncSession`; every `session.exec(...)` and
`session.commit()` MUST be awaited.

See the dedicated "seed_data() Contract" section below.

### `filter_report_rows(rows, filters) -> list[JsonObject]`

Module-owned filter logic over report rows. The module defines which keys are valid, which use exact match, and which use substring match. Platform delegates filtering entirely to this method.

```python
def filter_report_rows(
    self,
    rows: list[JsonObject],
    filters: JsonObject | None = None,
) -> list[JsonObject]:
    ...
```

- Must return `list(rows)` unchanged when `filters` is `None`, empty, or contains only unknown/empty keys.
- Filter semantics (exact vs. contains, delimiter splitting) are module-internal -- callers must not assume a specific algorithm.

---

## seed_data() Contract

`seed_data(session)` is called by the platform after every startup. It must be **idempotent**.

Rules:

1. **Check `SeedVersionRecord` first.** If the module's seed version already matches `SEED_VERSION`, return immediately without touching any data.

   ```python
   from aila.storage.db_models import SeedVersionRecord
   existing = (await session.exec(
       select(SeedVersionRecord).where(SeedVersionRecord.module_id == self.module_id)
   )).first()
   if existing is not None and existing.seed_version == SEED_VERSION:
       return
   ```

2. **Call `await session.commit()` before returning.** The session is caller-owned; do not open a new session inside `seed_data()`. The platform provides a live `AsyncSession` and expects the commit to happen inside this call.

3. **Bump `SEED_VERSION` to re-trigger seeding.** Define `SEED_VERSION` as a module-level constant (e.g., `SEED_VERSION = "1.0"`). Changing this value causes the platform to re-seed on the next startup.

4. **Session ownership.** Do not call `session_scope()`, `async_session_scope()`, or open a new engine connection inside `seed_data()`. The caller owns the session lifetime.

```python
SEED_VERSION = "1.0"

async def seed_data(self, session: AsyncSession) -> None:
    from sqlmodel import select
    from aila.storage.db_models import SeedVersionRecord

    existing = (await session.exec(
        select(SeedVersionRecord).where(SeedVersionRecord.module_id == self.module_id)
    )).first()
    if existing is not None and existing.seed_version == SEED_VERSION:
        return

    _seed_defaults(session)

    if existing is None:
        session.add(SeedVersionRecord(module_id=self.module_id, seed_version=SEED_VERSION))
    else:
        existing.seed_version = SEED_VERSION
        session.add(existing)
    await session.commit()
```

---

## Allowed Import Surfaces

A module may import from:

- `aila.platform.*` -- modules, routing, runtime, services, tools, contracts
- `aila.storage.*` -- DB models, schema registry, config registry
- `aila.config.Settings` -- infrastructure settings

A module **must not** import from another feature module:

```python
# FORBIDDEN
from aila.modules.other_module.anything import Something
```

Cross-module data sharing must go through platform services or shared contracts.

---

## __all__ Export Rules

From `CLAUDE.md`:

- Every `__init__.py` in a package **must** define `__all__` explicitly.
- Every non-private module that exposes public functions or classes **must** define `__all__` at module scope.
- `__all__` must list every name intended for external use.
- `__all__` must **not** include names that start with an underscore.
- Namespace packages with no public re-exports must set `__all__ = []`.
- Underscore-prefixed modules (e.g., `_lookup_helpers.py`) are private implementation details. They **must not** define `__all__` -- the underscore prefix signals non-public surface.

```python
# Public module or package init
__all__ = ["MyService", "MyContract"]
from .my_service import MyService
from .my_contract import MyContract

# Package init with no public exports -- __all__ = []
# _helpers.py -- private module, omit __all__ entirely
```

---

## SchemaRegistry Usage

DB table classes are registered by modules during `register_tools()`. The platform calls `create_all()` after all modules have registered.

```python
async def register_tools(self, tool_registry, settings, registry=None, schema_registry=None):
    if schema_registry is not None:
        schema_registry.push(
            MyTableRecord,
            AnotherTableRecord,
        )
```

Rules:

- Call `schema_registry.push(TableClass, ...)` inside `register_tools()` -- not elsewhere.
- Do **not** call `create_all()` directly inside a module. The platform calls it after all modules have registered.
- Every SQLModel table class must set `__tablename__` explicitly.
- `schema_registry` may be `None` in some execution contexts (e.g., test fixtures that bypass DB setup) -- always guard with `if schema_registry is not None`.

---

## Tool Registration Pattern

Tools are registered by key during `register_tools()`. Use the `TOOL_ALIAS`, `CAPABILITY`, and `FACTORY` constants pattern with `iter_tool_specs()`:

```python
# In tool_catalog.py
from dataclasses import dataclass
from collections.abc import Callable
from aila.config import Settings

@dataclass(frozen=True)
class ToolSpec:
    TOOL_ALIAS: str
    CAPABILITY: str
    FACTORY: Callable[[Settings], object]

    def key(self) -> str:
        return self.TOOL_ALIAS

    def factory(self, settings: Settings) -> object:
        return self.FACTORY(settings)

def iter_tool_specs() -> list[ToolSpec]:
    return [
        ToolSpec(
            TOOL_ALIAS="my_module.my_tool",
            CAPABILITY="what this tool does",
            FACTORY=lambda s: MyTool(s),
        ),
    ]
```

Then in `module.py`:

```python
for spec in iter_tool_specs():
    tool_registry.register(spec.key(), spec.factory(settings))
```

Tool keys must be unique across all registered modules. Platform enforces no duplicate keys at registration.

---

## Event Emitter Integration

Every workflow state handler must emit stage lifecycle events via `emit_stage_result()`.
This replaces the three-call pattern (audit_event + run_event + progress_callback) used before v1.4.

Import:

```python
from aila.modules.vulnerability.workflow.helpers import emit_stage_result
```

Usage in a state handler:

```python
def state_prepare(context: WorkflowExecutionContext) -> WorkflowStage | None:
    # ... do work ...
    emit_stage_result(
        context,
        stage=WorkflowStage.PREPARE,
        action="prepare",
        event_key="module_id.prepare",
        message="Preparation complete.",
        audit_details={"target_count": len(context.target_names)},
        progress_message="Preparing...",
    )
    return None
```

Rules:
- Call `emit_stage_result()` at the end of each state handler, after all mutations to context are complete.
- `event_key` format: `"<module_id>.<stage_name>"` -- must be unique and lowercase.
- `audit_details` is optional; include meaningful facts (counts, IDs, mode names).
- `progress_message` is optional; used for CLI/SSE progress display.
- Do not call `audit_event()`, `append_run_event()`, or `progress_callback` directly -- they are destinations wired inside `emit_stage_result`.

---

## BaseProviderClient

HTTP provider clients (NVD, OSV, EPSS, KEV, Alpine, Arch, GHSA) must extend `BaseProviderClient` from `aila.modules.vulnerability.providers.base`.

`BaseProviderClient` handles:
- Shared `__init__` with proxy, timeout, and `httpx.Client` construction
- `close()` for explicit cleanup
- `__del__` safety guard

Subclass pattern:

```python
from aila.modules.vulnerability.providers.base import BaseProviderClient

class MyProviderClient(BaseProviderClient):
    def __init__(
        self,
        base_url: str,
        settings: Settings | None = None,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(base_url=base_url, settings=settings, timeout=timeout)
        self._api_key = self._resolve_api_key()

    def _resolve_api_key(self) -> str | None:
        ...
```

HTTP tools that use a provider client must override `__init__` WITHOUT calling `super().__init__()` from `VulnerabilityTool` -- HTTP tools do not need `init_db()`.

---

## Google-Style Docstrings

Every public function, method, and class must have a Google-style docstring.

Required format:

```python
def my_function(name: str, count: int = 0) -> list[str]:
    """One-line summary ending with a period.

    Optional extended description explaining WHAT this does and WHY it exists.
    Describe behavior, side effects, or constraints that are not obvious.

    Args:
        name: Description of the parameter.
        count: Description with default behavior noted if relevant.

    Returns:
        Description of the return value and its shape.

    Raises:
        ValueError: When name is empty.
        NotFoundError: When the record does not exist.
    """
```

Rules:
- First line: one-sentence summary, ends with a period.
- Blank line between summary and Args/Returns/Raises sections.
- Args section: one line per parameter. Type annotations are in the function signature -- do NOT duplicate types in the docstring.
- Returns section: what the return value is, its shape, and key semantics. Omit for `None`-returning functions.
- Raises section: document exceptions that callers must handle. Omit for functions that do not raise.
- Skip trivial `__init__` that only assigns fields (no logic) and obvious property getters.
- Describe WHAT and WHY -- not the parameter types (those are in type annotations).
- Private functions (`_` prefix) may have docstrings but are not required to.

---

## ModuleRouteSpec (API Route Declaration)

Modules declare HTTP routes via `route_specs()` on `ModuleProtocol`. The platform
calls `spec.router_factory()` at startup to obtain a FastAPI `APIRouter` and mounts
it at `spec.prefix` via `include_router(prefix=...)`.

### Dataclass Shape (v1.5)

```python
@dataclass(frozen=True, slots=True)
class ModuleRouteSpec:
    prefix: str                                # URL prefix for all routes in this spec
    router_factory: Callable[[], Any]          # () -> APIRouter
    tool_keys: tuple[str, ...] = ()            # tool keys this module registers
    config_namespace: str | None = None         # config namespace owned by module
    payload_type: str | None = None             # discriminated-union payload type name
```

### Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `prefix` | `str` | Yes | URL prefix for all routes (e.g. `"/vulnerability"`). Platform mounts the router at this path. |
| `router_factory` | `Callable[[], Any]` | Yes | Zero-argument callable returning a FastAPI `APIRouter`. Called once at startup. |
| `tool_keys` | `tuple[str, ...]` | No | Tool keys this module registers, surfaced via `GET /tools`. Use `tuple()` not `list()` because the dataclass is frozen. |
| `config_namespace` | `str \| None` | No | Config namespace this module owns, surfaced via `GET/PUT /config`. `None` if the module has no config. |
| `payload_type` | `str \| None` | No | Name of the discriminated-union payload type (optional). |
| `auth_required` | `bool` | No | When False, skip the global `require_user_or_api_key` dependency. Default `True`. |

### Example: Vulnerability Module

```python
def route_specs(self) -> list[ModuleRouteSpec]:
    from my_module.api_router import create_my_router  # deferred import

    return [
        ModuleRouteSpec(
            prefix="/my_module",
            router_factory=create_my_router,
            tool_keys=("my_module.tool_a", "my_module.tool_b"),
            config_namespace="my_module",
        ),
    ]
```

### Rules

- Platform calls `spec.router_factory()` to obtain the `APIRouter` and mounts it at `spec.prefix`. Modules must **NOT** embed the prefix in router paths. If the platform mounts at `/vulnerability`, router paths should be relative: `/findings`, not `/vulnerability/findings`.
- Return `[]` (the protocol default) for modules with no HTTP surface.
- `ModuleRouteSpec` is a frozen dataclass -- do not subclass it.
- Use `tuple()` for `tool_keys`, not `list()`. Frozen dataclasses reject mutable defaults.
- Import the router factory inside `route_specs()` (deferred import) to keep module discovery lightweight. Importing at module level pulls in FastAPI and all route dependencies at discovery time.

---

## Frontend Endpoint Standard

Module-owned HTTP routes are public contracts for the browser and other API clients. Treat them as explicit product surfaces, not as storage leaks or CLI payload dumps.

### Location

- If a module exposes HTTP routes, keep the router factory in `api_router.py`.
- `module.py` declares the mounted HTTP surface through `route_specs()`.
- Route paths must remain relative to the mount prefix declared in `ModuleRouteSpec`.

### Contract Rules

- Every route must declare `response_model=...` and `summary=...`.
- Every request body must use an explicit Pydantic model. Do not accept raw `dict[str, Any]` bodies for frontend-facing endpoints.
- Read routes must not trigger scans, rescoring, or other expensive work implicitly. If work is queued, expose it as an explicit mutation or a `202 Accepted` flow.
- List endpoints intended for frontend browsing must be paginated. Standard shape is `total`, `page`, `page_size`, `pages`, `items` unless the route is intentionally streaming.
- Filters, counts, and facets must be computed server-side. Do not dump the full dataset to the browser and expect the UI to reconstruct truth.
- Router boundaries must map internal names to stable API names. Never leak raw DB column names, filesystem paths, or module-private payload shapes just because they already exist internally.
- Empty, missing, and unavailable are different states. Return them differently: empty result for no data, `404` for missing resource, `409/503` for unavailable or blocked work where appropriate.
- Streaming/progress routes must reflect backend state honestly. No invented percentages, no fake completion, no silent downgrade from live state to stale state.
- If an endpoint exposes artifact availability, return frontend-usable contract fields (IDs, formats, or download route inputs), not raw local file paths.

### Naming and Shape Rules

- Use noun-based route groups that match the browser mental model: `/findings`, `/reports/{run_id}`, `/systems/{id}`.
- Keep module-specific semantics in the module route prefix, not in hidden query switches or overloaded action names.
- Prefer one route per observable user task. Do not create generic catch-all endpoints that return unrelated shapes depending on hidden flags.

### Boundary Example

Internal storage fields may differ from the public API, but the translation must happen at the router boundary:

```python
# GOOD: map internal names to stable API names at the HTTP boundary
FindingResponse(
    package=row.package_name,
    severity=row.criticality,
)

# BAD: return raw storage field names and make the frontend learn internals
{"package_name": row.package_name, "criticality": row.criticality}
```

---

## Optional Lifecycle Methods

These methods have default implementations that return empty values. Modules override them when they contribute data to platform endpoints. All three are called by platform API routes; modules that do not participate simply inherit the default.

### `async system_summary(system_id, session) -> dict[str, Any]`

**Signature:**

```python
async def system_summary(self, system_id: int, session: AsyncSession) -> dict[str, Any]:
```

**When the platform calls it:** `GET /systems/{id}` collects module-contributed dashboard data. The platform iterates all registered modules, calls `system_summary()` on each, and merges all non-empty dicts into the response.

**Expected return type:** `dict[str, Any]` with module-specific data. Return `{}` if the module has nothing to contribute for this system.

**Default behavior:** Returns `{}` (empty dict). No action required from the module.

**Example implementation:**

```python
async def system_summary(self, system_id: int, session: AsyncSession) -> dict[str, Any]:
    from sqlmodel import select
    from my_module.db_models import FindingRecord

    rows = (await session.exec(
        select(FindingRecord).where(FindingRecord.system_id == system_id)
    )).all()
    if not rows:
        return {}
    return {
        "critical": sum(1 for r in rows if r.criticality == "CRITICAL"),
        "high": sum(1 for r in rows if r.criticality == "HIGH"),
    }
```

### `async report_count(run_id, session) -> dict[str, Any]`

**Signature:**

```python
async def report_count(self, run_id: str, session: AsyncSession) -> dict[str, Any]:
```

**When the platform calls it:** `GET /reports/{run_id}/count` collects semantic count breakdowns. The platform calls this on the module that owns the given `run_id`. Modules that do not own the `run_id` should return `{}` without raising.

**Expected return type:** `dict[str, Any]` with domain-specific breakdowns (e.g. severity counts, category totals). Return `{}` if the module has nothing to report.

**Default behavior:** Returns `{}` (empty dict).

**Example implementation:**

```python
async def report_count(self, run_id: str, session: AsyncSession) -> dict[str, Any]:
    from sqlmodel import select
    from my_module.db_models import FindingRecord

    rows = (await session.exec(select(FindingRecord))).all()
    if not rows:
        return {}
    return {
        "total_findings": len(rows),
        "critical": sum(1 for r in rows if r.criticality == "CRITICAL"),
    }
```

### `health_checks() -> dict[str, object]`

**Signature:**

```python
def health_checks(self) -> dict[str, object]:
```

**When the platform calls it:** `GET /health` collects module-contributed health checks. The health endpoint checks `hasattr(module, 'health_checks')` before calling, so this method is truly optional on concrete implementations.

**Expected return type:** `dict[str, object]` mapping check name to a zero-argument callable returning a `ModuleHealthResult`-compatible object with a `status` attribute (`'up'`, `'degraded'`, or `'down'`).

**Default behavior:** Returns `{}` (empty dict). Platform-level code must never require this method.

**Example implementation:**

```python
def health_checks(self) -> dict[str, object]:
    return {
        "llm_api": lambda: self._check_llm_reachability(),
        "db_connection": lambda: self._check_db(),
    }
```

Each callable should return a `ModuleHealthResult(status="up")` or equivalent on success, or `ModuleHealthResult(status="down", message="...")` on failure.

---

## Worked Example: Scaffold to Running Module

This section walks through building a complete module from the `_template` scaffold. The example creates a `network_scan` module that registers tools, contributes HTTP routes, seeds default data, and integrates with platform lifecycle methods.

### Step 1: Copy the Template

```bash
cp -r src/aila/modules/_template src/aila/modules/network_scan
```

Resulting layout:

```text
src/aila/modules/network_scan/
  __init__.py
  module.py
  runtime.py
  capabilities.py
  workflow.py
  tool_keys.py
  contracts/
    __init__.py
  tools/
    __init__.py
  services/
    __init__.py
  reporting/
    __init__.py
```

### Step 2: Define Tool Keys

Edit `tool_keys.py` -- stable identifiers referenced by `capabilities.py`, `required_tools()`, and `register_tools()`.

```python
# tool_keys.py
from __future__ import annotations

NETWORK_SCAN_DISCOVER_TOOL = "network_scan.discover"
NETWORK_SCAN_PROBE_TOOL = "network_scan.probe"

__all__ = ["NETWORK_SCAN_DISCOVER_TOOL", "NETWORK_SCAN_PROBE_TOOL"]
```

### Step 3: Declare Capabilities

Edit `capabilities.py` -- description and examples are embedded in LLM routing prompts.

```python
# capabilities.py
from __future__ import annotations

MODULE_DESCRIPTION = "Network scanner: discovers hosts and probes open ports."
MODULE_TOOLS: list[str] = [
    "network_scan.discover",
    "network_scan.probe",
]
MODULE_EXAMPLES: list[str] = [
    "scan the 10.0.0.0/24 subnet for open ports",
    "discover hosts on the management network",
]

__all__ = ["MODULE_DESCRIPTION", "MODULE_EXAMPLES", "MODULE_TOOLS"]
```

### Step 4: Implement Tools

Each tool file in `tools/` contains exactly one `Tool` subclass scoped to a single concern.

```python
# tools/__init__.py
from .discover import DiscoverTool
from .probe import ProbeTool

__all__ = ["DiscoverTool", "ProbeTool"]
```

```python
# tools/discover.py
from __future__ import annotations

from aila.config import Settings

__all__ = ["DiscoverTool"]


class DiscoverTool:
    """Discover live hosts on a subnet."""

    def __init__(self, settings: Settings) -> None:
        self._timeout = settings.ssh_timeout

    def execute(self, subnet: str) -> list[str]:
        """Scan subnet and return list of responding hosts.

        Args:
            subnet: CIDR notation subnet to scan.

        Returns:
            List of IP address strings that responded.
        """
        # Real implementation goes here
        return []
```

### Step 5: Define Contracts

Cross-component models go in `contracts/`. Internal-only models stay in the implementation file.

```python
# contracts/__init__.py
from .scan_result import ScanResult

__all__ = ["ScanResult"]
```

```python
# contracts/scan_result.py
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["ScanResult"]


@dataclass(frozen=True)
class ScanResult:
    """Result of a network scan passed between components."""

    host: str
    open_ports: list[int]
    latency_ms: float
```

### Step 6: Write the Module Entrypoint

Edit `module.py` -- this is the only file the platform imports directly.

```python
# module.py
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
from .runtime import NetworkScanRuntime
from .tool_keys import NETWORK_SCAN_DISCOVER_TOOL, NETWORK_SCAN_PROBE_TOOL
from .tools import DiscoverTool, ProbeTool

MODULE_ID = Path(__file__).parent.name      # "network_scan" -- must match folder
MODULE_ACTION_ID = action_id_for(MODULE_ID, "run")
SEED_VERSION = "1.0"


class NetworkScanModule(ModuleProtocol):
    """Network scan module implementing ModuleProtocol."""

    module_id = MODULE_ID
    action_id = MODULE_ACTION_ID

    # --- Required lifecycle methods ---

    def capability_profiles(self) -> list[ModuleCapabilityProfile]:
        """Advertise this module to the routing agent."""
        return [
            ModuleCapabilityProfile(
                module_id=self.module_id,
                action_id=self.action_id,
                description=MODULE_DESCRIPTION,
                tools=list(MODULE_TOOLS),
                examples=list(MODULE_EXAMPLES),
            )
        ]

    def required_tools(self) -> list[str]:
        """Return tool keys the platform scopes for this module."""
        return list(MODULE_TOOLS)

    async def register_tools(
        self,
        tool_registry: ToolRegistry,
        settings: Settings,
        registry=None,
        schema_registry=None,
    ) -> None:
        """Register tools and DB schemas.

        Args:
            tool_registry: Register each tool by key.
            settings: Passed to tool constructors.
            registry: ConfigRegistry -- register config schema here.
            schema_registry: SchemaRegistry -- push DB table classes here.
        """
        # Register DB tables (if any)
        # if schema_registry is not None:
        #     schema_registry.push(NetworkScanRecord)

        # Register tools
        tool_registry.register(NETWORK_SCAN_DISCOVER_TOOL, DiscoverTool(settings))
        tool_registry.register(NETWORK_SCAN_PROBE_TOOL, ProbeTool(settings))

    def build_runtime(self, context: ModuleContext) -> ModuleRuntime:
        """Construct the runtime that handles incoming requests."""
        del context
        return NetworkScanRuntime(
            module_id=self.module_id,
            action_id=self.action_id,
            capability_profiles=self.capability_profiles(),
        )

    # --- Route declaration ---

    def route_specs(self) -> list[ModuleRouteSpec]:
        """Declare HTTP routes mounted by the platform.

        IMPORTANT: Import the router factory inside this method (deferred import)
        to keep module discovery lightweight.
        """
        from .api_router import create_network_scan_router  # deferred import

        return [
            ModuleRouteSpec(
                prefix="/network_scan",
                router_factory=create_network_scan_router,
                tool_keys=(NETWORK_SCAN_DISCOVER_TOOL, NETWORK_SCAN_PROBE_TOOL),
                config_namespace="network_scan",
            ),
        ]

    # --- Optional lifecycle methods (defaults inherited if not overridden) ---

    async def seed_data(self, session: AsyncSession) -> None:
        """Seed default configuration. Idempotent via SeedVersionRecord."""
        from sqlmodel import select
        from aila.storage.db_models import SeedVersionRecord

        existing = (await session.exec(
            select(SeedVersionRecord).where(
                SeedVersionRecord.module_id == self.module_id
            )
        )).first()
        if existing is not None and existing.seed_version == SEED_VERSION:
            return

        # Seed your default data here (policies, lookup tables, etc.)
        # session.add(NetworkScanPolicy(name="default", ...))

        if existing is None:
            session.add(SeedVersionRecord(
                module_id=self.module_id, seed_version=SEED_VERSION
            ))
        else:
            existing.seed_version = SEED_VERSION
            session.add(existing)
        await session.commit()

    def filter_report_rows(
        self,
        rows: list[JsonObject],
        filters: JsonObject | None = None,
    ) -> list[JsonObject]:
        """Filter report rows. Return all rows unchanged when filters is empty."""
        if not isinstance(filters, dict) or not filters:
            return list(rows)
        # Apply module-specific filtering logic
        return list(rows)

    def report_filter_keys(self) -> list[str]:
        """Return valid filter keys for filter_report_rows."""
        return ["host", "port"]

    async def system_summary(self, system_id: int, session: AsyncSession) -> dict[str, Any]:
        """Contribute data to GET /systems/{id}. Return {} if nothing to add."""
        return {}

    async def report_count(self, run_id: str, session: AsyncSession) -> dict[str, Any]:
        """Contribute count data to GET /reports/{run_id}/count."""
        return {}

    def health_checks(self) -> dict[str, object]:
        """Return health checks for GET /health."""
        return {}


def create_module() -> ModuleProtocol:
    """Module factory. Zero-argument, returns ModuleProtocol instance."""
    return NetworkScanModule()
```

### Step 7: Add HTTP Routes

Create `api_router.py`. Paths are relative -- the platform mounts at the prefix declared in `route_specs()`. Frontend/API routes are public contracts: use explicit request/response models, do server-side pagination/filtering, and map internal names to stable API fields at the router boundary.

```python
# api_router.py
from __future__ import annotations

from fastapi import APIRouter
from pydantic import Field

from aila.api.schemas.common import APIModel

__all__ = ["create_network_scan_router"]


class NetworkScanStatusResponse(APIModel):
    """Response for GET /network_scan/status."""
    module: str = Field(description="Module identifier")
    status: str = Field(description="Module operational status")


def create_network_scan_router() -> APIRouter:
    """Create the network_scan module router.

    Returns:
        A FastAPI APIRouter with module-specific endpoints.
    """
    router = APIRouter(tags=["network_scan"])

    @router.get("/status", response_model=NetworkScanStatusResponse)
    async def network_scan_status() -> NetworkScanStatusResponse:
        """Return network_scan module status."""
        return NetworkScanStatusResponse(module="network_scan", status="ok")

    return router
```

### Step 8: Verify

Start the platform. Module discovery validates the contract at boot:

```bash
python -m compileall src/aila
python -m aila serve
```

If `module_id` mismatches the folder name, `capability_profiles()` is empty, or `required_tools()` returns an empty list, the platform fails fast with a descriptive error. Successful boot confirms: tool registration, route mounting, seed execution, and health check wiring all passed.

### Key Validation Points

| What | Validated by | When |
|------|-------------|------|
| `module_id` matches folder name | Platform module loader | Boot |
| `capability_profiles()` non-empty | Module registry | Boot |
| `required_tools()` non-empty | Module registry | Boot |
| No duplicate tool keys | ToolRegistry | Boot |
| `action_id` starts with `module_id.` | Module registry | Boot |
| DB tables exist | SQLAlchemy `create_all()` | Boot |
| `seed_data()` idempotent | SeedVersionRecord check | Boot |
| Routes mount at correct prefix | FastAPI include_router | Boot |
| Handler concurrency declarations | `validate_handler_concurrency()` | Boot |
| No parallel write conflicts | `validate_handler_concurrency()` | Boot |

---

## Handler Concurrency Contract

Every handler function registered in a module's `HANDLER_REGISTRY` MUST declare two attributes immediately after its definition:

### `parallel_safe: bool`

Whether this handler can safely run in parallel with other handlers in the same workflow.

- `True` -- handler only reads context, or writes to fields that no other parallel handler touches.
- `False` -- handler mutates shared state and must run sequentially.

When in doubt, use `False`. Only mark `True` when you can guarantee no write overlap with other parallel-safe handlers.

### `writes_fields: list[str]`

The top-level context attributes this handler may mutate during execution.

- Empty list `[]` for read-only handlers (e.g., validation-only or emit-only stages).
- List context attribute names like `["analysis_state", "scoring_summary"]` for handlers that write.
- Include every field the handler assigns to, even conditionally.

### Declaration Pattern

Attributes are set on the function object after its definition:

```python
async def state_scoring(context: WorkflowExecutionContext) -> WorkflowStage | None:
    """Score vulnerabilities and write summary."""
    context.scoring_summary = compute_scores(context.analysis_state)
    return WorkflowStage.REPORT

state_scoring.parallel_safe = False
state_scoring.writes_fields = ["scoring_summary"]


async def state_response_emit(context: WorkflowExecutionContext) -> None:
    """Read-only validation before response emission."""
    validate_response(context)

state_response_emit.parallel_safe = True
state_response_emit.writes_fields = []
```

### Startup Validation

At import time, the platform runs `validate_handler_concurrency()` on every module's handler registry. This validator enforces:

1. **Every handler has both attributes.** Missing `parallel_safe` or `writes_fields` raises `ConcurrencyConflictError` and prevents startup.
2. **No parallel write conflicts.** If two handlers both declare `parallel_safe=True` and list the same field in `writes_fields`, the platform raises `ConcurrencyConflictError`.
3. **Non-parallel handlers are unconstrained.** Handlers with `parallel_safe=False` may write any field without conflict checks -- they run sequentially by contract.

### Wiring

Call `validate_handler_concurrency()` alongside existing handler validations. The call converts enum-keyed registries to string-keyed dicts:

```python
from aila.platform.modules.concurrency_validator import validate_handler_concurrency

# After populate_handler_registry() and validate_workflow_handlers()
validate_handler_concurrency(
    {stage.value: fn for stage, fn in HANDLER_REGISTRY.items()},
    module_id="my_module",
)
```

For simple modules with a single `workflow.py`, place the call after the import-time stage validation block.

---

## Common Pitfalls

These are concrete mistakes that module authors encounter. Where applicable, the `honesty_audit` AST rules catch violations automatically.

### 1. Wrong import path

Importing from another module's internals instead of through platform contracts.

```python
# WRONG -- violates import boundary
from aila.modules.other_module.services import OtherService

# CORRECT -- use platform contracts or services
from aila.platform.contracts import SharedContract
```

The `honesty_audit` AST rule `import_boundary` catches cross-module imports at CI time.

### 2. Missing `__all__`

Every public module and `__init__.py` must define `__all__`. The `honesty_audit` rule `private_in_all` catches underscore names in `__all__`.

```python
# WRONG -- no __all__ in a public module
def my_function():
    ...

# CORRECT
__all__ = ["my_function"]

def my_function():
    ...
```

### 3. Table not registered

Calling `session.add(MyRecord(...))` without first registering `MyRecord` via `schema_registry.push()` in `register_tools()`.

**Symptom:** `sqlalchemy.exc.OperationalError: no such table: my_record`

```python
# WRONG -- table class not pushed to schema_registry
async def register_tools(self, tool_registry, settings, registry=None, schema_registry=None):
    for spec in iter_tool_specs():
        tool_registry.register(spec.key(), spec.factory(settings))
    # MyRecord never registered -- will crash at runtime

# CORRECT
async def register_tools(self, tool_registry, settings, registry=None, schema_registry=None):
    if schema_registry is not None:
        schema_registry.push(MyRecord)
    for spec in iter_tool_specs():
        tool_registry.register(spec.key(), spec.factory(settings))
```

### 4. Creating a new session in `seed_data`

`seed_data()` receives a caller-owned session. Do **NOT** call `session_scope()` or create a new engine.

**Symptom:** Locked DB or missing writes (separate session commits are invisible to the caller's transaction).

```python
# WRONG
async def seed_data(self, session):
    async with async_session_scope() as new_session:  # creates a second connection
        new_session.add(MyRecord(...))
        await new_session.commit()

# CORRECT
async def seed_data(self, session):
    session.add(MyRecord(...))
    await session.commit()
```

### 5. Prefix in router paths

Defining router paths as `/vulnerability/findings` when the platform already mounts the router at `/vulnerability`. Router paths should be relative.

```python
# WRONG -- prefix is duplicated
@router.get("/vulnerability/findings")
async def list_findings(): ...

# CORRECT -- path is relative to the mount prefix
@router.get("/findings")
async def list_findings(): ...
```

### 6. Non-tuple `tool_keys` in ModuleRouteSpec

`ModuleRouteSpec` is a frozen dataclass. Using a list for `tool_keys` raises `TypeError` at construction if the field's default factory expects a tuple.

```python
# WRONG
ModuleRouteSpec(prefix="/x", router_factory=f, tool_keys=["a", "b"])

# CORRECT
ModuleRouteSpec(prefix="/x", router_factory=f, tool_keys=("a", "b"))
```

### 7. `route_specs()` import at module level

Importing the API router at the top of `module.py` pulls in FastAPI and all route dependencies at discovery time. Use a deferred import inside `route_specs()` to keep discovery lightweight.

```python
# WRONG -- heavyweight import at module scope
from my_module.api_router import create_my_router

class MyModule:
    def route_specs(self):
        return [ModuleRouteSpec(prefix="/x", router_factory=create_my_router)]

# CORRECT -- deferred import
class MyModule:
    def route_specs(self):
        from my_module.api_router import create_my_router
        return [ModuleRouteSpec(prefix="/x", router_factory=create_my_router)]
```

### 8. `module_id` mismatch

`module_id` must match the folder name exactly. Platform enforces this at registration and will reject the module with a clear error if they differ.

```python
# Folder: src/aila/modules/vulnerability/
# WRONG
module_id = "vuln"

# CORRECT
module_id = "vulnerability"
```
