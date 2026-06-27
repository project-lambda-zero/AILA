# AILA Architecture

AILA (AI Lab Assistant) is a modular AI security platform: a Python core
exposing a Typer CLI and a FastAPI REST API, backed by PostgreSQL and an
ARQ/Redis task queue, with a React + Vite + TypeScript frontend.

This document describes how the platform and its modules are organized,
how data flows through the system, and the operational constraints that
must hold for the system to behave correctly.

## System Overview

```
                    +------------------+
                    |   React Frontend |
                    |   (Vite + TS)    |
                    +--------+---------+
                             |
                    +--------v---------+
                    |   FastAPI REST   |
                    |   29 platform    |
                    |   routers +      |
                    |   module-        |
                    |   contributed    |
                    +--------+---------+
                             |
          +------------------+------------------+
          |                  |                  |
+---------v------+  +--------v-------+  +-------v--------+
|    Platform    |  |    Modules     |  |    Storage     |
|  routing       |  |  vulnerability |  |  SQLModel/PG   |
|  runtime       |  |  forensics     |  |  Alembic       |
|  services      |  |  vr            |  |  pgvector      |
|  contracts     |  |  hello_world   |  +----------------+
|  tools         |  +----------------+
|  llm           |
|  tasks (ARQ)   |           |
|  workflows     |  +--------v-------+
+----------------+  |  Redis / ARQ   |
                    |  task queues   |
                    +----------------+
```

The frontend talks only to the FastAPI layer. FastAPI delegates to the
platform's service and runtime layers. The platform owns infrastructure;
modules own domain logic. Long-running work is dispatched onto ARQ
queues (default, vulnerability, forensics, vr) backed by
Redis. Persistent state lives in PostgreSQL through SQLModel, with
schema managed by Alembic and vector search backed by pgvector.

## Platform Packages

All platform packages live under `src/aila/platform/`. The platform is
the only layer that knows about cross-cutting infrastructure; modules
must depend on platform abstractions, never on each other.

**`contracts/`** defines the typed boundary between the platform and
modules: `ModuleProtocol`, `ModuleRuntime`, `ModuleRouteSpec`, request
and response envelopes, frontend extension specs. Anything crossing the
platform/module line is declared here.

**`modules/`** is the module loader and registry. It discovers modules,
calls each module's `create_module()` factory, and registers their
runtimes, route specs, and tool sets with the rest of the platform. It
does not contain domain logic.

**`routing/`** owns the routing agent that maps a CLI or chat-style
request onto a target module. It uses module capabilities
(`MODULE_DESCRIPTION`, `MODULE_TOOLS`, `MODULE_EXAMPLES`) to choose a
handler, then forwards the request to that module's `ModuleRuntime`.

**`runtime/`** provides the execution scaffolding modules build on:
runtime context, lifecycle hooks, cancellation, structured error paths,
and the base classes that `ModuleRuntime.handle()` implementations plug
into.

**`services/`** holds platform-level domain services that are not tied
to any single module: system inventory, scan history, user and auth
services, report indexing. FastAPI routers and module runtimes both
consume these.

**`tools/`** is the tool execution framework. Tools extend a common
`Tool` base class, declare typed inputs and outputs, and are registered
under module-prefixed keys defined in each module's `tool_keys.py`. The
platform handles dispatch, validation, and observability for every tool
call.

**`llm/`** wraps the LLM layer: client construction, model selection,
pipeline configuration (e.g. classify/restricted-behavior pipelines),
token-budget enforcement, and the rejecting-temperature substring list.
All model calls flow through this package so policy and cost controls
apply uniformly.

**`tasks/`** is the ARQ integration: queue definitions (default,
vulnerability, forensics, vr), worker entry points wired into
`aila worker -q <queue>`, and `TaskRecord` persistence.

**`workflows/`** provides the explicit state-machine primitives modules
use to orchestrate multi-step domain flows. Workflows are declared as
named states with explicit transitions; the runtime drives them, and
the state is observable rather than implicit in code flow.

**`events/`** is the in-process event bus used to decouple producers
and observers (e.g. lifecycle events emitted during a scan). It is the
plumbing that SSE handlers and audit hooks read from.

**`automation/`** contains scheduled and triggered automation flows
that run independently of an interactive request, plus the policy and
safety guards around them.

**`sse/`** implements server-sent-event streams used by the frontend
to follow long-running tasks: it subscribes to `events/`, formats
frames, and handles client disconnect and backpressure.

## Module Boundary

Modules live under `src/aila/modules/<module_id>/` and follow MODULE_STANDARD v2.1:

```
src/aila/modules/<module_id>/
  module.py         # ModuleProtocol implementation + create_module()
  runtime.py        # ModuleRuntime.handle() implementation
  capabilities.py   # MODULE_DESCRIPTION, MODULE_TOOLS, MODULE_EXAMPLES
  tool_keys.py      # Tool key constants (prefixed with module_id)
  workflow.py       # or workflow/ package for complex state machines
  contracts/        # Pydantic/dataclass models
  tools/            # Tool implementations extending Tool base
  services/         # Domain service layer
  reporting/        # Report generation
  api_router.py     # Optional - router factory
  db_models/        # Optional - module-owned SQLModel tables
  frontend/         # Optional - React components
```

The boundary rules are non-negotiable:

- **Platform never imports from modules.** The platform discovers modules
  through the registry and interacts with them only through contracts.
- **Modules never import from each other.** Cross-module communication
  goes through platform services, events, or tool calls.
- **Modules register through `create_module()`.** This factory returns a
  `ModuleProtocol` implementation that exposes the module's runtime,
  route specs, tools, and frontend spec.
- **Routes register via `route_specs()`.** Each module declares its
  HTTP surface as `ModuleRouteSpec` instances; the platform mounts
  them onto the FastAPI app.
- **Tools register via `register_tools()`.** Tool keys must be prefixed
  with the module id so registration and dispatch are unambiguous.
- **Frontend extends via `ModuleFrontendSpec`.** Modules contribute nav
  entries, routes, panels, and widgets through this spec; the React
  shell composes them at boot.

## Data Flow

There are two primary flows.

**CLI / agentic request:**

```
CLI input (aila ...)
   -> platform.routing  (route to target module via capabilities)
      -> module.ModuleRuntime.handle(request)
         -> module.workflow  (explicit state machine)
            -> tool execution via platform.tools
               -> platform.llm (when an LLM step is involved)
               -> platform.services + storage
            -> module.reporting (artifact generation)
   -> result + report path returned to caller
```

The routing agent decides _which_ module handles the request. The
module's runtime decides _how_, by stepping a workflow that issues
tool calls. Reports are written to disk and referenced by path.

**API request:**

```
Frontend (React) -> FastAPI router -> platform.services -> storage
                                  \-> module router (when module-owned)
```

Synchronous reads and short writes go directly through the service
layer. Long-running work is enqueued onto ARQ; clients follow progress
through SSE streams sourced from `platform.events`.

## Extension Points

Modules extend the platform through declarative specs, never by
patching it.

- **`ModuleRouteSpec`** declares HTTP routes a module owns. The
  platform mounts the resulting router onto the FastAPI app under a
  module-scoped prefix.
- **`ModuleFrontendSpec`** is the frontend extension surface:
  ```typescript
  interface ModuleFrontendSpec {
    moduleId: string;
    nav?: NavContribution[];        // sidebar entries
    routes?: RouteContribution[];   // page routes
    panels?: PanelContribution[];   // injected panels (system detail, etc)
    widgets?: WidgetContribution[]; // dashboard widgets
  }
  ```
- **`NavContribution`** adds entries to the React shell's sidebar.
- **`RouteContribution`** registers a top-level page route, mounted by
  the shell's router.
- **`PanelContribution`** injects a module-owned panel into a known
  host surface (e.g. the system detail view).
- **`WidgetContribution`** contributes a dashboard widget.

The shell discovers these contributions at boot and composes the UI;
modules never reach into the shell directly.

## Constraints

These are operational requirements. They are enforced by code where
possible and by review where not. A change that breaks one of these is
a system change, not a feature change.

### INFRA-03: Single Concurrent Scan Per System

A given target system must have at most one active scan at a time
across the platform. Concurrent scans of the same system produce
inconsistent state (overlapping artifact writes, racing workflow
transitions, ambiguous report ownership) and must be prevented.

**Enforcement:**

- The scan service rejects a new scan request for a system that already
  has an in-flight task.
- ARQ workers per queue are sized so that no single system is scanned
  twice in parallel; per-system serialization is enforced at the
  service layer rather than relying on worker count alone.

This is a hard requirement, not a soft guideline. Scans across
_different_ systems can and do run in parallel; the constraint is
per-system, not global.

### INFRA-06: Task results stay in the database

Task results are surfaced through the module's own result tables --
`vr_findings`, `vr_investigation_outcomes`, `scan_findings`,
`forensics_*`, and so on -- not as file-system artifacts referenced by
a path column. The historical `TaskRecord.result_path` column survives
for wire-shape compatibility (the column is nullable and currently
populated by no task in `src/aila/`); every consumer reads the result
from the module table or its dedicated API endpoint (e.g.
`GET /vr/investigations/{id}`, `GET /scans/{id}/findings`).

The earlier file-path pattern existed to keep SQLite row sizes
bounded under the single-writer model. PostgreSQL handles large rows
without contention, the on-disk artifact directory introduced an
orthogonal lifecycle problem (cleanup, permissions, backup), and
modules already needed structured per-result tables anyway. The
pattern was retired; `result_path` should not be populated by new
code and will be dropped in a future migration once the schema
column can be cleanly removed from every TaskResponse consumer.

### INFRA-07: No Module Cross-Imports

A module under `src/aila/modules/<a>/` must not import from
`src/aila/modules/<b>/`. Cross-module communication goes through:

- platform services (`platform.services`),
- the in-process event bus (`platform.events`),
- registered tools (`platform.tools`).

This is what keeps modules independently versionable, removable, and
testable. Static checks in CI enforce this; review rejects any PR that
introduces a module-to-module import.

### INFRA-08: Schema Changes via Alembic Only

PostgreSQL schema changes are made exclusively through Alembic
migrations under `src/aila/alembic/`. No code path may issue ad-hoc DDL
(`CREATE TABLE`, `ALTER TABLE`, index creation) at runtime, and
SQLModel `metadata.create_all()` is not used outside of dev-only test
fixtures.

**Rules:**

- Every schema change ships as a reviewed Alembic revision.
- Migrations are applied with `make migrate` (which wraps
  `cd src/aila && alembic upgrade head`); `make db-init` performs the
  one-time fresh-DB bootstrap before the first `make migrate`.
- Module-owned tables (under a module's `db_models/`) are picked up by
  Alembic's autogeneration; they still ship as explicit revisions.
- Downgrade paths must be implemented for any revision that may need
  to be rolled back in production.

This guarantees that the deployed schema is always reproducible from
version control and that no environment silently drifts.
