# AILA -- Claude Code Instructions

AILA (AI Lab Assistant) is a modular AI security platform. Python 3.11+ backend (FastAPI, SQLModel, Alembic, ARQ/Redis), React + Vite + TypeScript frontend.

## Repository Layout

```
src/aila/
  platform/       # shared infrastructure -- never imports from modules/
    contracts/     # cross-module data contracts
    modules/       # module registry and discovery
    routing/       # LLM-based request routing
    runtime/       # runtime assembly and tool registry
    services/      # shared services (audit, embedding, health, SSH, storage)
    tools/         # platform-owned tools (registry, memory, SSH, HTTP)
    llm/           # LLM client, pipelines, cost, drift, seals
    tasks/         # ARQ task queue, worker bootstrap, progress tracking
    workflows/     # workflow engine (create, advance, log)
    events/        # event emitter
    automation/    # cron-based automation runner
    sse/           # server-sent events transport
  modules/
    vulnerability/ # production -- CVE scanning, remediation, scoring
    forensics/     # production -- DFIR investigation, evidence analysis
    sbd_nfr/       # production -- Security by Design NFR assessment
    hello_world/   # reference -- minimal module proving the contract
    _template/     # scaffold -- copy to start a new module
  api/             # FastAPI app, 28 routers, auth, middleware, schemas
  storage/         # SQLModel models, Alembic migrations, config registry
  alembic/         # migration versions (alembic.ini is at src/aila/)

frontend/          # React + Vite + TypeScript
  src/platform/    # shared UI: design system, extension registry, layout
  src/app/         # app shell, routing, auth, error boundaries
  src/components/  # shared components (AilaCard, AilaBadge, EmptyState)

tests/             # pytest suite (test_e2e*.py require live infrastructure)
docs/              # canonical specs (MODULE_STANDARD, GOLDEN_RULES, etc.)
```

## Build and Verify

```bash
pip install -e ".[dev]"                              # install backend + dev deps
cd frontend && npm install && cd ..                  # install frontend deps
cd src/aila && alembic upgrade head && cd ../..      # apply migrations

# Development servers (each in a separate terminal)
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload
cd frontend && npm run dev                           # port 3000
python -m aila worker                                # default queue
python -m aila worker -q vulnerability               # vulnerability queue
python -m aila worker -q forensics                   # forensics queue

# Quality gates (all must pass before submitting changes)
python -m ruff check src/aila/                       # lint
python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py
python -m compileall -q src/aila                     # smoke compile
cd frontend && npm run typecheck                     # TypeScript check
cd frontend && npm run build                         # production build

# Tests
python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py -x

# Or use make:
make check     # lint + honesty + compile + typecheck
make test      # unit tests
```

## Module Authoring

To create a new module:
1. Copy `src/aila/modules/_template/` to `src/aila/modules/<your_module>/`
2. Rename all Template/TEMPLATE placeholders
3. Register in `src/aila/platform/modules/builtin.py`
4. See `docs/MODULE_STANDARD.md` for the complete specification
5. Reference `src/aila/modules/hello_world/` as a working example

Module structure:
```
module.py        # ModuleProtocol + create_module()
runtime.py       # handle() request handler
capabilities.py  # MODULE_DESCRIPTION, MODULE_TOOLS, MODULE_EXAMPLES
tool_keys.py     # tool key constants (prefixed: module_id.tool_name)
workflow.py      # state machine (or workflow/ package for complex ones)
contracts/       # Pydantic models
tools/           # Tool subclasses
services/        # domain services
reporting/       # report generation
api_router.py    # optional HTTP router factory
frontend/        # optional React UI (spec.ts exports ModuleFrontendSpec)
```

## Non-Negotiable Rules

### 1. No legacy preservation
Delete old code. Do not add fallbacks, compatibility fields, alias fields, or shims.

### 2. No structural dishonesty
No string-mirroring constants, forwarding wrappers, fake managers, reflection for fixed sets, or "agent" naming for simple dispatch.

### 3. No hidden smartness
No deceptive routing, fake personalization, unjustified confidence, or hidden deterministic parsing to bypass the model.

### 4. Explicit state machines over implicit flow
Multi-step behavior uses staged workflows with named states, not nested condition chains.

### 5. Respect ownership boundaries
- Platform owns: routing, runtime, services, contracts, tools, task queue
- Modules own: domain logic, module-specific contracts/tools/services, reports, workflow
- Platform never imports from `aila.modules.*`
- Modules never import from each other

## Common Mistakes

1. **Top-level api_router import in module.py** -- MODULE_STANDARD requires deferred import inside `route_specs()`. The honesty audit catches this.

2. **Bare `except Exception`** -- Catch specific types: `(OSError, TimeoutError, RuntimeError)` for infra paths. The honesty audit flags silent swallows.

3. **Missing `__all__`** -- Every `__init__.py` and public module needs `__all__`. Underscore-prefixed private modules omit it.

4. **CSS variables in SVG** -- Recharts `fill` attributes don't resolve CSS `var(--color-*)`. Use `getComputedStyle` via the `useThemeChartColors()` hook.

5. **Tailwind v4 arbitrary values** -- `h-[720px]`, `bg-[#131313]` don't generate CSS in Tailwind v4. Use inline `style={{ height: 720 }}` instead.

6. **Schema changes without Alembic** -- All DDL goes through `src/aila/alembic/versions/`. No runtime CREATE TABLE, no `metadata.create_all()` outside test fixtures.

7. **Config via `os.getenv` instead of ConfigRegistry** -- Module-scoped config uses `ConfigRegistry.get()`, which resolves env var -> DB -> schema default.

8. **Workers don't auto-reload** -- After Python file changes, kill and restart workers. Clear `__pycache__` if bytecode is stale.

9. **Passing Pydantic models as task kwargs** -- Every kwarg to a `@platform_task`-decorated function or `DurableStateMachine.execute()` must be JSON-serializable. `RunState`, `RouteDecision`, `ModuleRequest`, and any `BaseModel` subclass must be `.model_dump(mode="json")`-serialized before passing. The workflow engine validates this at runtime and crashes with a clear `TypeError` if violated.

10. **`session.add()` on potentially-existing rows** -- When a `WorkflowRunRecord` or other row may already exist (e.g., created by `_ensure_run_record`), use `session.merge()` instead of `session.add()`. ORM `add()` always INSERTs; `merge()` does INSERT-or-UPDATE based on PK.

## Verification Checklist

Before yielding any change:
- [ ] `python -m compileall -q src/aila` -- no syntax errors
- [ ] `python -m ruff check src/aila/` -- clean
- [ ] `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py` -- zero findings
- [ ] `cd frontend && npm run typecheck` -- clean (if frontend changed)
- [ ] Tests covering the changed behavior pass
- [ ] No stale imports, no dead code introduced
