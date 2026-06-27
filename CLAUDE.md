# AILA -- Claude Code Instructions

AILA (AI Lab Assistant) is a modular AI security platform. Python 3.11+ backend (FastAPI, SQLModel, Alembic, ARQ/Redis), React 19 + Vite 8 + TypeScript 6 frontend organized as a pnpm workspace.

## Repository Layout

```
AILA/
├── package.json                  # workspace root: scripts, packageManager pnpm@10.x
├── pnpm-workspace.yaml           # workspace members + pnpm catalogs (version pinning)
├── pnpm-lock.yaml                # single lockfile for the entire JS workspace
├── .npmrc                        # save-prefix='', strict peers, hoist patterns
├── packages/
│   └── typescript-config/        # @aila/typescript-config: shared tsconfig variants
├── frontend/                     # @aila/shell: the React SPA host
│   ├── src/platform/             # shared UI: design system, extension registry, layout
│   ├── src/app/                  # app shell, routing, auth, error boundaries
│   ├── src/components/           # shared components (AilaCard, AilaBadge, EmptyState)
│   └── vite.config.ts            # @/, @app, @platform aliases only
├── scripts/
│   └── db_init.py                # bootstrap a fresh database (create tables + stamp head)
├── src/aila/
│   ├── platform/                 # shared infrastructure -- never imports from modules/
│   │   ├── contracts/            # cross-module data contracts
│   │   ├── modules/              # module registry and discovery
│   │   ├── routing/              # LLM-based request routing
│   │   ├── runtime/              # runtime assembly and tool registry
│   │   ├── services/             # shared services (audit, embedding, health, SSH, storage)
│   │   ├── tools/                # platform-owned tools (registry, memory, SSH, HTTP)
│   │   ├── llm/                  # LLM client, pipelines, cost, drift, seals
│   │   ├── tasks/                # ARQ task queue, worker bootstrap, progress tracking
│   │   ├── workflows/            # workflow engine (create, advance, log)
│   │   ├── events/               # event emitter
│   │   ├── automation/           # cron-based automation runner
│   │   └── sse/                  # server-sent events transport
│   ├── modules/
│   │   ├── vulnerability/        # production -- CVE scanning, remediation, scoring
│   │   │   ├── frontend/         # @aila/vulnerability-frontend (own package.json)
│   │   │   └── ...
│   │   ├── forensics/            # production -- DFIR investigation
│   │   │   └── frontend/         # @aila/forensics-frontend
│   │   ├── hello_world/          # reference -- minimal module proving the contract
│   │   │   └── frontend/         # @aila/hello-world-frontend
│   │   └── _template/            # scaffold -- copy to start a new module
│   ├── api/                      # FastAPI app, 28 routers, auth, middleware, schemas
│   ├── storage/                  # SQLModel models, Alembic migrations, config registry
│   └── alembic/                  # migration versions
├── tests/                        # pytest suite (test_e2e*.py require live infrastructure)
└── docs/                         # canonical specs (MODULE_STANDARD, GOLDEN_RULES, etc.)
```

## Build and Verify

```bash
# Initial setup
pip install -e ".[dev]"                              # install backend + dev deps
corepack enable && pnpm install                      # install frontend (pnpm workspace)

# Bring up dev infra (Postgres with pgvector + Redis)
make dev-up                                          # docker compose -f infra/utilities/docker-compose.yml
make db-init                                         # create tables, stamp at head (FIRST RUN ONLY)
make migrate                                         # apply any future migrations

# Development servers (each in a separate terminal)
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload
pnpm dev                                              # frontend at http://localhost:3000
python -m aila worker                                # default worker queue
python -m aila worker -q vulnerability               # vulnerability queue
python -m aila worker -q forensics                   # forensics queue

# Quality gates (all must pass before submitting changes)
python -m ruff check src/aila/                       # lint
python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py
python -m compileall -q src/aila                     # smoke compile
pnpm -r run type-check                                # TypeScript across shell + modules
pnpm --filter @aila/shell run build                  # production build (single SPA)

# Tests
python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py -x
pnpm -r run test                                      # frontend unit tests (shell + modules)

# Or use make
make install        # full setup (pip + pnpm)
make dev-up         # start postgres + redis (idempotent)
make dev-down       # stop services (keeps data)
make dev-reset      # stop services and wipe volumes
make dev-logs       # tail compose logs
make dev-status     # `docker compose ps`
make db-init        # create tables + stamp head (one-time, fresh DB only)
make migrate        # alembic upgrade head
make check          # lint + honesty + compile + typecheck
make test           # backend unit tests
make test-frontend
make backend frontend worker          # dev servers (each in separate terminal)
```

> Dev infra lives at `infra/utilities/docker-compose.yml` (Postgres 16 with pgvector, Redis 7). Postgres init scripts at `infra/postgres-init/` enable the pgvector extension on first volume creation.

## Frontend pnpm Workspace

The frontend is a pnpm workspace. Every package and module declares its own deps; pnpm catalogs in `pnpm-workspace.yaml` pin shared versions globally.

### Workspace members

| Package                            | Path                                       | Role                                                |
|------------------------------------|--------------------------------------------|-----------------------------------------------------|
| `@aila/shell`                      | `frontend/`                                | The host React SPA. Imports each module by name.    |
| `@aila/typescript-config`          | `packages/typescript-config/`              | Shared tsconfigs: `./base`, `./react-vite`, `./react-module` |
| `@aila/hello-world-frontend`       | `src/aila/modules/hello_world/frontend/`   | Reference module                                    |
| `@aila/vulnerability-frontend`     | `src/aila/modules/vulnerability/frontend/` | Vulnerability module UI                             |
| `@aila/forensics-frontend`         | `src/aila/modules/forensics/frontend/`     | Forensics module UI                                 |

### Catalogs

`pnpm-workspace.yaml` defines named catalogs (`react19`, `router`, `vite`, `tailwind`, `query`, `ui`, `dnd`, `flow`, `testing`, `storybook`, `types`, `maps`, `particles`, `data`). Packages reference deps by catalog, never by literal version:

```json
{
  "dependencies": {
    "@dnd-kit/core": "catalog:dnd"
  },
  "peerDependencies": {
    "react": "catalog:react19",
    "react-router": "catalog:router"
  }
}
```

To bump a shared version, edit the catalog entry once. To add a new shared dep, add it to a catalog and reference it from each consumer.

### Common pnpm commands

```bash
pnpm install                                # install / sync all workspace packages
pnpm dev                                    # alias for: pnpm --filter @aila/shell run dev
pnpm build                                  # alias for: pnpm --filter @aila/shell run build
pnpm -r run type-check                      # typecheck across all workspace packages
pnpm -r run test                            # vitest across all workspace packages
pnpm --filter @aila/vulnerability-frontend run type-check   # one module
pnpm add <pkg> --filter @aila/<module>-frontend             # add a dep to a single module
```

## Module Authoring

To create a new module:
1. Copy `src/aila/modules/_template/` to `src/aila/modules/<your_module>/`
2. Rename all Template/TEMPLATE placeholders
3. Register in `src/aila/platform/modules/builtin.py`
4. If the module has a frontend:
   - Add `frontend/package.json` (name `@aila/<module>-frontend`, see hello_world for reference)
   - Add `frontend/tsconfig.json` extending `@aila/typescript-config/react-module`
   - Add `"@aila/<module>-frontend": "workspace:*"` to `frontend/package.json` (the shell)
   - Import its `frontendSpec` in `frontend/src/platform/extension-registry/loadModuleSpecs.ts`
5. Run `pnpm install` to wire up the workspace symlinks
6. See `docs/MODULE_STANDARD.md` and `docs/FRONTEND_MODULE_STANDARD.md` for the complete specifications
7. Reference `src/aila/modules/hello_world/` as a working example

### Module structure

```
module.py             # ModuleProtocol + create_module()
runtime.py            # handle() request handler
capabilities.py       # MODULE_DESCRIPTION, MODULE_TOOLS, MODULE_EXAMPLES
tool_keys.py          # tool key constants (prefixed: module_id.tool_name)
workflow.py           # state machine (or workflow/ package for complex ones)
contracts/            # Pydantic models
tools/                # Tool subclasses
services/             # domain services
reporting/            # report generation
api_router.py         # optional HTTP router factory
frontend/             # optional React UI
  package.json        # @aila/<module>-frontend, declares deps + peer deps
  tsconfig.json       # extends @aila/typescript-config/react-module
  spec.ts             # exports ModuleFrontendSpec via `frontendSpec`
  routes.tsx          # route definitions
  screens/            # top-level screens
  components/         # module-local components
```

### Frontend dep allocation rules

| Layer            | Owner                                         |
|------------------|-----------------------------------------------|
| Framework        | shell direct, modules `peerDependencies`      |
| Data / state     | shell direct, modules `peerDependencies`      |
| Design system    | shell direct, modules `peerDependencies`      |
| Module-specific  | module `dependencies`                         |
| Test-only        | module `devDependencies`                      |

Modules MUST NOT depend on other `@aila/<module>-frontend` packages. Cross-module communication goes through the shell's extension registry.

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
- Modules never import from each other (Python OR frontend -- pnpm strict mode enforces this at install time by failing on undeclared bare imports)

### 6. Frontend dep ownership
- Every bare import in a module's frontend MUST be declared in that module's `package.json` (deps, peerDeps, or devDeps)
- Shared versions go through pnpm catalogs in `pnpm-workspace.yaml`, never as literal versions
- The shell never imports from a module-specific dep that no other code uses (e.g., `@dnd-kit/*` is owned by `@aila/vulnerability-frontend`, not the shell)

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

11. **Adding a frontend bare import without declaring it in the module's `package.json`** -- Every module is a pnpm workspace package at `src/aila/modules/<name>/frontend/`. pnpm strict mode catches missing deps at install time. Fix by adding the dep to `dependencies`, `peerDependencies` (for shell-owned packages), or `devDependencies` (for test-only).

12. **Using `react-router-dom`** -- React Router v7 unified `react-router-dom` and `react-router`. The codebase canonicalizes on `react-router`. New code must import from `react-router` only.

13. **Using literal versions in module `package.json`** -- Shared deps (react, vite, tailwind, etc.) must reference catalog entries (`"react": "catalog:react19"`). Only module-specific deps that aren't shared may use literal versions, and even those should be added to a catalog if a second consumer appears.

14. **Hand-editing `pnpm-lock.yaml`** -- Always re-run `pnpm install` to regenerate. The lockfile format is structured but not designed for manual edits.

## Verification Checklist

Before yielding any change:
- [ ] `python -m compileall -q src/aila` -- no syntax errors
- [ ] `python -m ruff check src/aila/` -- clean
- [ ] `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py` -- zero findings
- [ ] `pnpm -r run type-check` -- clean (if frontend changed)
- [ ] `pnpm --filter @aila/shell run build` -- exits 0 (if frontend changed)
- [ ] Tests covering the changed behavior pass
- [ ] No stale imports, no dead code introduced
