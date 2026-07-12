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

15. **Tailwind classes in module frontends have no CSS rules** -- Tailwind v4 scans content starting from the directory containing `frontend/src/styles/globals.css`. Module frontends live OUTSIDE `frontend/src/` (under `src/aila/modules/<name>/frontend/`), reached only via pnpm symlinks in `node_modules/@aila/*` which Tailwind ignores by default. A class added in a module-side file gets NO CSS rule generated unless that same class is also used somewhere inside `frontend/src/`. Symptom: `position: fixed` with `bottom-6 right-6` renders at flow position because the inset rules don't exist. Fix: add `@source "../../../src/aila/modules/<name>/frontend/**/*.{ts,tsx}";` to `frontend/src/styles/globals.css` for every module. Already wired for vr, vulnerability, forensics, hello_world, malware.

16. **Module page components wrapping their own `<PageShell>`** -- The shell's `protectPage` in `frontend/src/app/router.tsx` already wraps every routed module page in `<PageFrame>` which renders the title bar. If the page component ALSO returns `<PageShell title=...>`, you get two stacked `<h1>` blocks + two icon badges. VR's screens render bare `<div>` fragments and let the shell own the title. Malware screens were authored against the wrong pattern initially and produced doubled headers across all 22 pages until stripped. Mirror VR's pattern: return content directly, hoist any page-level CTAs into an in-body top-of-page `flex items-center justify-between` row.

17. **JSX escape sequence leaks** -- `\u00b7` / `\u2026` / `\u2715` written as bare text inside JSX children (NOT inside string literals) render literally as `\u00b7`, not as `\u00b7`. JSX child text is taken verbatim. Either use the actual glyph or wrap in `{"\u00b7"}` so it parses as a string literal.

18. **Module summary contracts with `ConfigDict(extra="forbid")` reject undeclared kwargs at response-serialization time** -- The 500 fires AFTER the underlying DB row has committed (request handler ran, then Pydantic rejected the response shape on the way out). The operator sees a generic error toast but the row is in fact persisted. Fix at the source: add the missing field to the contract. Pattern: every `_<x>_summary()` helper kwarg MUST appear on the matching Pydantic `BaseModel`. Surfaced in this codebase on `MalwareTargetSummary.capability_profile`.

19. **`@platform_task` collides on `__name__` across modules** -- The decorator's wrapper at `aila/platform/tasks/template.py:558` sets `_wrapper.__name__ = fn.__name__`. ARQ keys its function name resolution by the bare `__name__`, so two modules each defining `run_target_analysis` collide -- the later-loaded module overwrites the earlier registration. Symptom: queue X dispatches X's job but a Y-module function runs the body. Fix: name module tasks with the module prefix (e.g. `run_malware_target_analysis`). Worth fixing upstream (set `_wrapper.__name__ = registry_name` for the qualified key) but not in any current scope.

20. **TaskQueue constructor takes `(config_registry, module_id)`, NOT `track`** -- `track` is a `.submit()` kwarg, not a constructor kwarg. The canonical pattern (mirror VR's `_task_queue.py`): `return TaskQueue(config_registry=ConfigRegistry(), module_id="<module_id>")`. A wrong constructor signature crashes at every enqueue site silently if the only call path is wrapped in a `try/except` warning logger.

21. **`extra="forbid"` + cross-module constraint name collisions in Alembic migrations** -- Postgres constraint names are unique per schema, not per table. Two modules both declaring a constraint named `uq_workspace_team_slug` (one on `vr_workspaces`, one on `malware_workspaces`) collide on `CREATE TABLE`. Prefix every named constraint with the module: `uq_malware_workspace_team_slug`, `uq_vr_workspace_team_slug`.

22. **`start.sh` WORKERS default needs every module's queue** -- Currently `default vr vulnerability forensics malware`. A queue absent from this list has no worker listening; tasks land in Redis and sit forever (display reads as `Queued`). The malware module's tasks all declare `track="malware"` so the worker line is `python -m aila worker -q malware`. After adding a new module that declares its own `track`, append the queue name and restart workers.

23. **`ida-headless-mcp-exp` runs on port 18821** -- Not 18820. Multiple malware backend files were initialized with 18820 as the default; they were wrong. The canonical port is 18821 (matches the `IDA_HEADLESS_PORT` default in `start.sh`). Per-server URL overrides go through `IDA_HEADLESS_EXP_URL` env or `PATCH /malware/mcp/servers/ida_headless_exp` (live, no restart needed).

24. **Operator Resume/Retrigger writing `analysis_state="pending"` directly** -- The handlers in `api_router.py` rewrite the row's overall state column but DO NOT touch the per-stage state in `analysis_stages_json`. Next worker run hits `StageAlreadyDoneError`, logs "already ingested -- skip", and returns. Without an explicit `load_target_stages` -> `save_target_stages` re-roll on that skip path, the row sits at `pending` forever even though every applicable stage is DONE. The malware module's skip path does the re-roll; copy that pattern when adding new resume-style handlers.

## Verification Checklist

Before yielding any change:
- [ ] `python -m compileall -q src/aila` -- no syntax errors
- [ ] `python -m ruff check src/aila/` -- clean
- [ ] `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py` -- zero findings
- [ ] `pnpm -r run type-check` -- clean (if frontend changed)
- [ ] `pnpm --filter @aila/shell run build` -- exits 0 (if frontend changed)
- [ ] Tests covering the changed behavior pass
- [ ] No stale imports, no dead code introduced

## Development Workflow (versioning + release management)

Every non-trivial change follows this flow. No direct commits to
`main` for feature work; `main` always reflects the last released,
green state.

### Branch model

- `main` -- released state only. Protected in spirit: feature work
  never lands here directly. A release reaches `main` only by merging
  a reviewed PR.
- `dev` -- integration branch. All feature/fix work is committed here
  (or on short-lived `feat/*` / `fix/*` branches cut from `dev` and
  merged back into `dev`).
- Flow: work on `dev` -> version + changelog on `dev` -> push `dev`
  -> open PR `dev -> main` -> merge -> tag the release commit on
  `main`.

### Semantic versioning (semver 2.0.0)

Current version lives in `pyproject.toml` and is mirrored across the
workspace (see version sites below). Decide the bump from the change,
not from habit:

- MAJOR (`X.0.0`) -- a breaking change: removed/renamed public API,
  a contract field made required, a DB column dropped, a route
  removed, or any change that forces callers/operators to migrate.
- MINOR (`0.X.0`) -- a backward-compatible feature: new action /
  field with a safe default, new route, new module, new tool. Old
  callers keep working untouched.
- PATCH (`0.0.X`) -- a backward-compatible bug fix or internal
  refactor with no API/observable-behavior change.

When in doubt between MINOR and MAJOR, it is MAJOR -- assume a caller
depends on the thing you changed.

### Version sites (bump ALL in lockstep -- the repo speaks one version)

The monorepo is deliberately harmonized to a single version string.
Bumping the version means editing every one of these to the SAME
value in the same commit:

- `pyproject.toml` -> `version = "X.Y.Z"`
- `package.json` (root) -> `"version": "X.Y.Z"`
- `frontend/package.json`
- `packages/typescript-config/package.json`
- `src/aila/modules/*/frontend/package.json` (every module frontend:
  vr, vulnerability, forensics, malware, hello_world)
- `tools/aila_fuzz_reporter/__init__.py` -> `__version__ = "X.Y.Z"`

`workspace:*` deps mean a version bump does NOT churn
`pnpm-lock.yaml`; run `pnpm install --lockfile-only` and confirm the
lockfile diff is empty (or commit it if pnpm regenerated it).

### CHANGELOG (Keep a Changelog format)

`CHANGELOG.md` follows https://keepachangelog.com. Every release adds
one `## [X.Y.Z] - YYYY-MM-DD -- <one-line summary>` entry above the
prior one, grouped by `### Added` / `### Changed` / `### Fixed` /
`### Removed`. Rules:

- Write the entry ON `dev` as part of the release commit, dated the
  day the PR is opened.
- Neutral technical voice only. NEVER quote operator chat, NEVER use
  em-dashes (use `--`), NEVER name private inv/UUIDs or brands. Same
  banned-prose rules as every other artifact (see user-global
  CLAUDE.md).
- Describe observable behavior change, not the diff. "Live hypotheses
  now render in full" -- not "changed hypotheses[:10] to a ceiling".

### Release checklist (in order, on `dev`)

1. All Verification Checklist items above pass.
2. Decide the semver bump; edit every version site in lockstep.
3. Add the CHANGELOG entry.
4. One commit: feature change + version bump + changelog together.
   Conventional-commit subject (`feat:` / `fix:` / `refactor:`),
   neutral voice, no operator quotes.
5. `git push origin dev`.
6. Open PR `dev -> main` (`gh pr create --base main --head dev`).
7. On merge, tag the merge commit: `git tag vX.Y.Z && git push
   origin vX.Y.Z`. The tag is cut on `main` AFTER merge, never before.

### DB changes gate

If the change touches schema, an Alembic migration in
`src/aila/alembic/versions/` is part of the SAME commit (see Common
Mistake 6). A release that changes models without a migration is
incomplete. Pure in-memory / logic / render changes need no
migration -- state that explicitly in the changelog reasoning when
relevant.

## Bridge + workflow gotchas (session learnings, 2026-05-24)

A long debugging session on investigation `<inv-uuid>` (WebAssembly RCE
variant hunt) exposed a stack of bugs that were silently breaking
investigations. These rules are the operational lessons:

### MCP adapter rules

1. **audit_mcp `read_function` returns `content`, NOT `source`.** The
   `source` field is the literal provider tag (e.g. `"semble"`,
   `"trailmark"`). For months the adapter read `source` first and
   stored the literal string `"semble"` as the function body. Always
   `raw.get("content") or raw.get("body") or raw.get("text")` --
   NEVER `source`. See `audit_mcp.py:adapt_read_function`.

2. **`search_functions` returns `file_path: null` for ~half the
   indexed functions** (trailmark loses locations). The generic
   `_render_matches_dense` produces literal `?:?:` rows from these.
   Use the specialized `adapt_search_functions` that renders the
   actual fields (name, kind, cyclomatic_complexity).

3. **`search_constants`, `search_bitfields` return 0 results for
   patterns that exist in source.** Trailmark's index doesn't track
   them on this codebase. Tell the agent in the prompt -- don't
   recommend these as the primary path.

4. **`semantic_search` and `find_related` return code CHUNKS** with
   `{file_path, start_line, end_line, content}` per result. They have
   their own adapters; do NOT fall through to generic JSON dump.

5. **`read_lines` is a bridge-side virtual tool** -- no upstream MCP
   endpoint. Bridge resolves `index_id → root_path` via
   `/tools/list_indexes` then reads the file slice from disk. Use
   this when the agent has a precise `(file_path, start, end)` and
   needs verbatim source bypassing all indexers.

6. **No per-tool-call truncation.** All `_MAX_OBS_*` caps are set to
   100MB. Per-value caps were causing silent body truncation; the
   policy now is full content stored, render layer decides display.

### Workflow / cursor mechanism

1. **`__crashed__` cursors persist forever** unless explicitly
   cleared. The `/re-enqueue` handler now wipes them for the target
   investigation. Standalone reaper for orphans across the whole
   table not yet shipped -- operator can `DELETE FROM
   workflow_state_cursor WHERE current_state = '__crashed__' AND NOT
   EXISTS (SELECT 1 FROM taskrecord t WHERE t.id = run_id AND
   t.status IN ('queued','running','waiting'))` to bulk-clean.

2. **`safe_exc_message()` redacts to class name** per Phase 178
   security policy. The cursor row stores ONLY `"UnboundLocalError"`
   etc. -- no message, no traceback. The engine's crash paths
   (`_force_crashed`, handler-raised) now also `_log.exception(...)`
   so the operator-private worker log gets the full traceback.

3. **Three sources of truth for "is this task active":**
   `TaskRecord.status` (DB), `workflow_state_cursor.current_state`,
   `arq:in-progress:<id>` (Redis). They CAN desync. The D-86 SKIP
   path now coordinates all three. New drift paths are landmines --
   inspect all three before claiming a task is running/stuck.

4. **Worker D-86 SKIP `rec.completed_at` not `rec.finished_at`** --
   TaskRecord has no `finished_at` column. Typoing it raises
   `AttributeError` inside the reaper loop, which is caught silently
   higher up, leaving the cursor in an inconsistent state.

### Agent-loop structural rules

1. **Sibling rejections don't auto-propagate.** Each branch's
   case_state is private. Halvar will keep h1 live forever even
   after Maddie + Renzo reject it. The `_render_sibling_consensus`
   directive at `vuln_researcher.py` injects an explicit
   `_directive.sibling_consensus_rejection` observable when 2+
   siblings reject an id this branch still has live.

2. **Operator messages need ACK.** The agent emits
   `observables: { "_acked_operator_messages": "<id1>,<id2>" }` to
   stop a steering message from re-appearing. Without ACK,
   operator messages re-fire on every turn within the wall-clock
   TTL (24h).

3. **Idempotency: every LLM call is request-keyed**. Cache table
   `llm_idempotency_cache` (migration 061) stores responses by
   sha256(investigation_id, branch_id, turn_number, prompt_hash).
   Retries replay the cached decision instead of re-paying for
   Claude. Caller-supplied keys live in `vuln_researcher.run_turn`.

4. **Agent self-bloats observables.** They invent scratchpad keys
   like `sibling_renzo_h7`, `mandatory_next`, `critic_open_question`.
   `absorb()` caps agent-set obs at 10/turn + 50 total; tool-prefix
   keys (audit_mcp:*, ida_headless:*, _directive.*) are never
   evicted. `render_case_model` partitions tool readings (shown
   unlimited, capped at 80 display) from agent scratchpad (capped
   at 15 display).

### Operations

1. **`start.sh` has per-service restart**: `restart-backend`,
   `restart-frontend`, `restart-workers`, `restart-worker <queue>`,
   `restart-audit-mcp`. Use these instead of full `restart` to
   avoid losing firefox semble cache (~9s reload from pickle).

2. **`record_pid` uses `RUN_DIR_ABS`** (absolute) so subshells
   that `cd` elsewhere (audit-mcp launches in its own repo) still
   write the pidfile into AILA's `.run/`.

3. **Windows uvicorn must run with `--loop asyncio`** (selector
   event loop). The default Proactor loop leaks IOCP socket handles
   on abnormal exit -- port appears owned by a phantom PID forever.
   `start.sh` backend launch enforces `--loop asyncio`.

4. **PowerShell `Start-Process` discards bash env vars on
   Windows.** Pass `--workers N` as CLI flag, NOT
   `AUDIT_MCP_WORKERS=N` env prefix.

### Auto-steering pattern

`tool_executor` calls `maybe_post_auto_steering(...)` after every
tool dispatch. When a result matches a known dead-end pattern
(`read_lines` past EOF, `read_function` returning file header from
indexer fault), the system POSTS an operator message to the
investigation with the corrective info -- identical DB write to the
UI's chat composer. Lands at PROMPT POSITION 2 on every branch's
next turn under `*** OPERATOR STEERING -- MANDATORY OVERRIDE ***`.
De-dupes by `(rule, target_file, target_symbol)` key; allows
re-post once all prior matching steerings are ACKed (so a recurring
condition can re-fire after the agent ignores the first one). To
add a new rule: write `_detect_X` + `_derive_X_correction` in
`auto_steering.py` and branch in `maybe_post_auto_steering`.

### Cost tracking known-broken

`VRInvestigationRecord.cost_actual_usd` shows $0 forever. The
aggregator in `api_router._compute_live_investigation_cost` joins
`LLMCostRecord.run_id == TaskRecord.id` -- but `run_id` is actually
the workflow `RunRecord.id` (DurableStateMachine run instance),
not the ARQ TaskRecord id. The correct join needs an extra hop
through `workflow_run_records`. Not yet fixed.

### audit-mcp async-first runtime (commit 16cb963 in audit-mcp repo, 2026-05-28)

Concurrency issue: identical sibling-branch tool calls used to
serialize on the GIL inside the anyio worker-thread pool. 3 branches
asking the same `semantic_search('foo')` paid 3× the cost. Long
`index_codebase` runs starved every other tool by holding pool
slots. Semble cold-build hangs were unbounded.

Resolved by `audit_mcp/async_runtime.py` (new) + `audit_mcp/http_api.py`
rewrite. Operator-facing knobs:

|Env var|Default|Effect|
|---|---|---|
|`AUDIT_MCP_THREAD_POOL_LIMIT`|`64`|anyio worker-thread pool size (was 40). Bump if you see "all threads busy" without dedup help.|
|`AUDIT_MCP_TOOL_CAP_<TOOLNAME>`|see `DEFAULT_TOOL_CAPS`|Per-tool concurrency cap. e.g. `AUDIT_MCP_TOOL_CAP_SEMANTIC_SEARCH=8` doubles the default. Tool name is uppercased.|
|`AUDIT_MCP_TIMEOUT_<TOOLNAME>`|see `DEFAULT_TOOL_TIMEOUTS_S`|Per-tool wall-clock timeout. e.g. `AUDIT_MCP_TIMEOUT_DEEP_AUDIT=1200`.|
|`AUDIT_MCP_SEMBLE_BUILD_TIMEOUT_S`|`7200` (2h)|Bounded `subprocess.communicate(timeout=...)` for the semble cold-build child. Was unbounded; a stuck child would hold `semble_status='building'` forever.|

Diagnostics: `GET http://127.0.0.1:18822/runtime` returns live
`{dedup: {inflight, hits, misses}, semaphores: {<tool>: {cap,
available}}, thread_pool_limit}`. When agents report "audit_mcp slow"
check this endpoint first -- `available: 0` on a tool = that tool is
the bottleneck; bump its cap via env. High `misses` with low `hits` =
sibling branches aren't asking the same questions, which is fine; high
`hits` = dedup is doing real work.

Backward compat: every existing tool keeps its current sync signature.
The HTTP layer wraps them. Stdio transport (`audit_mcp/server.py`) is
unchanged. Async tools (`tool.is_async == True`) now WORK -- previously
the HTTP transport refused them at startup with a hard `RuntimeError`.
