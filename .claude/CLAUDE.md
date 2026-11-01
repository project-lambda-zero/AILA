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
├── tools/
│   ├── oxlint/                   # @aila/oxlint-config: oxlint anti-slop rule plugin (workspace member)
│   └── aila_fuzz_reporter/       # Python fuzz-reporter helper
├── frontend/                     # @aila/shell: the single React SPA (console UI)
│   ├── src/App.tsx               # console shell: auth gate, windows, rails
│   ├── src/console/              # nav.ts (MODULES), contract.ts, pages/ (page registry), wizards/, widgets/, window/
│   ├── src/api/                  # typed API client + TanStack Query hooks
│   ├── src/styles/globals.css    # plain CSS + custom properties (no Tailwind)
│   └── vite.config.ts            # vite + react plugin, manual vendor chunks
├── scripts/
│   └── db_init.py                # bootstrap a fresh database (create tables + stamp head)
├── src/aila/
│   ├── platform/                 # shared infrastructure -- never imports from modules/
│   │   ├── agents/               # shared reasoning-agent base: AgentTurnRunnerBase, ToolExecutorHelpersBase, submit gates, auto-steering
│   │   ├── mcp/                  # native MCP client, server specs, middleware, adapters, bridge tools
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
│   │   ├── vulnerability/        # production -- CVE scanning, remediation, scoring (pipeline module)
│   │   ├── vr/                   # production -- vulnerability research (reasoning module)
│   │   ├── malware/              # production -- static malware analysis (reasoning module)
│   │   ├── forensics/            # production -- DFIR investigation
│   │   ├── hello_world/          # reference -- minimal module proving the contract
│   │   └── _template/            # scaffold -- copy to start a new module
│   ├── api/                      # FastAPI app, routers/, auth, middleware, schemas
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
python -m aila.tools.liveness_audit src/aila --whitelist liveness_whitelist.py
python -m compileall -q src/aila                     # smoke compile
pnpm -r run type-check                                # TypeScript across the workspace (shell)
pnpm --filter @aila/shell run build                  # production build (single SPA)

# Tests
python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py -x

# Or use make
make install        # full setup (pip + pnpm)
make dev-up         # start postgres + redis (idempotent)
make dev-down       # stop services (keeps data)
make dev-reset      # stop services and wipe volumes
make dev-logs       # tail compose logs
make dev-status     # `docker compose ps`
make db-init        # create tables + stamp head (one-time, fresh DB only)
make migrate        # alembic upgrade head
make check          # lint + honesty + liveness + liveness-guard + compile + typecheck
make test           # backend unit tests
make backend frontend worker          # dev servers (each in separate terminal)
```

> Dev infra lives at `infra/utilities/docker-compose.yml` (Postgres 16 with pgvector, Redis 7). Postgres init scripts at `infra/postgres-init/` enable the pgvector extension on first volume creation.

## Frontend pnpm Workspace

The frontend is a pnpm workspace with one SPA. Modules do NOT ship their own frontend packages: every module's UI is a page or wizard inside the shell. pnpm catalogs in `pnpm-workspace.yaml` pin shared versions globally.

### Workspace members

`pnpm-workspace.yaml` `packages:` lists `frontend`, `packages/*`, and `tools/oxlint`.

| Package                            | Path                                       | Role                                                |
|------------------------------------|--------------------------------------------|-----------------------------------------------------|
| `@aila/shell`                      | `frontend/`                                | The React SPA (console shell + every module page)   |
| `@aila/typescript-config`          | `packages/typescript-config/`              | Shared tsconfigs: `./base`, `./react-vite`, `./react-module` |
| `@aila/oxlint-config`              | `tools/oxlint/`                            | oxlint anti-slop rule plugin used by `pnpm --filter @aila/shell run lint` |

### Catalogs

`pnpm-workspace.yaml` defines the top-level `catalog:` slot (TypeScript) plus named catalogs `react19`, `vite`, `query`, `ui`, `lint`, and `types`. Packages reference deps by catalog, never by literal version:

```json
{
  "dependencies": {
    "react": "catalog:react19",
    "@tanstack/react-query": "catalog:query"
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
pnpm --filter @aila/shell run lint          # oxlint over frontend/src
pnpm add <pkg> --filter @aila/shell         # add a dep to the shell
```

## Module Authoring

To create a new module:
1. Copy `src/aila/modules/_template/` to `src/aila/modules/<your_module>/`
2. Rename all Template/TEMPLATE placeholders
3. Register in `src/aila/platform/modules/builtin.py`
4. If the module has a UI, add it to the shell (there is no per-module frontend package):
   - Add a `ModuleDef` entry (id, label, noun, pages) to `MODULES` in `frontend/src/console/nav.ts`
   - Map each page id to a renderer in `frontend/src/console/pages/registry.tsx` (data-table pages use `DataPage` with a `PAGE_CONFIGS` entry from `frontend/src/console/pages/configs`; bespoke pages are lazy-loaded components taking `ModulePageProps` from `frontend/src/console/contract.ts`)
   - Typed API calls live in `frontend/src/api/`
5. See `docs/MODULE_STANDARD.md` and `docs/FRONTEND_MODULE_STANDARD.md` for the complete specifications
6. Reference `src/aila/modules/hello_world/` as a working example

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
agents/               # reasoning modules only (see "Reasoning agents" below)
```

Reasoning modules also carry `db_models/`, `config_schema.py`, and a `workflow/` package; see `src/aila/modules/_template/` for the minimal shape. The module UI is not part of the module directory: it lives in the shell (`frontend/src/console/`).

### Reasoning agents

The shared per-branch turn loop lives in `src/aila/platform/agents/turn_runner.py`: `AgentTurnRunnerBase` (`turn_runner.py:146`, `run_turn` at `:881`). A module researcher subclasses it, sets the config class attributes (`_LOG_LABEL`, `_MODULE_ID`, ...), binds its module-level helpers, and overrides the behavior hooks. `HonestVulnResearcher` (`modules/vr/agents/vuln_researcher.py:175`), `HonestMalwareResearcher` (`modules/malware/agents/malware_researcher.py:227`), and the template researcher (`modules/_template/agents/researcher.py`) are the subclasses. Forensics does not use it: its panel loop is a separate minimal handler (`modules/forensics/workflow/panel/loop.py`).

Tool dispatch is per module. The shared pieces are `ToolExecutorHelpersBase` (`platform/agents/tool_executor.py:93`: message persistence, circuit breaker, observable merge) and the dispatch primitives in `platform/agents/tool_execution.py` (`ToolExecutionResult`, `parse_command`, `classify_contract_error`). Each module defines its own `ToolExecutor(ToolExecutorHelpersBase)` with its own `_AGENT_ALLOWED_SERVERS` allowlist (`modules/vr/agents/tool_executor.py:78,125`, `modules/malware/agents/tool_executor.py:589,618`, `modules/_template/agents/tool_executor.py:41,53`).

### Frontend dep rules

The shell (`frontend/package.json`) is the only frontend package with runtime deps. Add a dep with `pnpm add <pkg> --filter @aila/shell` and reference shared versions through a catalog entry in `pnpm-workspace.yaml`.

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
- Modules never import from each other (Python)

### 6. Frontend dep ownership
- Every bare import in `frontend/src` MUST be declared in `frontend/package.json` (pnpm strict mode fails the install on undeclared bare imports)
- Shared versions go through pnpm catalogs in `pnpm-workspace.yaml`, never as literal versions

## Common Mistakes

Entry numbers are stable identifiers cited from source comments and migrations; gaps are retired entries (Recharts, Tailwind, react-router, and per-module frontend package guidance no longer apply to the single-SPA frontend).

1. **Top-level api_router import in module.py** -- MODULE_STANDARD requires deferred import inside `route_specs()`. The honesty audit catches this.

2. **Bare `except Exception`** -- Catch specific types: `(OSError, TimeoutError, RuntimeError)` for infra paths. The honesty audit flags silent swallows.

3. **Missing `__all__`** -- Every `__init__.py` and public module needs `__all__`. Underscore-prefixed private modules omit it.

4. **Module page id with no registry entry** -- A page listed in `MODULES` (`frontend/src/console/nav.ts`) opens only if `PAGE_REGISTRY` has the key `<moduleId>:<pageId>` (built from `PAGE_CONFIGS` plus the `BESPOKE` map in `frontend/src/console/pages/registry.tsx`). `openNamedPage` returns early when `resolvePage(key)` is null (`frontend/src/App.tsx:178`, `registry.tsx:407`), so the click does nothing and no error is shown.

6. **Schema changes without Alembic** -- All DDL goes through `src/aila/alembic/versions/`. No runtime CREATE TABLE, no `metadata.create_all()` outside test fixtures.

7. **Config via `os.getenv` instead of ConfigRegistry** -- Module-scoped config uses `ConfigRegistry.get()`, which resolves env var -> DB -> schema default.

8. **Workers don't auto-reload** -- After Python file changes, kill and restart workers. Clear `__pycache__` if bytecode is stale.

9. **Passing Pydantic models as task kwargs** -- Every kwarg to a `@platform_task`-decorated function or `DurableStateMachine.execute()` must be JSON-serializable. `RunState`, `RouteDecision`, `ModuleRequest`, and any `BaseModel` subclass must be `.model_dump(mode="json")`-serialized before passing. The workflow engine validates this at runtime and crashes with a clear `TypeError` if violated.

10. **`session.add()` on potentially-existing rows** -- When a `WorkflowRunRecord` or other row may already exist (e.g., created by `_ensure_run_record`), use `session.merge()` instead of `session.add()`. ORM `add()` always INSERTs; `merge()` does INSERT-or-UPDATE based on PK.

11. **Adding a frontend bare import without declaring it in `frontend/package.json`** -- `@aila/shell` is the only frontend package with runtime deps. pnpm strict mode catches missing deps at install time. Fix by adding the dep to `dependencies` (or `devDependencies` for build/test-only tools).

13. **Using literal versions in `frontend/package.json`** -- Shared deps (react, vite, typescript, etc.) must reference catalog entries (`"react": "catalog:react19"`). Add a new dep to a catalog in `pnpm-workspace.yaml` and reference it from the consumer.

14. **Hand-editing `pnpm-lock.yaml`** -- Always re-run `pnpm install` to regenerate. The lockfile format is structured but not designed for manual edits.

17. **JSX escape sequence leaks** -- `\u00b7` / `\u2026` / `\u2715` written as bare text inside JSX children (NOT inside string literals) render literally as `\u00b7`, not as `\u00b7`. JSX child text is taken verbatim. Either use the actual glyph or wrap in `{"\u00b7"}` so it parses as a string literal.

18. **Module summary contracts with `ConfigDict(extra="forbid")` reject undeclared kwargs at response-serialization time** -- The 500 fires AFTER the underlying DB row has committed (request handler ran, then Pydantic rejected the response shape on the way out). The operator sees a generic error toast but the row is in fact persisted. Fix at the source: add the missing field to the contract. Pattern: every `_<x>_summary()` helper kwarg MUST appear on the matching Pydantic `BaseModel`. Surfaced in this codebase on `MalwareTargetSummary.capability_profile`.

19. **`@platform_task` registration key is module-qualified (no cross-module `__name__` collision)** -- The decorator computes `registry_name = f"{fn.__module__}.{fn.__qualname__}"` (`aila/platform/tasks/template.py:457`), registers the task under that key (`template.py:633,641`), and `_Registry.all_functions` hands it to ARQ as `_arq_func(t.fn, name=t.name, ...)` (`template.py:147`). The wrapper's `__name__`/`__qualname__` are set to the same qualified key (`template.py:627-628`). Two modules that each define `run_target_analysis` therefore register as distinct ARQ functions. `TaskQueue.submit`, `requeue_failed`, and resume-from-pause enqueue by the stored `TaskRecord.fn_path` (the same qualified key; `aila/platform/tasks/queue.py:137-150`). Registering the same fully-qualified name twice raises `ValueError` (`template.py:122-127`). Module-prefixed handler names (e.g. `run_malware_target_analysis`) are a readability convention, not a correctness requirement. Never enqueue an ARQ job by a bare `__qualname__`: the worker only knows the qualified key.

20. **TaskQueue constructor takes `(config_registry, module_id)`, NOT `track`** -- `track` is a `.submit()` kwarg, not a constructor kwarg. The canonical pattern (mirror VR's `_task_queue.py`): `return TaskQueue(config_registry=ConfigRegistry(), module_id="<module_id>")`. A wrong constructor signature crashes at every enqueue site silently if the only call path is wrapped in a `try/except` warning logger.

21. **`extra="forbid"` + cross-module constraint name collisions in Alembic migrations** -- Postgres constraint names are unique per schema, not per table. Two modules both declaring a constraint named `uq_workspace_team_slug` (one on `vr_workspaces`, one on `malware_workspaces`) collide on `CREATE TABLE`. Prefix every named constraint with the module: `uq_malware_workspace_team_slug`, `uq_vr_workspace_team_slug`.

22. **`start.sh` WORKERS default needs every module's queue** -- Currently `default vr vulnerability forensics malware`. A queue absent from this list has no worker listening; tasks land in Redis and sit forever (display reads as `Queued`). The malware module's tasks all declare `track="malware"` so the worker line is `python -m aila worker -q malware`. After adding a new module that declares its own `track`, append the queue name and restart workers.

23. **`rea` + `reverser_belt` replace ida-headless (no RE port to configure)** -- Binary reverse engineering no longer uses the ida-headless HTTP server (archived; its old port 18821 is unused). Two stdio MCP children are spawned per AILA process (`SERVER_SPECS` in `aila/platform/mcp/server_specs.py`): `rea` (npm `rea-agents`, Ghidra provider; default argv `rea mcp`, override `REA_MCP_COMMAND`) and `reverser_belt` (package `reverser_belt_mcp`, default argv `python -m reverser_belt_mcp.server` in the current interpreter at `server_specs.py:142`, override `REVERSER_BELT_MCP_COMMAND`; `stdio_command` in `aila/platform/mcp/factory.py:114` shlex-splits the override, so use forward slashes on Windows). `reverser_belt` is a separate repo (`ida-headless-mcp-exp`) that must be importable in the AILA interpreter (`pip install -e <checkout>`; `start.sh:75-79`); it owns the scanner surface REA lacks (capa, crypto, API-hash, emulation, taint, SMT proofs, patching, YARA). The in-platform `re_analytics` package was deleted; do not reference it or the `re_analytics` server id. `start.sh` exports `REA_MCP_COMMAND`, `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, and `REA_ANALYSIS_PROVIDER=ghidra`. Setting `REA_MCP_URL` / `REVERSER_BELT_MCP_URL` (or the `rea_mcp_url` / `reverser_belt_mcp_url` config keys) to an http(s) URL targets a remote instance instead. Modules address a binary by the server-injected absolute `target_path`; `ReaMiddleware` opens it for `rea`, and `ReverserBeltMiddleware` (`aila/platform/mcp/middleware/reverser_belt.py`) opens it once per path and rewrites each call to carry the resulting `binary_id`. The agent never passes a path or id. Tool executors allow `rea` and `reverser_belt` for binary targets (`modules/vr/agents/tool_executor.py:125-129`, `modules/malware/agents/tool_executor.py:618-620`). The only fixed MCP ports are `audit_mcp` 18822 and `android_mcp` 18823 (`server_specs.py:64-79`).

24. **Operator Resume/Retrigger writing `analysis_state="pending"` directly** -- The handlers in `api_router.py` rewrite the row's overall state column but DO NOT touch the per-stage state in `analysis_stages_json`. Next worker run hits `StageAlreadyDoneError`, logs "already ingested -- skip", and returns. Without an explicit `load_target_stages` -> `save_target_stages` re-roll on that skip path, the row sits at `pending` forever even though every applicable stage is DONE. The malware module's skip path does the re-roll; copy that pattern when adding new resume-style handlers.

## Verification Checklist

Before yielding any change:
- [ ] `python -m compileall -q src/aila` -- no syntax errors
- [ ] `python -m ruff check src/aila/` -- clean
- [ ] `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py` -- zero findings
- [ ] `python -m aila.tools.liveness_audit src/aila --whitelist liveness_whitelist.py` -- zero findings
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

> HARD RULE (operator directive, 2026-10-30): stay on `0.6.x`. Every
> release is a PATCH bump (`0.6.X`) by default. NEVER bump the MINOR or
> MAJOR digit (NEVER go to `0.7.x` or `1.x`) without the operator saying
> so explicitly in the current conversation. "New feature" does NOT
> authorize a minor bump; it is still a patch until told otherwise.

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
   NEVER `source`. See `adapt_read_function`
   (`aila/platform/mcp/adapters/audit_mcp.py:823`, body selection at `:885`).

2. **`search_functions` returns `file_path: null` for ~half the
   indexed functions** (trailmark loses locations). The generic
   `_render_matches_dense` produces literal `?:?:` rows from these.
   `adapt_search_functions` (`adapters/audit_mcp.py:1234`, registered at
   `adapters/registry.py:157`) renders the actual fields (name, kind,
   cyclomatic_complexity) instead.

3. **`search_constants`, `search_bitfields` return 0 results for
   patterns that exist in source.** Trailmark's index doesn't track
   them on this codebase. Tell the agent in the prompt -- don't
   recommend these as the primary path.

4. **`semantic_search` and `find_related` return code CHUNKS** with
   `{file_path, start_line, end_line, content}` per result. They have
   their own adapters; do NOT fall through to generic JSON dump.

5. **`read_lines` is a middleware-side virtual tool** -- no upstream MCP
   endpoint. `AuditMcpMiddleware` injects it into the tool catalog
   (`aila/platform/mcp/middleware/audit.py:1245`), resolves
   `index_id → root_path` from a cached `list_indexes` call
   (`audit.py:1621`), and reads the file slice from disk. Use this
   when the agent has a precise `(file_path, start, end)` and needs
   verbatim source bypassing all indexers.

6. **Observable previews are capped at 32 KiB; raw responses are not.**
   `MAX_OBS_DUMP_CHARS = 32 * 1024` (`adapters/_shared.py:207`) bounds
   what an adapter writes into observables (`_MAX_OBS_READ_FUNCTION` /
   `_MAX_OBS_SEARCH` in `adapters/audit_mcp.py:263,1081` alias it). The
   earlier 100MB ceiling made "bounded" meaningless and bloated
   `case_state_json`. The full raw response still lives in the message
   store for the operator UI (`_shared.py:203-206`).

### Workflow / cursor mechanism

1. **Reserved terminal cursors (`__crashed__`, `__failed__`,
   `__cancelled__`, `__succeeded__`) are reaped by the worker.** The
   worker reaper cron (every minute, `aila/platform/tasks/worker.py:354`) calls
   `sweep_orphan_crashed_cursors` (`aila/platform/tasks/cursor_reaper.py:67`),
   which clears these cursors once their `run_id` has no active
   `TaskRecord`. A cursor can still sit until the next sweep tick, so
   operators who need an immediate clear run the same predicate by hand:
   `DELETE FROM workflow_state_cursor WHERE current_state = '__crashed__'
   AND NOT EXISTS (SELECT 1 FROM taskrecord t WHERE t.id = run_id AND
   t.status IN ('queued','running','waiting'))`.

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
   after Maddie + Renzo reject it. `inject_sibling_consensus`
   (`aila/platform/agents/sibling_consensus.py:17`) writes an explicit
   `_directive.sibling_consensus_rejection` observable (`:80`) when 2+
   siblings reject an id this branch still has live.

2. **Operator messages need ACK.** The agent emits
   `observables: { "_acked_operator_messages": "<id1>,<id2>" }` to
   stop a steering message from re-appearing. Without ACK,
   operator messages re-fire on every turn within the wall-clock
   TTL (24h).

3. **Idempotency: every agent-turn LLM call is request-keyed**. Cache
   table `llm_idempotency_cache` (migration 061) stores responses by
   `make_request_key(investigation_id, branch_id, turn_number,
   prompt_hash)` (`aila/platform/llm/idempotency_cache.py:74`).
   Retries replay the cached decision instead of re-paying for
   Claude. The key is built and looked up once per turn in
   `AgentTurnRunnerBase.run_turn` (`aila/platform/agents/turn_runner.py:1051`),
   shared by vr and malware.

4. **Agent self-bloats observables.** They invent scratchpad keys
   like `sibling_renzo_h7`, `mandatory_next`, `critic_open_question`.
   `absorb()` (`aila/platform/services/reasoning.py:455`) accepts at
   most 10 new agent-set keys per turn and evicts the oldest agent-set
   keys past `reasoning_max_agent_keys_total` (default 150,
   `reasoning.py:77`; config-resolved at `:661`). Keys with a
   `_TOOL_PREFIXES` prefix (`audit_mcp:`/`.`, `rea:`/`.`,
   `reverser_belt:`/`.`, `android_mcp:`/`.`, `_directive.`, `_recall.`,
   `_ledger.`; `reasoning.py:55-65`) cannot be written by the agent and
   are never evicted. `render_case_model` (`reasoning.py:716`) no longer
   applies display caps: it indexes every tool reading, renders every
   agent scratchpad key in full, and the context assembler sizes the
   live section against `platform.reasoning_context_budget_tokens`.

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

### Cost tracking

`LLMCostRecord.run_id` for an agent turn is the investigation id, not
a `TaskRecord` or workflow `RunRecord` id: `AgentTurnRunnerBase.run_turn`
passes `run_id=self.investigation_id` to the engine
(`aila/platform/agents/turn_runner.py:1106`). The live total is therefore
a direct filter, with no extra join hop:
`compute_live_investigation_cost`
(`aila/platform/services/investigation_cost.py:34`) sums
`LLMCostRecord.cost_usd` where `run_id == investigation_id`
(`investigation_cost.py:50`); the vr, malware, and template detail
endpoints call it.

The stored `cost_actual_usd` column is also materialized on write:
`persist_cost_record` calls `accrue_investigation_cost` in the same
session as the cost-record insert (`aila/platform/llm/cost.py:406-410`;
`investigation_cost.py:67`), and migration `121_backfill_investigation_cost`
backfilled older rows. Do not read the stored column as the only source of
truth for a live gauge; use `compute_live_investigation_cost`.

The real gap is attribution, not the join: an LLM call made without a
`run_id` is recorded under the `_no_run` sentinel
(`aila/platform/llm/cost.py:36,381`), is skipped by
`accrue_investigation_cost` (`investigation_cost.py:86`), and is never
budget-checked (`cost.py:127`). Such spend does not appear in any
investigation total unless the caller threads the investigation id
through as `run_id`.

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
