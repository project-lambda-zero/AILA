# AILA -- AI Lab Assistant

Modular AI security platform with pluggable analysis modules: a Python core
exposing a Typer CLI and a FastAPI REST API, backed by PostgreSQL with pgvector
and an ARQ/Redis task queue, paired with a React + Vite + TypeScript frontend.

## Architecture Overview

```
+-------------------------------------------------------------+
|                     Frontend (frontend/)                    |
|              React 19 + Vite + TypeScript shell             |
|        Module UIs mounted from modules/<id>/frontend/       |
+----------------------------+--------------------------------+
                             |  HTTP / SSE / JWT
+----------------------------v--------------------------------+
|                    API (src/aila/api/)                      |
|        FastAPI app with 30 routers, JWT auth, RBAC,         |
|              SSE event streams, OpenAPI at /docs            |
+----------------------------+--------------------------------+
                             |
        +--------------------+--------------------+
        |                                         |
+-------v-------------+                  +--------v-----------+
|  Platform           |                  |  Modules           |
|  src/aila/platform/ |                  |  src/aila/modules/ |
|                     |                  |                    |
|  routing/           |                  |  forensics/        |
|  runtime/           | <-- ModuleProto. |  hello_world/      |
|  services/          |     contracts -> |  sbd_nfr/          |
|  contracts/         |                  |  vr/               |
|  tools/             |                  |  vulnerability/    |
|  llm/               |                  |                    |
|  tasks/   (ARQ)     |                  |  Each module owns  |
|  workflows/         |                  |  its own runtime,  |
|  sse/               |                  |  tools, workflow,  |
|  events/            |                  |  contracts, API    |
|  automation/        |                  |  router, frontend, |
|  config.py, uow.py  |                  |  and DB models.    |
|                     |                  |                    |
|                     |                  |  See docs/vr/ for  |
|                     |                  |  the VR engine +   |
|                     |                  |  MCP architecture. |
|                     |                  |                    |
+----+-------------+--+                  +---------+----------+
     |             |                               |
+----v---+   +-----v------+                +-------v---------+
| Redis  |   | PostgreSQL |                | Per-module ARQ  |
| ARQ    |   | SQLModel + |                | queue tracks:   |
| queues |   | Alembic +  |                | default, vr,    |
|        |   | pgvector   |                | vulnerability,  |
+--------+   +------------+                | forensics,      |
             src/aila/storage/             | sbd_nfr         |
                                           +-----------------+
```

**Layer responsibilities**

- **Platform** (`src/aila/platform/`) -- routing, runtime construction,
  shared services, module/tool contracts, LLM client and pipelines, ARQ task
  registration, workflow engine, SSE bus. Never imports from a feature module.
- **Modules** (`src/aila/modules/`) -- domain logic. Each module is a
  self-contained package implementing `ModuleProtocol`. One module never
  imports from another. Layout is fixed by `docs/MODULE_STANDARD.md`.
  Current modules: `vulnerability` (CVE/CWE scanning + intel),
  `forensics` (DFIR investigations), `sbd_nfr` (Security-by-Design NFR
  assessments), `vr` (vulnerability research — graph-aware audit, fuzz
  campaign proposals, enterprise PDF reports, exploit/PoC writer
  agent), and the `hello_world` reference module.
- **API** (`src/aila/api/`) -- FastAPI application (`aila.api.app:app`).
  Modules contribute additional routers via `api_router.py`.
- **Frontend** (`frontend/`) -- top-level Vite + React + TypeScript shell.
  Module UIs live under `src/aila/modules/<id>/frontend/` and are mounted by
  the shell through the frontend module spec. Managed as a **pnpm
  workspace** at the repo root.
- **Storage** (`src/aila/storage/`) -- SQLModel models, Alembic migrations,
  config registry, secret store. Vector search uses pgvector with
  384-dimensional embeddings.
- **Task queue** -- ARQ on Redis, with per-module queue tracks (default,
  vulnerability, forensics, vr, sbd_nfr) so long-running jobs don't
  starve each other.

For deeper detail see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## VR Engine and MCP Architecture

The vulnerability research module (`vr`) drives a multi-MCP backend with
graph-aware code intelligence, semantic search, and binary analysis. Three
MCP servers run alongside AILA, exposed over HTTP and orchestrated by the
platform's task queue.

```
  +-------------------------------------------------------------+
  |                  AILA backend (Python + ARQ)                |
  |  agent loop -> tool_executor -> bridge tools -> MCP servers |
  +----+--------------------+--------------------+--------------+
       |                    |                    |
  +----v-----+      +-------v--------+    +------v---------+
  | audit-   |      | ida-headless-  |    | semble         |
  | mcp      |      | mcp            |    | (embedded in   |
  | 18822    |      | 18821          |    |  audit-mcp)    |
  +----------+      +----------------+    +----------------+
  trailmark        Hex-Rays + miasm     Model2Vec + BM25
  graph engine     binary engine        chunk retrieval
  + GPU CSR        + 81 tools
  + 58 tools
```

### audit-mcp -- source-code intelligence

- **Tool surface:** 58 tools over HTTP (`/tools` for catalog, `/tools/<name>` for invocation)
- **Graph engine:** trailmark builds a call graph + symbol table on `index_codebase`. Per-index cached on disk via `DurableIndexStore`, recovered automatically on restart.
- **GPU acceleration:** `from_trailmark()` constructs a GPU CSR adjacency matrix when CUDA is present; powers `attack_surface`, `fuzzing_targets`, `unreachable_from_entrypoints` on monorepo-scale graphs.
- **Semantic search via semble:**
  - Hybrid Model2Vec (potion-code-16M) embeddings + BM25 + RRF + code-aware reranker
  - Per-index lazy build in a **separate Python process** so the parent's GIL stays free during cold builds
  - Pickled to `~/.audit-mcp/semble-cache/<index_id>.pkl` after first build -- subsequent restarts load in ~9s instead of rebuilding
  - Tools: `semantic_search(query, top_k, alpha, rerank, filter_*)`, `find_related(file, line, top_k)`, `semble_stats(index_id)`
- **Read-function fast path:** `read_function` queries the semble chunk index first (matches by name + definition pattern); falls back to a process-cached `TypeResolver` instead of rebuilding it per call (was the source of 15-minute hangs on firefox-scale).
- **Multi-worker support:** `AUDIT_MCP_WORKERS` env / `--workers` CLI flag. Each worker holds its own engine + semble + TypeResolver caches; AILA's bridge pre-warms all workers on the first call to a new `index_id` (Linux/macOS only -- Windows uvicorn multi-worker is broken).

### ida-headless-mcp -- binary intelligence

- **Tool surface:** 81 tools over HTTP (`/tools` catalog)
- **Engines:** Hex-Rays decompiler + miasm IR for control-flow obfuscation, CFF deflattening, symbolic execution, CAPA behavioral rule scanning
- **Mutations:** Renames, comments, prototypes, and assembly patches are queued through `ida_headless/poll_mutation` so concurrent operator + agent edits don't race
- **Specialised tools:** GPU-backed call graph traversal, opaque-predicate proving via SMT, structural binary diffing, exploitability assessment (`assess_exploitability`, `prove_overflow`, `prove_bounds_sufficient`)

### Agent loop and reliability

The VR module runs adversarial 3-persona deliberation (researcher / critic / synthesizer) over the MCP tool surface. Each tool call goes through `AuditMcpBridgeTool` (or its IDA equivalent) which provides:

- **Schema-driven kwarg validation** -- catches LLM-hallucinated parameters (e.g. `fuzzing_targets(threshold=...)`) before the HTTP round-trip and returns a structured "did you mean" error so the next turn self-corrects
- **Per-action kwarg synonyms** -- transparently rewrites common aliases (`top_n` -> `limit`, `cutoff` -> `min_complexity`, etc.) per tool's actual signature
- **Circuit breaker** -- counts repeated failures by both `(server, tool, args)` AND `(server, tool, error_class)` so the agent can't burn turns varying the value of a bad kwarg name; injects a hard pivot directive after 3 consecutive failures
- **Survey-streak pivot** -- after 3 consecutive survey-tool calls (`attack_surface`, `complexity_hotspots`, `fuzzing_targets`, ...) without a source read, forces the agent into `read_function` / `taint_paths_to` / `callers_of` or a finding submission
- **Language-aware tool suppression** -- hides `dead_code` and `unreachable_from_entrypoints` from agents running against C++/Java/Kotlin/C#/Swift/Objective-C/Scala targets (static call graphs are blind to vtable + template dispatch on those languages)
- **Pending/poll pattern** -- heavy operations like `fuzzing_targets` on firefox return `status=pending + task_id`; the bridge polls `poll_task` for up to ~15 min so AILA's 900s HTTP timeout doesn't kill long graph queries
- **Lazy pre-warm fan-out** -- first call to a new `index_id` fires 16 parallel `summary` + `semble_stats` requests so every uvicorn worker warms its caches before the agent's real query lands

### Per-stage target analysis (durable)

Target ingestion is split into three independently-tracked stages with per-stage status, attempts counter, and reaper:

- `INGESTION` -- audit_mcp `index_codebase` clone + parse (timeout 14400s)
- `CAPABILITY_PROFILE` -- D-51 capability rule evaluation (timeout 1800s)
- `FUNCTION_RANKING` -- `fuzzing_targets` ranking with GPU CSR (timeout 1800s)

Operator can resume a stuck target via `POST /vr/targets/{id}/resume-analysis`; the endpoint fans out per non-DONE stage. Reaper runs every minute via ARQ cron, flips RUNNING stages past their timeout to FAILED with `"reaper: RUNNING for Xs > Ys timeout"`.

### Statistics (current deployment)

| Measurement | Value |
|---|---|
| audit-mcp tools available | **58** (incl. 3 semble tools, 8 graph tools, 7 specialised search, 5 deep-audit, etc.) |
| ida-headless-mcp tools | **81** |
| Trailmark graph -- nginx | ~10k functions, ~100k call edges |
| Trailmark graph -- firefox | **742,335 functions, 5M+ call edges** |
| Semble index -- nginx | 16 MB pickle, ~250ms cold build |
| Semble index -- openjpeg | 26 MB pickle, ~3s cold build |
| Semble index -- firefox | **3.4 GB pickle, ~85 min cold build, ~9s warm restore** |
| Semble chunks -- firefox | 700k+ across 17 languages (cpp 234k, c 221k, js 425k, rust 165k, ...) |
| Read-function on firefox | 15+ min hang **->** ~30s first call + cached, <100ms subsequent |
| Semantic search latency | ~250ms (nginx) / ~5ms in-process, ~200ms via MCP HTTP |
| Cold start (3 indexes recovered) | ~30s including all semble pickle loads |

### Bug-fix scorecard (recent)

| Issue | Fix |
|---|---|
| firefox `read_function` 15-min hang | TypeResolver cached on `IndexEntry`; reused across calls (`audit-mcp d091d94`) |
| audit-mcp full-server hang during semble build | Cold builds moved to a separate Python process (`audit-mcp 13dc2d6`) |
| `attack_surface` returning 0 entries on every call | Adapter was looking up wrong response key (`surfaces` vs actual `entrypoints`); fixed (`AILA ec1b4f3`) |
| `fuzzing_targets(threshold=...)` infinite loop | Per-action kwarg synonyms (was: global map rewrote correct `min_complexity` -> broken `threshold`) (`AILA ef1ca59`) |
| Agent surveying 10+ turns without reading source | Survey-streak pivot circuit breaker (`AILA b8aa54f`) |
| firefox classified as `python` (trailmark iteration order) | Byte-weighted language detection by walking `mcp_path` ourselves (`AILA c29d82b`) |
| Module-side Tailwind classes had no CSS | Explicit `@source` directives in `globals.css` for every module path (`AILA 02ef955`) |

For day-to-day MCP operations and the full VR agent design see [docs/vr/](docs/vr/).

## Quick Start

**Prerequisites**

- Python 3.11+
- Node.js 20+
- PostgreSQL 15+ with the `pgvector` extension available
- Redis 6+

**Steps**

1. Clone the repository.

   ```bash
   git clone <repo-url>
   cd AILA
   ```

2. Install backend and frontend dependencies.

   ```bash
   make install
   ```

   Equivalent to `pip install -e ".[dev]"` plus `corepack enable && pnpm install`. The frontend is a pnpm workspace at the repo root; one install wires the shell, `@aila/typescript-config`, and all module packages.

3. Copy the environment template and fill in real values.

   ```bash
   cp .env.example .env
   ```

   At minimum, set `AILA_DATABASE_URL`, `AILA_PLATFORM_REDIS_URL`, `AILA_JWT_SECRET_KEY`, `AILA_ADMIN_PASSWORD` (first-boot bootstrap, removed afterward), and the `AILA_PLATFORM_LLM_*` group. Generate the JWT secret with `openssl rand -hex 32`. See [docs/ENV_VARS.md](docs/ENV_VARS.md) for the full reference.

4. Bring up Postgres (pgvector) and Redis via Docker Compose.

   ```bash
   make dev-up
   ```

   This launches `pgvector/pgvector:pg16` on `:5432` and `redis:7-alpine` on `127.0.0.1:6379`, defined in `infra/utilities/docker-compose.yml`. Idempotent. Use `make dev-down` to stop (keeps volumes), `make dev-reset` to wipe.

5. Initialize or migrate the schema.

   ```bash
   make db-init        # FIRST RUN ONLY: create tables + stamp Alembic head
   make migrate        # subsequent runs: alembic upgrade head
   ```

6. Start the services in three terminals.

   ```bash
   # Terminal 1 -- REST API on :8000
   make backend

   # Terminal 2 -- Vite dev server on :3000 (single SPA, all module UIs)
   make frontend

   # Terminal 3 -- ARQ worker, default queue
   make worker
   ```

   For per-module queue tracks, run additional workers:

   ```bash
   make worker-vr           # vulnerability research
   make worker-vuln         # vulnerability scans
   make worker-forensics    # DFIR investigations
   make worker-sbd          # Security-by-Design NFR
   ```

   On Windows, `bash start.sh` brings up audit-mcp + backend + 5 workers + frontend in a single command.

For the expanded walkthrough including admin user creation, smoke tests, and
common pitfalls, see [docs/QUICKSTART.md](docs/QUICKSTART.md).

## Module Inventory

| module_id       | Description                                                                                       | Status     |
|-----------------|---------------------------------------------------------------------------------------------------|------------|
| `vulnerability` | SSH package inventory, distro-aware advisory resolution, CVE enrichment, scoring, and reporting.  | production |
| `forensics`     | Remote forensic evidence triage over SSH: disk images, memory dumps, PCAPs, write-up generation.  | production |
| `sbd_nfr`       | Security-by-Design NFR assessment: questionnaire-driven workbook generation and Jira handoff.     | production |
| `vr`            | Vulnerability research: graph-aware source/binary audit (audit-mcp + IDA Headless MCP), hypothesis-driven reasoning, fuzz campaign proposals (audit→fuzz pipeline), enterprise PDF reports with LLM writer agent, automatic exploit/PoC drafting, variant hunting with child-investigation spawning. | production |
| `hello_world`   | Minimal reference module proving the `ModuleProtocol` contract end-to-end.                        | example    |

Modules are auto-discovered at platform boot by scanning `src/aila/modules/*`.
Packages whose name starts with `_` are skipped (used for templates and
fixtures). To add a new module, follow [docs/MODULE_STANDARD.md](docs/MODULE_STANDARD.md)
and the worked tutorial in [docs/MODULE_TUTORIAL.md](docs/MODULE_TUTORIAL.md).

## Development

Common targets in the root `Makefile`:

| Target                  | What it runs                                                              |
|-------------------------|---------------------------------------------------------------------------|
| `make install`          | `pip install -e ".[dev]"` plus `corepack enable && pnpm install`          |
| `make dev-up`           | `docker compose -f infra/utilities/docker-compose.yml up -d postgres redis` (idempotent) |
| `make dev-down`         | Stop dev infra containers (keeps data volumes)                            |
| `make dev-reset`        | Stop containers and wipe data volumes                                     |
| `make dev-logs`         | Follow compose service logs                                               |
| `make dev-status`       | `docker compose ps`                                                       |
| `make db-init`          | `python scripts/db_init.py` — create tables + stamp Alembic head (first run only) |
| `make migrate`          | `cd src/aila && alembic upgrade head`                                     |
| `make dev`              | Print the canonical dev workflow (no services started)                    |
| `make backend`          | Ensure `dev-up` + `db-init`, free port 8000, run `uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload` |
| `make frontend`         | Free port 3000, run `pnpm --filter @aila/shell run dev` (Vite on :3000)   |
| `make frontend-build`   | `pnpm --filter @aila/shell run build` (production SPA bundle)             |
| `make storybook`        | `pnpm --filter @aila/shell run storybook`                                 |
| `make worker`           | `python -m aila worker` (default queue)                                   |
| `make worker-vr`        | `python -m aila worker -q vr`                                             |
| `make worker-vuln`      | `python -m aila worker -q vulnerability`                                  |
| `make worker-forensics` | `python -m aila worker -q forensics`                                      |
| `make worker-sbd`       | `python -m aila worker -q sbd_nfr`                                        |
| `make dev-all`          | Bring up all services in one terminal (Ctrl+C stops everything)           |
| `bash start.sh`         | Spawn audit-mcp + backend + 5 workers + frontend in one shot (Windows: Git Bash + PowerShell) |
| `docker compose -f infra/utilities/docker-compose.full.yml up --build` | Full-stack containers: postgres + redis + api + 5 workers + frontend. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). |
| `make test`             | `pytest`, excluding `tests/test_e2e*.py`                                  |
| `make test-e2e`         | `pytest tests/test_e2e.py -v` (requires live infrastructure)              |
| `make test-frontend`    | `pnpm -r run test` across shell + module packages                         |
| `make lint`             | `ruff check src/aila/`                                                    |
| `make typecheck`        | `pnpm -r run type-check` (every workspace package, shell + modules)       |
| `make honesty`          | `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py` |
| `make compile`          | `python -m compileall -q src/aila`                                        |
| `make build`            | `pnpm --filter @aila/shell run build` (production SPA bundle)             |
| `make check`            | `lint` + `honesty` + `compile` + `typecheck` (the full pre-PR gate)       |
| `make security-scan`    | `pip-audit --strict --desc` and `bandit -r src/aila -q -ll`               |
| `make clean`            | Remove `__pycache__/` directories and coverage artifacts                  |

Run `make check` before opening a PR. Contributor workflow, branch policy,
review expectations, and the honesty audit rules are documented in
[docs/CONTRIBUTING.md](docs/CONTRIBUTING.md).

## CLI

The `aila` entry point (`aila = "aila.cli:app"`) is a Typer application.
Invoke `aila --help` to list every subcommand and command group; the most
common entry points are summarised below.

| Command                          | Purpose                                                                |
|----------------------------------|------------------------------------------------------------------------|
| `aila serve`                     | Start the FastAPI REST API via uvicorn                                 |
| `aila worker [-q <queue>]`       | Start an ARQ worker for the given queue track (default: `default`)     |
| `aila task "<question>"`         | Ask a natural-language question routed through the platform agent      |
| `aila analyze [--target <name>]` | Run a vulnerability scan across registered targets (or one)            |
| `aila add-ssh ...`               | Register an SSH-reachable system for the vulnerability module          |
| `aila create-api-key`            | Mint an admin-role API key for first-boot bootstrap                    |
| `aila health`                    | Probe platform and provider readiness                                  |

Command groups expose related subcommands:
`aila config` (runtime config registry),
`aila tool` (invoke registered platform tools directly),
`aila cache` (manage decision and intel caches),
`aila policy` (scoring policy management),
`aila feedback` (operator knowledge entries),
`aila report` (PDF and CSV reporting),
`aila schedule` (scheduled scans),
`aila intel`, `aila ops`, `aila auto`, `aila digest`
(fleet intelligence, operational metrics, automation, executive digests).

## REST API

- **Base URL (dev):** `http://localhost:8000`
- **OpenAPI / Swagger UI:** `http://localhost:8000/docs`
- **OpenAPI JSON:** `http://localhost:8000/openapi.json`
- **Authentication:** `POST /auth/login` with `{"username", "password"}` returns a JWT (`data.access_token`) used as `Authorization: Bearer <token>` for all subsequent calls; `POST /auth/token` exchanges an API key for the same envelope. RBAC roles
  are `admin`, `operator`, `reader` -- see
  [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md).
- **Streaming:** long-running scans, sessions, and tasks expose SSE endpoints
  (e.g. `/scans/{id}/events`, `/tasks/{id}/events`). Integration patterns are
  documented in [docs/SSE_GUIDE.md](docs/SSE_GUIDE.md).
- **Errors:** structured error envelope catalogued in
  [docs/API_ERRORS.md](docs/API_ERRORS.md).

The OpenAPI document is the source of truth for the route surface; the
`/docs` UI lists every endpoint, request schema, and response schema.

## Documentation Index

| Document                                                                    | Covers                                                                  |
|-----------------------------------------------------------------------------|-------------------------------------------------------------------------|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)                                | System diagram, layer responsibilities, data flow, runtime constraints  |
| [docs/PLATFORM_INTERNALS.md](docs/PLATFORM_INTERNALS.md)                    | X-ray: full request lifecycle traced through every platform layer       |
| [docs/QUICKSTART.md](docs/QUICKSTART.md)                                    | Expanded onboarding walkthrough with troubleshooting                    |
| [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md)                                | Contributor workflow, branch policy, review expectations                |
| [docs/MODULE_STANDARD.md](docs/MODULE_STANDARD.md)                          | Required module layout, contracts, and lifecycle (v2.1)                 |
| [docs/MODULE_TUTORIAL.md](docs/MODULE_TUTORIAL.md)                          | Step-by-step authoring of a new module                                  |
| [docs/MODULE_AGENT_GUIDE.md](docs/MODULE_AGENT_GUIDE.md)                      | Module context conventions for LLM-driven flows                         |
| [docs/FRONTEND_MODULE_STANDARD.md](docs/FRONTEND_MODULE_STANDARD.md)        | Frontend shell and per-module UI contribution contract                  |
| [docs/forensics/](docs/forensics/)                                          | Forensics module domain reference and design history                     |
| [docs/DB_SCHEMA.md](docs/DB_SCHEMA.md)                                      | Database tables, relationships, and ownership                           |
| [docs/DATABASE_MIGRATIONS.md](docs/DATABASE_MIGRATIONS.md)                  | Alembic policy, conventions, and migration authoring                    |
| [docs/CONFIG_REGISTRY.md](docs/CONFIG_REGISTRY.md)                          | Config resolution chain (env -> registry -> defaults)                   |
| [docs/ENV_VARS.md](docs/ENV_VARS.md)                                        | Environment variable reference                                          |
| [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md)                            | Auth, RBAC, API keys, JWT lifecycle                                     |
| [docs/DATA_PROTECTION.md](docs/DATA_PROTECTION.md)                          | Data posture modes, LLM redaction, input/output sanitization            |
| [docs/API_ERRORS.md](docs/API_ERRORS.md)                                    | API error catalog                                                       |
| [docs/OPENAPI_NOTES.md](docs/OPENAPI_NOTES.md)                              | OpenAPI generation notes and conventions                                |
| [docs/SSE_GUIDE.md](docs/SSE_GUIDE.md)                                      | Server-sent events: usage, reconnection, curl examples                  |
| [docs/TASK_QUEUE_OPS.md](docs/TASK_QUEUE_OPS.md)                            | ARQ worker operations, queue tracks, retry semantics                    |
| [docs/LLM_INTEGRATION.md](docs/LLM_INTEGRATION.md)                          | LLM client, pipelines, model selection, transparency posture            |
| [docs/WORKFLOW_GUIDE.md](docs/WORKFLOW_GUIDE.md)                              | Durable state machine: handler contract, do/don't, production examples  |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)                                    | Production deployment guide                                             |
| [docs/TEST_GUIDE.md](docs/TEST_GUIDE.md)                                    | Testing conventions, fixtures, e2e gating                               |
| [docs/GOLDEN_RULES.md](docs/GOLDEN_RULES.md)                                | Code quality rules enforced by review and tooling                       |
| [docs/HONESTY_AUDIT.md](docs/HONESTY_AUDIT.md)                              | Structural honesty rules enforced by `aila.tools.honesty_audit`         |
| [docs/PITFALL_GUIDE.md](docs/PITFALL_GUIDE.md)                              | Common mistakes when working on AILA                                    |
| [docs/PRODUCTION_RUBRIC.md](docs/PRODUCTION_RUBRIC.md)                      | Readiness rubric for shipping a module to production                    |
| [docs/vr/](docs/vr/)                                                        | VR engine internals: reasoning loop, IDA Headless MCP, exploit automation |
| [docs/VR_INSTALLATION_GUIDE.md](docs/VR_INSTALLATION_GUIDE.md)              | Standing up audit-mcp + IDA Headless MCP next to AILA                    |
| [CHANGELOG.md](CHANGELOG.md)                                                | Version history                                                         |

## License

AILA is licensed under the GNU Affero General Public License v3.0. See
[LICENSE](LICENSE) for the full text.
