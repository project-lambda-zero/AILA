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
|        FastAPI app with 28 routers, JWT auth, RBAC,         |
|              SSE event streams, OpenAPI at /docs            |
+----------------------------+--------------------------------+
                             |
        +--------------------+--------------------+
        |                                         |
+-------v-------------+                  +--------v-----------+
|  Platform           |                  |  Modules           |
|  src/aila/platform/ |                  |  src/aila/modules/ |
|                     |                  |                    |
|  routing/           |                  |  vulnerability/    |
|  runtime/           | <-- ModuleProto. |  forensics/        |
|  services/          |     contracts -> |  sbd_nfr/          |
|  contracts/         |                  |  hello_world/      |
|  tools/             |                  |                    |
|  llm/               |                  |  Each module owns  |
|  tasks/   (ARQ)     |                  |  its own runtime,  |
|  workflows/         |                  |  tools, workflow,  |
|  sse/               |                  |  contracts, API    |
|  events/            |                  |  router, frontend, |
|  automation/        |                  |  and DB models.    |
|  config.py, uow.py  |                  |                    |
+----+-------------+--+                  +---------+----------+
     |             |                               |
+----v---+   +-----v------+                +-------v---------+
| Redis  |   | PostgreSQL |                | Per-module ARQ  |
| ARQ    |   | SQLModel + |                | queue tracks:   |
| queues |   | Alembic +  |                | default,        |
|        |   | pgvector   |                | vulnerability,  |
+--------+   +------------+                | forensics       |
             src/aila/storage/             +-----------------+
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
   cd Playground
   ```

2. Install backend dependencies (editable, with dev extras).

   ```bash
   pip install -e ".[dev]"
   ```

3. Install frontend dependencies.

   ```bash
   corepack enable && pnpm install
   ```

4. Create the database.

   ```bash
   createdb aila
   ```

   Or via `psql`:

   ```bash
   psql -U postgres -c "CREATE DATABASE aila;"
   psql -U postgres -d aila -c "CREATE EXTENSION IF NOT EXISTS vector;"
   ```

5. Copy the environment template and fill in real values.

   ```bash
   cp .env.example .env
   ```

   At minimum, set `AILA_DATABASE_URL`, `AILA_PLATFORM_REDIS_URL`,
   `AILA_JWT_SECRET_KEY`, and the `AILA_PLATFORM_LLM_*` group. Generate the
   JWT secret with `openssl rand -hex 32`. See
   [docs/ENV_VARS.md](docs/ENV_VARS.md) for the full reference.

6. Apply database migrations.

   ```bash
   cd src/aila && alembic upgrade head && cd ../..
   ```

7. Start the services in three terminals.

   ```bash
   # Terminal 1 -- REST API
   uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload

   # Terminal 2 -- frontend (port 3000)
   cd frontend && npm run dev

   # Terminal 3 -- ARQ worker (default queue)
   python -m aila worker
   ```

   For per-module queue tracks, run additional workers:

   ```bash
   python -m aila worker -q vulnerability
   python -m aila worker -q forensics
   ```

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
| `make dev`              | Prints the commands to launch backend, frontend, audit-mcp, and all workers |
| `make backend`          | `uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload`            |
| `make frontend`         | `pnpm dev` (Vite on `:3000`)                                              |
| `make worker`           | `python -m aila worker` (default queue)                                   |
| `make worker-vr`        | `python -m aila worker -q vr`                                             |
| `make worker-vuln`      | `python -m aila worker -q vulnerability`                                  |
| `make worker-forensics` | `python -m aila worker -q forensics`                                      |
| `make worker-sbd-nfr`   | `python -m aila worker -q sbd_nfr`                                        |
| `bash start.sh`         | Spawn every service (audit-mcp + backend + 5 workers + frontend) in one shot, Git-Bash + PowerShell on Windows |
| `docker compose -f infra/utilities/docker-compose.full.yml up --build` | Full-stack containers: postgres + redis + api + 5 workers + frontend. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md). |
| `make migrate`          | `cd src/aila && alembic upgrade head`                                     |
| `make test`             | `pytest`, excluding `tests/test_e2e*.py`                                  |
| `make test-e2e`         | `pytest tests/test_e2e.py -v` (requires live infrastructure)              |
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
- **Authentication:** API-key bootstrap (`POST /auth/token`) returning a JWT
  used as `Authorization: Bearer <token>` for all subsequent calls. RBAC roles
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
| [docs/MODULE_AI_CONTEXT.md](docs/MODULE_AI_CONTEXT.md)                      | Module context conventions for LLM-driven flows                         |
| [docs/FRONTEND_MODULE_STANDARD.md](docs/FRONTEND_MODULE_STANDARD.md)        | Frontend shell and per-module UI contribution contract                  |
| [docs/forensics/](docs/forensics/)                                          | Forensics module domain reference and design history                     |
| [docs/DB_SCHEMA.md](docs/DB_SCHEMA.md)                                      | Database tables, relationships, and ownership                           |
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
| [CHANGELOG.md](CHANGELOG.md)                                                | Version history                                                         |

## License

AILA is licensed under the GNU Affero General Public License v3.0. See
[LICENSE](LICENSE) for the full text.
