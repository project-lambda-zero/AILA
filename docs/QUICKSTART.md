# AILA Quickstart

Zero-to-running guide for AILA (AI Lab Assistant). Takes you from a clean clone to a usable backend, frontend, and worker on a developer machine.

For production deployment, see [DEPLOYMENT.md](DEPLOYMENT.md). For the full environment variable reference, see [ENV_VARS.md](ENV_VARS.md).

---

## 1. Prerequisites

| Tool | Version | Verify |
|------|---------|--------|
| Python | 3.11+ | `python --version` |
| Node.js | 20+ | `node --version` |
| pnpm | 10.30+ | `pnpm --version` (activate via `corepack enable && corepack prepare pnpm@10.30.3 --activate`) |
| PostgreSQL | 15+ | `psql --version` |
| Redis (Linux/macOS) | 7+ | `redis-cli ping` (expects `PONG`) |
| Memurai (Windows) | latest | `redis-cli ping` or `memurai-cli ping` |

PostgreSQL and Redis must be running locally on their default ports (`5432` and `6379`) before continuing.

**Optional MCP servers** (only if you want to use the `vr` or `malware` modules):

| Server | Default port | Needed for | Repo |
|--------|--------------|------------|------|
| audit-mcp | `18822` | `vr` module (all source-repo targets); can also feed `vulnerability` intel workflows | source repo |
| ida-headless-mcp | `18821` | `vr` binary targets, all `malware` investigations | [github.com/echel0nn/ida-headless-mcp-exp](https://github.com/echel0nn/ida-headless-mcp-exp) |
| android-mcp | `18823` | `vr` audits against `android_apk` targets (MASVS L1/L2 pipeline) | source repo |

All three are HTTP servers you run alongside AILA on the same host (or reachable over the network). The platform, `vulnerability`, `forensics`, and `hello_world` modules do NOT require any MCP. See section 4 below for install + start.

---

## 2. Install

### 2a. Create a Python 3.11+ virtualenv

The project requires Python 3.11+. If your system Python is older (e.g., Ubuntu 22.04 ships 3.10), get 3.11 first:

```bash
# Option A -- via uv (recommended, no apt repo work needed)
curl -LsSf https://astral.sh/uv/install.sh | sh
uv python install 3.11
PY311=$(uv python find 3.11)

# Option B -- via deadsnakes PPA on Ubuntu/Debian
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt install python3.11 python3.11-venv python3.11-dev
PY311=python3.11
```

Create and activate the venv:

```bash
git clone <repo-url> aila
cd aila
$PY311 -m venv .venv
source .venv/bin/activate
```

### 2b. Install backend + frontend deps

```bash
pip install --upgrade pip
pip install -e ".[dev]"
corepack enable && pnpm install
```

The frontend is a pnpm workspace at the repo root; `pnpm install` wires up `@aila/shell`, `@aila/typescript-config`, and the five module packages (`@aila/forensics-frontend`, `@aila/hello-world-frontend`, `@aila/malware-frontend`, `@aila/vr-frontend`, `@aila/vulnerability-frontend`) in one pass.

> **Verify the venv is activated**: `which uvicorn` should print a path inside `.venv/bin/`. If it prints `~/.local/bin/uvicorn` or `/usr/bin/uvicorn`, your venv is not active and uvicorn will fail to import `aila` (because system Python doesn't have it installed).
Or:

```bash
make install
```

`pip install -e ".[dev]"` installs AILA in editable mode with dev dependencies (pytest, ruff, bandit, pip-audit). It also registers the `aila` console script defined by `pyproject.toml` (`aila = "aila.cli:app"`).

---

## 3. Database Setup

The fastest path is the dockerized dev infra at `infra/utilities/docker-compose.yml`. It brings up Postgres 16 (with pgvector pre-installed) and Redis 7 with credentials matching `.env.example`:

```bash
cp .env.example .env       # then edit it (see env vars table below)
make dev-up                # starts postgres on :5432 and redis on :6379, healthy in ~10s
make db-init               # creates schema from SQLModel + stamps Alembic head (one-time)
```

`make dev-up` is idempotent and safe to re-run. Use `make dev-down` to stop, `make dev-reset` to wipe data volumes, `make dev-logs` to follow service logs.

If you prefer a host-installed Postgres + Redis, skip `make dev-up`/`make dev-reset` and create the database manually:

```bash
createdb aila
psql -U postgres -d aila -c "CREATE EXTENSION IF NOT EXISTS vector;"
make db-init
```

Edit `.env` and set at minimum:

| Variable | Example | Notes |
|----------|---------|-------|
| `AILA_DATABASE_URL` | `postgresql+asyncpg://postgres:<password>@localhost:5432/aila` | Required. PostgreSQL is the only supported DB. |
| `AILA_PLATFORM_REDIS_URL` | `redis://127.0.0.1:6379/0` | Required (task queue + SSE). |
| `AILA_JWT_SECRET_KEY` | output of `openssl rand -hex 32` | Required. |
| `AILA_ADMIN_PASSWORD` | a strong password you choose | **Required on first boot only.** Used to create the `admin` user. After first successful startup, REMOVE this variable. |
| `OPENAI_API_KEY` | your OpenAI-compatible provider key | Required for LLM-backed features. |
| `AILA_CORS_ORIGINS` | `http://localhost:3000` | Comma-separated; must include the frontend origin. |
| `AUDIT_MCP_URL` | `http://127.0.0.1:18822` | Only if using `vr`. |
| `IDA_HEADLESS_URL` | `http://127.0.0.1:18821` | Only if using `malware`, or `vr` on binary targets. |
| `ANDROID_MCP_URL` | `http://127.0.0.1:18823` | Only if using `vr` on `android_apk` targets. |

For an existing database (any subsequent runs), apply pending migrations:

```bash
make migrate
# or, equivalently:
cd src/aila && alembic upgrade head && cd ../..
```

`alembic.ini` lives under `src/aila/`, so the alembic CLI must be run from that directory. Both `make migrate` and `make db-init` handle the cwd for you. The repo's alembic `env.py` and the FastAPI app both auto-load `.env` at the repo root via `aila._dotenv.load_project_env()` -- no need to `export` env vars before each command.

---

## 4. MCP Servers (only if using `vr` or `malware`)

Skip this section if you only want the platform, `vulnerability`, `forensics`, and `hello_world` modules.

Each MCP is a separate HTTP server. Install and run each one in its own terminal or under your process supervisor of choice. The AILA backend and workers connect over HTTP using the URLs from `.env`.

### ida-headless-mcp

Required for `malware`; required for `vr` on binary targets.

```bash
git clone https://github.com/echel0nn/ida-headless-mcp-exp.git
cd ida-headless-mcp-exp
pip install -e .
ida-headless-http --port 18821
```

This needs a working IDA Pro installation on the same host. See the repo's README for full setup.

### audit-mcp

Required for `vr`. Install from its own source repo and run against port `18822`:

```bash
audit-mcp serve --port 18822
```

See [docs/VR_INSTALLATION_GUIDE.md](VR_INSTALLATION_GUIDE.md) for the full install + tuning walkthrough (thread pool caps, per-tool timeouts, semble cache).

### android-mcp

Only required if you point `vr` at an `android_apk` target. Install its host-side deps (`apktool`, `jadx`, `androguard`, optionally `MobSF`), then run:

```bash
python -m android_mcp --mode http --port 18823
```

See [docs/VR_INSTALLATION_GUIDE.md](VR_INSTALLATION_GUIDE.md) section 3 for the full Android tooling matrix.

### Verify

```bash
curl -s http://127.0.0.1:18821/ && echo   # ida-headless
curl -s http://127.0.0.1:18822/tools/list_indexes && echo   # audit-mcp
curl -s http://127.0.0.1:18823/ && echo   # android-mcp
```

All three should return JSON. A connection-refused error means the server is not running or is bound to a different port.

---

## 5. Start Services

AILA runs as three processes (four if you use `malware`, five if you use `vr`). Open a terminal per process.

```bash
# Terminal 1 -- Backend API (FastAPI on :8000)
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 -- Frontend (Vite dev server on :3000, single SPA bundling all modules)
pnpm dev

# Terminal 3 -- Default task worker (ARQ over Redis)
python -m aila worker
```

Or, in one terminal:

```bash
make dev-all
```

`make dev-all` brings up dev infra and all services (backend, frontend, workers) under one supervisor (Ctrl+C stops everything). `make dev` by itself only prints the canonical workflow above -- it does not start anything.

---

## 6. Verify

| Surface | URL | Notes |
|---------|-----|-------|
| Backend OpenAPI docs | http://localhost:8000/docs | FastAPI Swagger UI; lists platform + module routes |
| Health check | http://localhost:8000/health | Should return 200 |
| Frontend | http://localhost:3000 | Vite dev server (single SPA hosting all module UIs) |
| Login | username `admin` / password = your `AILA_ADMIN_PASSWORD` | First-boot value. Change it after login, then remove the env var. |

If the backend health endpoint returns 200 and the frontend renders the login page, the platform is up.

> **Why `admin` and not `admin/admin`?** AILA refuses to start if no admin user exists and `AILA_ADMIN_PASSWORD` is unset (D-21 security policy). On first boot, the username `admin` is created with the hash of whatever you set in `AILA_ADMIN_PASSWORD`. There is no hardcoded default password.

---

## 7. Module-specific Workers (optional)

The default worker subscribes to the `default` queue. Module-heavy workloads (vulnerability scans, forensics analyses) are dispatched to dedicated queues so they can be scaled independently. Run additional workers per queue track:

```bash
python -m aila worker -q vr                  # vulnerability research (needs audit-mcp; ida-headless for binary targets; android-mcp for APKs)
python -m aila worker -q malware             # malware reverse engineering (needs ida-headless-mcp)
python -m aila worker -q vulnerability       # vulnerability scans (CVE, scoring, remediation)
python -m aila worker -q forensics           # DFIR investigations, evidence analysis
```

Or via Make:

```bash
make worker            # default queue
make worker-vr         # vr queue
make worker-malware    # malware queue
make worker-vuln       # vulnerability queue
make worker-forensics  # forensics queue
```

Each worker process subscribes to one queue (`arq:queue:<name>`). For multi-module deployments, run one worker per queue.

---

## 8. Running Tests

```bash
make test           # backend unit tests (excludes E2E suites)
make test-frontend  # frontend unit tests (shell only). For all modules: pnpm -r run test
make check          # full quality gates: ruff, honesty, compileall, typecheck
```

Or run individual checks directly:

```bash
# Backend
python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py
python -m ruff check src/aila/
python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py
python -m compileall -q src/aila
make security-scan                       # pip-audit + bandit

# Frontend (from repo root)
pnpm -r run type-check                   # TypeScript across shell + all 4 modules
pnpm -r run test                         # vitest across shell + modules
pnpm --filter @aila/shell run build      # production build
```

---

## Next Steps

- [MODULE_TUTORIAL.md](MODULE_TUTORIAL.md) -- build your first module
- [MODULE_STANDARD.md](MODULE_STANDARD.md) -- module authoring contract
- [ARCHITECTURE.md](ARCHITECTURE.md) -- platform internals
- [ENV_VARS.md](ENV_VARS.md) -- full environment variable reference
- [DEPLOYMENT.md](DEPLOYMENT.md) -- production deployment
