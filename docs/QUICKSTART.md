# AILA Quickstart

Zero-to-running guide for AILA (AI Lab Assistant). Takes you from a clean clone to a usable backend, frontend, and worker on a developer machine.

For production deployment, see [DEPLOYMENT.md](DEPLOYMENT.md). For the full environment variable reference, see [ENV_VARS.md](ENV_VARS.md).

---

## 1. Prerequisites

| Tool | Version | Verify |
|------|---------|--------|
| Python | 3.11+ | `python --version` |
| Node.js | 20+ | `node --version` |
| npm | bundled with Node | `npm --version` |
| PostgreSQL | 15+ | `psql --version` |
| Redis (Linux/macOS) | 7+ | `redis-cli ping` (expects `PONG`) |
| Memurai (Windows) | latest | `redis-cli ping` or `memurai-cli ping` |

PostgreSQL and Redis must be running locally on their default ports (`5432` and `6379`) before continuing.

---

## 2. Install

```bash
git clone <repo-url> aila
cd aila
pip install -e ".[dev]"
cd frontend && npm install && cd ..
```

Or:

```bash
make install
```

`pip install -e ".[dev]"` installs AILA in editable mode with dev dependencies (pytest, ruff, bandit, pip-audit). It also registers the `aila` console script defined by `pyproject.toml` (`aila = "aila.cli:app"`).

---

## 3. Database Setup

Create the database, copy the example env file, edit it, then run migrations.

```bash
# Create the database
createdb aila
# Or via psql:
#   psql -U postgres -c "CREATE DATABASE aila;"

# Copy env template and edit it
cp .env.example .env
```

Edit `.env` and set at minimum:

| Variable | Example |
|----------|---------|
| `AILA_DATABASE_URL` | `postgresql+asyncpg://postgres:<password>@localhost:5432/aila` |
| `AILA_JWT_SECRET_KEY` | output of `openssl rand -hex 32` |
| `OPENAI_API_KEY` | your OpenAI-compatible provider key |

Run migrations. `alembic.ini` lives under `src/aila/`, so the command must be run from that directory:

```bash
cd src/aila && alembic upgrade head && cd ../..
```

Or:

```bash
make migrate
```

---

## 4. Start Services

AILA runs as three processes. Open three terminals.

```bash
# Terminal 1 — Backend API (FastAPI on :8000)
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 — Frontend (Vite dev server on :3000)
cd frontend && npm run dev

# Terminal 3 — Default task worker (ARQ over Redis)
python -m aila worker
```

Or, in one terminal:

```bash
make dev
```

`make dev` starts all three processes together.

---

## 5. Verify

| Surface | URL | Notes |
|---------|-----|-------|
| Backend OpenAPI docs | http://localhost:8000/docs | FastAPI Swagger UI; lists platform + module routes |
| Frontend | http://localhost:3000 | Vite dev server |
| Default login | `admin` / `admin` | Change immediately after first login |

If the backend health endpoint returns 200 and the frontend renders the login page, the platform is up.

---

## 6. Module-specific Workers (optional)

The default worker subscribes to the `default` queue. Module-heavy workloads (vulnerability scans, forensics analyses) are dispatched to dedicated queues so they can be scaled independently. Run additional workers per queue track:

```bash
python -m aila worker -q vulnerability
python -m aila worker -q forensics
```

Each worker process subscribes to one queue (`arq:queue:<name>`). For multi-module deployments, run one worker per queue.

---

## 7. Running Tests

```bash
make test      # unit tests (excludes E2E suites)
make check     # full quality gates: ruff, pytest, honesty audit, compileall, security-scan
```

Or run individual checks directly:

```bash
python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py
python -m ruff check src/aila/
python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py
python -m compileall -q src/aila
make security-scan                       # pip-audit + bandit
cd frontend && npm run typecheck
cd frontend && npm run build
```

---

## Next Steps

- [MODULE_TUTORIAL.md](MODULE_TUTORIAL.md) — build your first module
- [MODULE_STANDARD.md](MODULE_STANDARD.md) — module authoring contract
- [ARCHITECTURE.md](ARCHITECTURE.md) — platform internals
- [ENV_VARS.md](ENV_VARS.md) — full environment variable reference
- [DEPLOYMENT.md](DEPLOYMENT.md) — production deployment
