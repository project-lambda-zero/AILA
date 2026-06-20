# Repository Guidelines

AILA (AI Lab Assistant) is a modular AI security platform exposing a Typer CLI, a FastAPI REST API, and a Vite + React + TS frontend. The runtime is Python 3.11+, persistence uses SQLModel/Alembic over PostgreSQL, and async work is dispatched through ARQ on Redis. The platform owns infrastructure (routing, runtime, services, contracts, tools); feature modules own domain logic. Five feature modules ship today (alphabetical discovery order): `forensics`, `hello_world` (canonical example), `sbd_nfr`, `vr`, and `vulnerability`.

## Project Structure & Module Organization

- `src/aila/platform/` — shared infrastructure (`runtime/`, `routing/`, `services/`, `contracts/`, `tools/`, `tasks/`, `llm/`, `sse/`, `workflows/`, `automation/`, `events/`, `modules/`, `config.py`, `uow.py`, `rate_limiter.py`, `exceptions.py`). Never imports from `modules/`.
- `src/aila/modules/<module_id>/` — feature modules. One module never imports from another. Each follows `docs/MODULE_STANDARD.md` (`module.py`, `runtime.py`, `capabilities.py`, `tool_keys.py`, `workflow.py` or `workflow/`, `contracts/`, `tools/`, `services/`, `reporting/`; optional `api_router.py`, `db_models/`, `frontend/`).
- `src/aila/alembic/versions/` — append-only migrations; `alembic.ini` lives at `src/aila/alembic.ini`.
- `src/aila/api/` — FastAPI app, routers, auth, middleware. CLI entry point is `aila = "aila.cli:app"`.
- `tests/` — pytest suite mirroring source layout. `tests/test_e2e*.py` require live infrastructure (DB, Redis, LLM) and are gated.
- `frontend/` — top-level Vite + React + TS shell. Module UIs live under `src/aila/modules/<id>/frontend/` and are mounted by the shell.
- `docs/` — canonical specs: `ARCHITECTURE.md`, `PLATFORM_INTERNALS.md`, `MODULE_STANDARD.md`, `MODULE_TUTORIAL.md`, `MODULE_AGENT_GUIDE.md`, `FRONTEND_MODULE_STANDARD.md`, `GOLDEN_RULES.md`, `HONESTY_AUDIT.md`, `PITFALL_GUIDE.md`, `PRODUCTION_RUBRIC.md`, `LLM_INTEGRATION.md`, `SSE_GUIDE.md`, `TASK_QUEUE_OPS.md`, `WORKFLOW_GUIDE.md`, `CONFIG_REGISTRY.md`, `ENV_VARS.md`, `SECURITY_MODEL.md`, `DATA_PROTECTION.md`, `API_ERRORS.md`, `OPENAPI_NOTES.md`, `DB_SCHEMA.md`, `DATABASE_MIGRATIONS.md`, `DEPLOYMENT.md`, `TEST_GUIDE.md`, `QUICKSTART.md`, `CONTRIBUTING.md`. Module-specific subtrees: `docs/vr/`, `docs/forensics/`. ADRs under `docs/ADR/`.

## Build, Test, and Development Commands

```bash
make install                                                                  # pip install -e ".[dev]" + corepack enable + pnpm install
make dev-up                                                                   # docker compose: postgres (pgvector) + redis (idempotent)
make db-init                                                                  # first run only: create tables + stamp Alembic head
make migrate                                                                  # subsequent runs: alembic upgrade head
make backend                                                                  # uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload
make frontend                                                                 # pnpm --filter @aila/shell run dev (Vite on :3000)
make worker                                                                   # ARQ worker, default queue
make worker-vr                                                                # ARQ worker, vr queue
make worker-vuln                                                              # ARQ worker, vulnerability queue
make worker-forensics                                                         # ARQ worker, forensics queue
make worker-sbd                                                               # ARQ worker, sbd_nfr queue
make check                                                                    # lint + honesty + compile + typecheck (full pre-PR gate)
make test                                                                     # backend pytest (excludes tests/test_e2e*.py)
make test-frontend                                                            # pnpm -r run test across shell + module packages
make security-scan                                                            # pip-audit + bandit
```

For direct invocation when `make` is not available, the equivalent commands are `pip install -e ".[dev]" && corepack enable && pnpm install`; `cd src/aila && alembic upgrade head`; `python -m aila worker [-q <queue>]`; `uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload`; `pnpm --filter @aila/shell run dev`; `pnpm -r run type-check`; `pnpm --filter @aila/shell run build`.

## Coding Style & Naming Conventions

- PEP 8, 4-space indent, Google-style docstrings. Every public function carries type annotations.
- `__all__` required on every `__init__.py` and public module. Private modules use a `_` prefix and omit `__all__`.
- Filenames are lowercase (`normalization.py`, not `Normalization.py`). Module IDs: lowercase letters, digits, underscore.
- Layer order inside `workflow/`: `models -> utils -> states -> orchestrator`. No upward imports.
- No bare `except Exception`. Catch specific types (e.g. `(OSError, TimeoutError, RuntimeError, AILAError)`).
- No TODOs, no dead code, no wrapper functions that only forward. Delete; do not shim.

## Testing Guidelines

- `pytest` + `pytest-asyncio` + `pytest-cov`. Tests mirror `src/aila/` under `tests/`.
- Name tests `test_<behavior>.py::test_<case>`. Prefer fixtures over inline setup; clean up sessions.
- Unit tests are infrastructure-free. Live-DB, live-Redis, and live-LLM tests are gated behind `tests/test_e2e*.py` and skipped by default in CI runs.

## Commit & Pull Request Guidelines

- Subject: imperative, <=72 chars, scoped prefix matching history: `feat(<module>): ...`, `fix(<module>): ...`, `docs: ...`.
- Body explains *why*, not *what*. Reference issue or phase IDs where relevant.
- Every PR must clear four gates: unit tests green, honesty audit zero findings (or a justified `honesty_whitelist.py` entry), `ruff` clean, Golden Rules respected (`docs/GOLDEN_RULES.md`).

## Agent-Specific Instructions

- Platform owns infrastructure; modules own domain logic. Do not move module code into `platform/`, and never cross-import between modules.
- Schema changes go through Alembic migrations only — never ad-hoc `CREATE TABLE` or implicit metadata create.
- Module-scoped runtime values come from `ConfigRegistry` (see `docs/CONFIG_REGISTRY.md`), not direct `os.getenv` access.
- Prefer deletion over compatibility shims. This repo rejects legacy preservation: cut over fully and let the type checker and tests guide the cleanup.
