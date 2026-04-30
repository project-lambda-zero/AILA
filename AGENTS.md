# Repository Guidelines

AILA (AI Lab Assistant) is a modular AI security platform exposing a Typer CLI, a FastAPI REST API, and a Vite + React + TS frontend. The runtime is Python 3.11+, persistence uses SQLModel/Alembic over PostgreSQL, and async work is dispatched through ARQ on Redis. The platform owns infrastructure (routing, runtime, services, contracts, tools); feature modules own domain logic. Four modules ship today: `vulnerability`, `forensics`, `sbd_nfr`, and `hello_world` (canonical example).

## Project Structure & Module Organization

- `src/aila/platform/` — shared infrastructure (`runtime/`, `routing/`, `services/`, `contracts/`, `tools/`, `tasks/`, `llm/`, `sse/`, `workflows/`, `automation/`, `events/`, `modules/`, `config.py`, `uow.py`, `rate_limiter.py`, `exceptions.py`). Never imports from `modules/`.
- `src/aila/modules/<module_id>/` — feature modules. One module never imports from another. Each follows `docs/MODULE_STANDARD.md` (`module.py`, `runtime.py`, `capabilities.py`, `tool_keys.py`, `workflow.py` or `workflow/`, `contracts/`, `tools/`, `services/`, `reporting/`; optional `api_router.py`, `db_models/`, `frontend/`).
- `src/aila/alembic/versions/` — append-only migrations; `alembic.ini` lives at `src/aila/alembic.ini`.
- `src/aila/api/` — FastAPI app, routers, auth, middleware. CLI entry point is `aila = "aila.cli:app"`.
- `tests/` — pytest suite mirroring source layout. `tests/test_e2e*.py` require live infrastructure (DB, Redis, LLM) and are gated.
- `frontend/` — top-level Vite + React + TS shell. Module UIs live under `src/aila/modules/<id>/frontend/` and are mounted by the shell.
- `docs/` — canonical specs: `MODULE_STANDARD.md`, `GOLDEN_RULES.md`, `HONESTY_AUDIT.md`, `LLM_INTEGRATION.md`, `SSE_GUIDE.md`, `CONFIG_REGISTRY.md`, `ARCHITECTURE.md`, `TEST_GUIDE.md`.

## Build, Test, and Development Commands

```bash
pip install -e ".[dev]"                                                       # install with dev deps
python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py
python -m ruff check src/aila/                                                # lint (must be clean)
python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py  # structural honesty audit
python -m compileall -q src/aila                                              # smoke compile
cd src/aila && alembic upgrade head                                           # apply migrations
python -m aila worker                                                         # ARQ worker, default queue
python -m aila worker -q vulnerability                                        # vulnerability queue
python -m aila worker -q forensics                                            # forensics queue
uvicorn aila.api.app:app --host 0.0.0.0 --port 8000 --reload                  # API, dev mode
cd frontend && npm run dev                                                    # frontend on :3000
cd frontend && npm run typecheck                                              # TS check
cd frontend && npm run build                                                  # production build
make security-scan                                                            # pip-audit + bandit
```

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
