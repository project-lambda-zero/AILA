# Production Rubric

Pre-merge readiness checklist for any change that lands a feature module
in production. Run every gate below — green across the board is the bar.

The rubric is enforced by `make check` plus targeted tests; the per-item
rows below explain *what* each gate asserts and *why* a green result means
the change is shippable.

---

## 0. Scope and Definitions

"Module" means a package under `src/aila/modules/<name>/` that the platform
discovers via `pkgutil.iter_modules`. The reference module is
`hello_world`; the production set today is `forensics`, `sbd_nfr`, `vr`,
`vulnerability`. Platform-level changes (`src/aila/platform/*`,
`src/aila/api/*`) use the same gates but additionally require sign-off
from a code-reviewer agent.

---

## 1. Build Gates

| Gate | Command | Pass criterion |
|------|---------|---------------|
| Bytecode compile | `python -m compileall -q src/aila` | Exits 0. No syntax errors anywhere in the package. |
| Lint | `python -m ruff check src/aila/` | Clean. Per-file ignores in `pyproject.toml` are intentional; new code must not extend them. |
| Honesty audit | `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py` | Zero findings. The audit catches structural dishonesty (mirroring constants, forwarding wrappers, fake managers, eager `api_router` imports in `module.py`, bare `except Exception`, missing `__all__`). |
| Frontend typecheck | `pnpm -r run type-check` | Clean across `@aila/shell` and every `@aila/<module>-frontend` workspace member. |
| Frontend build | `pnpm --filter @aila/shell run build` | Exits 0; emits the single SPA bundle. |

Aggregate: `make check` runs lint + honesty + compile + typecheck. Use it
as the one-shot gate.

---

## 2. Test Gates

| Gate | Command | Pass criterion |
|------|---------|---------------|
| Backend unit tests | `python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py` | Every test the module adds passes. Pre-existing failures are documented in the PR description, not silenced. |
| Module-specific tests | Tests under `tests/<module>_*.py` cover every state machine branch, every error path, every contract field a caller relies on. | Domain logic, not plumbing — the test would actually break if the bug came back. No `assert True`-style sentinels. |
| Frontend unit tests | `pnpm -r run test` | Vitest passes across every workspace package, including the module's own `tests/` folder. |
| Optional E2E | `pytest tests/test_e2e.py` (Playwright + live infra) | Green only when the change affects user-visible flows; otherwise skipped and noted in the PR. |

Test conduct:

- Test behaviour, not defaults. Changing a config default must not break a
  test that asserts the config default.
- Exercise every conditional branch and at least one error path per public
  surface (HTTP route, tool, workflow handler).
- No new mocks of internal AILA code. Mocks for paramiko, openai, httpx
  upstreams are fine.

---

## 3. Architectural Rules

| Rule | How to verify |
|------|---------------|
| Platform does not import from `aila.modules.*` | `python -m aila.tools.honesty_audit` plus a manual `grep` if you added a new import. |
| Modules do not import from each other (Python or frontend) | Python: honesty audit. Frontend: `pnpm install` fails on undeclared bare imports in strict mode. |
| Module config goes through `ConfigRegistry`, not `os.getenv` | Search the module for `os.getenv` / `os.environ.get`. Allowed cases: the platform `app.py`, `cli.py`, `_dotenv.py`, and the `argon2` / `redis` / `openai` provider plumbing that resolves credentials. Module code paths use `await registry.get("<module_id>", "<key>")` with a registered schema. |
| Multi-step behaviour is an explicit state machine | The module exposes a `workflow.py` (or `workflow/` package) that names states and transitions. Long if/elif chains over `status` strings are a red flag. |
| All DDL goes through Alembic | A new column, table, or index requires a versioned file under `src/aila/alembic/versions/`. No `metadata.create_all()` outside test fixtures. No runtime `CREATE TABLE`. |
| Errors raise typed exceptions | New error paths raise an `AILAError` subclass with `ClassVar code` + `http_status` + `user_message`. Generic `RuntimeError` for user-visible failures is a regression. |

---

## 4. Surface Conformance

| Surface | Bar |
|---------|-----|
| `module.py` | Defers the `api_router` import inside `route_specs()`. Eager import at module top is caught by the honesty audit. |
| Tool keys | Prefixed by `module_id.` (e.g. `vr.search_functions`). Constants live in `tool_keys.py`. |
| Public exports | Every `__init__.py` and public module declares `__all__`. Private submodules start with `_`. |
| HTTP responses | Success bodies wrap in `DataEnvelope`. Errors raise typed exceptions or `HTTPException`; see `docs/API_ERRORS.md` for the envelope contract. |
| LLM calls | Route through `AilaLLMClient` (`platform.llm`) with a routing `task_type`. Modules never instantiate `openai.AsyncOpenAI` directly. |
| Task functions | Decorated with `@platform_task`. All kwargs JSON-serializable (Pydantic models pass `.model_dump(mode="json")`). |
| Frontend | Every bare import declared in the module's `package.json`. Shared deps via `pnpm-workspace.yaml` catalogs, not literal versions. Tailwind `@source` line added to `frontend/src/styles/globals.css` if the module ships UI. |

---

## 5. Operational Readiness

| Item | Bar |
|------|-----|
| Logs | Module code uses structlog via `aila.logging_config`; every log emission inherits the request `correlation_id` automatically. No `print()`. |
| Metrics | Long-running paths emit Prometheus counters/histograms via `aila.api.metrics` or module-local registries; new metrics include label cardinality docs. |
| Audit | State-changing operations write to `AuditEventRecord` via `record_audit_event(stage="<module>", action="<verb>", ...)`. |
| LLM cost | Calls pass `run_id` so `LLMCostRecord` rows land with the right scope; pricing is configured for any new `model_id` (see `docs/LLM_INTEGRATION.md`). |
| Worker queue | If the module uses ARQ, the worker target is documented (`python -m aila worker -q <queue>`) and the runbook in `docs/RUNBOOK.md` is updated. |
| Database | New Alembic revision listed in the PR. Migration is idempotent and tested locally with `make migrate` against a non-empty DB. |
| Bootstrap impact | First-boot behaviour (`AILA_ADMIN_PASSWORD` requirement, `AILA_BOOTSTRAP_KEY` idempotency, Alembic head) is preserved. |
| Config defaults | Every new `ConfigRegistry` key has a sensible default, an env-var override pattern (`AILA_<NS>_<KEY>`), and is documented in `docs/ENV_VARS.md`. |

---

## 6. Docs and Communication

| Item | Bar |
|------|-----|
| Module README | `src/aila/modules/<name>/README.md` reflects the current contracts, routes, and tools. |
| Top-level docs | If the change shifts an externally-visible contract (auth surface, error envelope, LLM behaviour), `docs/SECURITY_MODEL.md`, `docs/API_ERRORS.md`, `docs/LLM_INTEGRATION.md`, or `docs/DATA_PROTECTION.md` are updated in the same PR. |
| Env vars | Any new env var lands in `.env.example` with a default appropriate for local development and a comment if production needs a different value. |
| Decision record | A new architectural decision lands as an ADR under `docs/ADR/` rather than a paragraph in a module README. |
| PR description | Lists the gates that ran green, the migrations involved, and the operator actions required at deploy (env vars to add, workers to restart). |

---

## 7. Verification Checklist (paste into the PR)

```
[ ] python -m compileall -q src/aila
[ ] python -m ruff check src/aila/
[ ] python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py
[ ] pnpm -r run type-check
[ ] pnpm --filter @aila/shell run build
[ ] make test                       (or: pytest tests/ --ignore=tests/test_e2e*)
[ ] pnpm -r run test
[ ] Alembic head matches src/aila/alembic/versions/ tip (if DDL touched)
[ ] LLMCostRecord pricing configured for any new model_id
[ ] No new os.getenv in module code
[ ] No new bare except Exception in module code
[ ] Affected docs updated in the same PR
```

---

## 8. Known Platform Caveats

Carry-overs callers may hit while the gates above stay green. Document
per-module exposure in the PR if the change touches these areas:

- **VR cost gauge** — `VRInvestigationRecord.cost_actual_usd` is not written
  to by the LLM client; `_compute_live_investigation_cost()` aggregates from
  `LLMCostRecord` via `TaskRecord.id`, which mismatches the workflow
  `RunRecord.id` actually stored in `LLMCostRecord.run_id` for VR. The
  budget gauge therefore underreports for VR investigations. See
  `docs/LLM_INTEGRATION.md`.
- **Restricted-behavior env values** — `.env.example` ships `transparent`
  for `AILA_PLATFORM_LLM_PIPELINE_CLASSIFY_RESTRICTED_BEHAVIOR_*`. The
  resolver only recognises `redact`; any other value (including
  `transparent`) falls back to `fail`. See `docs/DATA_PROTECTION.md`.
- **JWT secret in dev** — Missing `AILA_JWT_SECRET_KEY` synthesises a
  random secret per process start and invalidates every issued JWT on
  restart. Production deployments MUST set it explicitly.