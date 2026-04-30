# Production Rubric

What works, what doesn't, and what will bite your colleagues.

Assessed by running every command a newcomer would run, reading every doc they'd follow, and building a module from the template. Not scored by the people who wrote it.

Last assessed: 2026-04-29 (v7.0)

---

## Newcomer Onboarding: What Actually Happens

### Clone and install

| Step | Works? | Issue |
|---|---|---|
| `git clone` + `pip install -e ".[dev]"` | Yes | |
| `cd frontend && npm install` | Yes | |
| `cp .env.example .env` | Yes | .env.example exists with all required vars |
| `make install` | **No on Windows** | `make` is not installed by default. QUICKSTART.md documents the manual commands but Makefile targets require GNU Make (install via `choco install make` or use WSL). |

### Database setup

| Step | Works? | Issue |
|---|---|---|
| `createdb aila` | Yes | Requires PostgreSQL running on :5432 |
| `cd src/aila && alembic upgrade head` | Yes | |
| `python -m alembic upgrade head` | **No** | `alembic` is a package, not a `__main__` module. Must `cd src/aila` first because `alembic.ini` is there. Docs say this correctly. |

### Start services

| Step | Works? | Issue |
|---|---|---|
| Backend: `uvicorn aila.api.app:app --reload` | Yes | |
| Frontend: `cd frontend && npm run dev` | Yes | |
| Workers: `python -m aila worker` | Yes | |
| `bash start.sh` | Yes on Windows Git Bash | Uses PowerShell Start-Process for persistent workers. Workers survive shell exit. |
| `./start-linux.sh` | Untested | Written but not validated on Linux. PID-based shutdown. |

### Quality gates

| Gate | Works? | Issue |
|---|---|---|
| `python -m compileall -q src/aila` | Yes | Zero errors |
| `python -m ruff check src/aila/` | **393 errors** | Pre-existing. 224 auto-fixable. Per-file ignores in pyproject.toml suppress the known ones. Newcomer running bare `ruff check` sees a wall of red. |
| Honesty audit | Yes | 5 pre-existing warnings in cli.py (do_nothing_wrapper, unused params). Not from module code. |
| `npm run typecheck` | Yes | Zero errors |
| `npm run build` | Yes | |
| `make check` | **No on Windows** | Requires GNU Make. Commands work individually. |

### Tests

| Step | Works? | Issue |
|---|---|---|
| `pytest tests/ --ignore=test_e2e*` | **1 error** | `test_knowledge_hybrid_retrieve.py` crashes with "SQLite is no longer supported" because it doesn't set `AILA_DATABASE_URL`. The test was written for the SQLite era. |
| Passing tests | 40 pass | |
| Coverage | 25.3% | Below the configured `fail_under=60`. pytest prints a FAIL line at the end even when all tests pass. Confusing for newcomers. |

---

## Module Development: What Actually Happens

### Following the template

| Step | Works? | Issue |
|---|---|---|
| Copy `_template/` to `my_module/` | Yes | |
| Rename Template -> MyModule | Yes | _template/README.md has clear instructions |
| Register in `builtin.py` | **Silent** | Auto-discovery via pkgutil scans `aila.modules` -- newcomer doesn't need to edit builtin.py at all. But docs say to do it. Confusing: is it needed or not? |
| `python -m compileall` on new module | Yes | Template compiles clean |
| Run the module | Yes | Platform discovers it, registers tools, boots |

### Following MODULE_TUTORIAL.md

| Step | Works? | Issue |
|---|---|---|
| Step 2: Set module_id | **Wrong API** | Tutorial uses `@property def module_id`. Actual protocol uses class attribute `module_id = MODULE_ID`. Tutorial also shows `display_name` and `description` properties -- these don't exist on ModuleProtocol. |
| Step 3: Define route_specs | **Wrong API** | Tutorial uses `ModuleRouteSpec(path=, method=, fn=)`. Actual dataclass uses `ModuleRouteSpec(prefix=, router_factory=, tool_keys=)`. A newcomer following this tutorial writes code that crashes at startup. |
| Step 4+: Tool registration | **Partially stale** | Tutorial references correct patterns but some imports are from old paths. |

**MODULE_TUTORIAL.md is the single most dangerous doc for a newcomer.** It teaches the wrong API. The _template/ and hello_world/ are correct. The tutorial contradicts them.

### Following MODULE_STANDARD.md

| Section | Accurate? | Issue |
|---|---|---|
| Module layout | Yes | Matches actual modules |
| Lifecycle methods | **Wrong count** | Says "four methods" -- ModuleProtocol has 17+ methods (most with defaults). Not blocking but misleading. |
| register_tools signature | **Missing `async`** | Doc shows `def register_tools(...)` but actual protocol is `async def register_tools(...)` |
| seed_data signature | **Wrong type** | Doc shows `session: Session` (sync). Actual is `session: Any` (AsyncSession in practice). Code examples use `session.exec()` not `await session.exec()`. |
| ModuleRouteSpec shape | **Stale version label** | Header says "(v1.5)" -- this is the current shape, not a v1.5 artifact. |

---

## Infrastructure: What Actually Works

### Database

| Aspect | Status |
|---|---|
| PostgreSQL + asyncpg | Working. 59 tables across 4 modules. |
| Alembic migrations | 39 versioned files. upgrade + downgrade both work. |
| Connection pooling | asyncpg pool with configurable size. |
| Backup/restore | CLI commands exist (`aila db backup/restore`). No automation. No documented drill. |

### Task queue

| Aspect | Status |
|---|---|
| ARQ + Redis | Working. 3 queue tracks (default, vulnerability, forensics). |
| Worker heartbeat | Reaper detects zombie tasks. Threshold is 24 hours (comment used to say 5 minutes -- fixed in v7.0). |
| Dead letter queue | Admin page exists. Inspect + requeue works. |
| Task dedup | SHA-256 hash prevents duplicate active submissions. |

### LLM pipeline

| Aspect | Status |
|---|---|
| Pipeline steps | classify -> call -> validate -> gate -> verify -> seal. All registered and functional. |
| Audit seals | HMAC-SHA256 persisted per call. |
| Cost tracking | Per-call token + USD estimation in CostRecord. Admin page works. |
| Temperature rejection | Configurable via env var + config DB. Covers o1, o3, o4, gpt-5, claude-opus. |
| Kill switch | Returns error without API call. Works. |

### Frontend

| Aspect | Status |
|---|---|
| Platform design system | CSS variables + Tailwind tokens. AilaCard, AilaBadge, EmptyState, PageFrame. |
| Module extension | ModuleFrontendSpec with nav, routes, panels, widgets. Auto-discovered. |
| All pages render | Verified via Playwright audit (v6.0). 40+ routes tested. |

---

## What Will Embarrass You

1. **MODULE_TUTORIAL.md teaches the wrong API.** A newcomer following it will write code that doesn't compile. The _template and hello_world are correct. The tutorial is not. Fix or delete.

2. **393 ruff errors on bare `ruff check`.** They're suppressed by per-file-ignores in pyproject.toml, but a newcomer who runs the command without `--config pyproject.toml` (which ruff auto-detects in most cases, but not all) sees 393 errors and thinks the codebase is broken.

3. **Test coverage 25.3% with fail_under=60.** Every `pytest` run prints "FAIL Required test coverage of 60.0% not reached" in red. This is the first thing a newcomer sees after tests pass. Either lower the threshold to match reality or raise coverage.

4. **One test crashes on import.** `test_knowledge_hybrid_retrieve.py` fails because it doesn't configure a PostgreSQL URL. Easy to fix (skip if no DB) but embarrassing on first run.

5. **`make` doesn't work on Windows without GNU Make.** The Makefile is well-written but Windows devs can't use it out of the box. QUICKSTART.md documents the manual commands. Consider adding a `tasks.py` (invoke) or PowerShell equivalent.

6. **Module auto-discovery vs manual registration.** `builtin.py` has explicit registration, but `pkgutil.iter_modules` also scans `aila.modules`. Docs say "register in builtin.py" -- but modules work without it. This confusion will generate questions.

7. **pyproject.toml version is 0.1.0.** The project is at v7.0 by milestone count but the Python package version is 0.1.0. OpenAPI docs, Prometheus metrics, and health endpoint all report 0.1.0 now (fixed from hardcoded 1.5.0 / 4.1 in v7.0). Either bump to 7.0.0 or accept that package version != milestone version and document why.

---

## What's Actually Solid

- Platform/module boundary is enforced by AST audit and breaks the build if violated.
- Durable state machine survives crashes, retries transient failures, and audits every transition.
- LLM pipeline has 5 post-call safety steps and cryptographic seals.
- The honesty audit catches structural dishonesty that no linter covers.
- SSH fleet scanning works end-to-end (tested on real Raspberry Pi, Arch VM).
- Forensics investigation loop with multi-turn LLM reasoning, evidence graphs, and operator steering works.
- SbD NFR questionnaire with 164 questions, conditional logic, and ReactFlow editor works.
- Frontend extension system lets modules add pages, sidebar entries, dashboard widgets, and system detail panels without touching platform code.

---

## Fix Priority

| # | Fix | Effort | Impact |
|---|---|---|---|
| 1 | Delete or rewrite MODULE_TUTORIAL.md | 1 hour | Unblocks every new module developer |
| 2 | Fix test_knowledge_hybrid_retrieve.py | 5 min | Clean first-run experience |
| 3 | Lower fail_under to 25 or remove it | 1 min | No more false FAIL on passing runs |
| 4 | Bump pyproject.toml version to 7.0.0 | 1 min | Package version matches reality |
| 5 | Add Windows-native task runner (PowerShell script or invoke) | 30 min | Windows devs get `make`-equivalent |
| 6 | Clarify auto-discovery vs builtin.py in CONTRIBUTING.md | 10 min | No more confusion about registration |
| 7 | Write missing tests to reach fail_under threshold | Days | Real coverage improvement |
