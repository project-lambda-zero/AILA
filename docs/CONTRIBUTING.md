# Contributing to AILA

AILA (AI Lab Assistant) is a modular AI security platform: Python 3.11+ backend
(FastAPI, SQLModel/Alembic over PostgreSQL, ARQ/Redis), a Typer CLI, and a React
+ Vite + TypeScript frontend. The platform owns infrastructure (routing,
runtime, services, contracts, tools); modules own domain logic.

This guide is for engineers contributing to the platform or shipping a new
module. It assumes familiarity with Python, FastAPI, and async I/O.

---

## 1. Getting Started

### Clone

```bash
git clone <repo-url> AILA
cd AILA
```

### Install

Full setup steps (Postgres, Redis, env vars, migrations, first run) live in
[`./QUICKSTART.md`](./QUICKSTART.md). The minimum to start hacking on Python
code is:

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Frontend work uses the pnpm workspace at the repo root:

```bash
corepack enable && pnpm install
```

### Branch

Branch off `main` for every change. Naming convention is in section 3.

```bash
git checkout main
git pull
git checkout -b feat/<module>/<short-description>
```

---

## 2. Module Development

A module is a self-contained domain unit under `src/aila/modules/<module_id>/`.
The platform discovers and wires modules at boot — adding one requires no
platform edits beyond registration.

### Scaffold

Copy the template and rename:

```bash
cp -r src/aila/modules/_template src/aila/modules/my_module
```

Rename `Template` / `TEMPLATE` symbols to your module name. The template's
[`README.md`](../src/aila/modules/_template/README.md) lists every required
substitution.

### Required structure

Every module must provide:

| File | Purpose |
|---|---|
| `module.py` | `ModuleProtocol` implementation + `create_module()` factory |
| `runtime.py` | `ModuleRuntime.handle()` request handler |
| `capabilities.py` | `MODULE_DESCRIPTION`, `MODULE_TOOLS`, `MODULE_EXAMPLES` |
| `tool_keys.py` | Tool key constants, prefixed with `<module_id>.` |
| `workflow.py` (or `workflow/`) | Explicit state machine |
| `contracts/` | Pydantic boundary models |
| `tools/` | `Tool` subclass implementations |
| `services/` | Domain service layer |
| `reporting/` | Report generation |

Optional: `api_router.py`, `db_models/`, `frontend/`. The full contract is
[`docs/MODULE_STANDARD.md`](MODULE_STANDARD.md) (v2.1).

### Working reference

[`src/aila/modules/hello_world/`](../src/aila/modules/hello_world/) is the
canonical minimal-but-complete module. It exercises every required surface —
runtime, capabilities, tool keys, workflow, contracts, tools, services,
reporting, and `api_router.py` — and is the recommended reference when shaping
a new module.

### Register

Append your module to `src/aila/platform/modules/builtin.py`. The platform's
discovery loop picks it up on next boot; mismatches against
`MODULE_STANDARD.md` fail fast at startup.

### Boundary rules

- A module must never import from another module.
- A module may import only from `aila.platform.*` and its own subpackages.
- `api_router.py` must defer platform imports inside `route_specs()` to avoid
  import cycles at module load.
- Tool keys must be prefixed with the module id (e.g. `hello_world.greet`).

---

## 3. Branch Naming

```text
feat/<module>/<description>     # new functionality in a module
fix/<module>/<description>      # bug fix in a module
docs/<description>              # documentation-only change
```

`<module>` is the module id (`forensics`, `hello_world`, `sbd_nfr`, `vr`,
`vulnerability`) or `platform` for platform-wide work. `<description>` is
kebab-case and short.

Examples:

```text
feat/vulnerability/epss-scoring
fix/forensics/empty-evidence-list
docs/env-vars-reference
```

---

## 4. Commit Format

Imperative mood, subject line at most 72 characters, scoped prefix.

```text
<type>(<scope>): <subject>
```

- `<type>`: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`.
- `<scope>`: module id, `platform`, `frontend`, `cli`, or a doc area.
- `<subject>`: imperative, no trailing period.
- Body (optional, blank line above) explains **why**, not what. Reference
  issues by number where applicable.

Examples:

```text
feat(vulnerability): add EPSS scoring
fix(forensics): handle empty evidence list
docs: update ENV_VARS reference
refactor(platform): consolidate UoW session lifecycle
```

---

## 5. Quality Gates

Every PR must pass all four gates. Run them locally before pushing.

| # | Gate | Command |
|---|---|---|
| 1 | Unit tests | `python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py` |
| 2 | Honesty audit | `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py` |
| 3 | Lint | `python -m ruff check src/aila/` |
| 4 | Frontend typecheck (if frontend changed) | `pnpm -r run type-check` (workspace-wide) |

The honesty audit must report zero findings. Whitelist entries in
[`honesty_whitelist.py`](../honesty_whitelist.py) require an inline comment
justifying the pattern; unjustified entries are rejected. See
[`docs/HONESTY_AUDIT.md`](HONESTY_AUDIT.md) for the rule catalogue.

Or run all gates at once:

```bash
make check
```

---

## 6. Code Style

The full standard is in [`docs/GOLDEN_RULES.md`](GOLDEN_RULES.md). The points
that block PRs:

- **PEP 8.** Enforced by `ruff`.
- **Type annotations on every public function.** `-> dict` is not a type. Use
  Pydantic models or `TypedDict` for structured returns.
- **Google-style docstrings** on every public class and function. Explain
  *why*, not what the signature already shows.
- **`__all__` on every public module.** No exceptions.
- **No bare `except Exception`.** Catch what you expect, let the rest
  propagate. Log at minimum if you must catch broadly.
- **No `**kwargs` passthrough** without validating keys against a known set.
- **No TODO / FIXME** in committed code. File an issue.
- **No dead code.** If it is not called, delete it. No "moved to X" comments,
  no re-exports kept "for now".
- **No legacy preservation.** Refactors cut over fully — no shims, no parallel
  APIs, no compatibility wrappers unless explicitly requested.

---

## 7. Testing

Test stack and conventions are in [`docs/TEST_GUIDE.md`](TEST_GUIDE.md).
Summary:

- **Runner:** `pytest` with `pytest-asyncio` for async tests.
- **HTTP:** `httpx.AsyncClient` with `ASGITransport`. Do **not** use
  Starlette's `TestClient` — it deadlocks on SSE and async routes.
- **Layout:** mirror the source tree under `tests/`. API tests under
  `tests/api/`, module tests under `tests/modules/<module_id>/`.
- **Naming:** `test_<behavior>.py::test_<case>`. The filename names the
  behavior under test; the function name names the case.
- **Fixtures over inline setup.** Reuse `tests/conftest.py`,
  `tests/api/conftest.py`, and module-level conftests rather than
  reconstructing state per test.
- **Unit tests stay infrastructure-free.** No live Postgres, Redis, LLM, or
  network. Use the seeded `test_db` fixture and async clients. Anything that
  needs real infrastructure belongs in `tests/test_e2e.py` or
  `tests/test_e2e_live.py`, both of which are excluded from the unit-test
  gate.
- **Mocks at the boundary only.** Mock external services; do not mock the code
  under test.

Run a focused subset while iterating:

```bash
python -m pytest tests/modules/<module_id> -x -q
```

---

## 8. Pull Request Process

1. Confirm all four quality gates pass locally (`make check`).
2. Push the branch and open a PR against `main`.
3. PR description must state:
   - **What changed.** The user-visible or system-visible behavior.
   - **Why.** The motivation — the bug, the requirement, the design force.
   - **Scope.** Modules, platform subsystems, or surfaces touched.
   - **Issue link.** `Closes #<n>` or `Refs #<n>` where applicable.
4. CI re-runs every gate. Failures block merge — fix them, do not retry.
5. Address review comments by amending commits where it keeps history clean,
   or by adding follow-up commits where the review trail matters. Squash on
   merge unless the history is intentionally preserved.

A PR is mergeable when gates pass, review is resolved, and the change is a
coherent unit — not a partial migration that leaves the design contradicting
itself.

---

## 9. AI-Assisted Development

Many contributors use Claude Code, Cursor, Copilot, or other LLM-powered
editors. The repository is set up to support this.

### Project-level instructions

`.claude/CLAUDE.md` is auto-discovered by Claude Code at session start. It
contains the repository layout, build commands, module authoring steps, 5
non-negotiable rules, 8 common mistakes, and a verification checklist. Other
LLM editors can be pointed to this file manually.

### What LLMs get wrong in this codebase

These are the patterns that consistently require human correction:

1. **Top-level `api_router` imports in `module.py`.** MODULE_STANDARD requires
   deferred import inside `route_specs()`. The honesty audit catches this, but
   every LLM defaults to top-of-file imports.
2. **Bare `except Exception`.** LLMs default to broad catches. Use specific
   types: `(OSError, TimeoutError, RuntimeError)` for infrastructure paths.
3. **Missing `__all__`.** LLMs forget this on every new file. Every
   `__init__.py` and public module needs it.
4. **Cross-module imports.** LLMs will import from `aila.modules.vulnerability`
   inside `aila.modules.forensics` without hesitation. The honesty audit flags
   this, but catch it during review.
5. **`os.getenv` instead of ConfigRegistry.** Module-scoped config must use
   `ConfigRegistry.get()`, which resolves env var -> DB -> schema default.
6. **Schema changes without Alembic.** LLMs will use `metadata.create_all()`
   or raw `CREATE TABLE`. All DDL goes through `src/aila/alembic/versions/`.

### Workflow with AI editors

1. Let the LLM generate. Do not trust the output.
2. Run `make check` before committing -- this catches 90% of LLM mistakes.
3. Review every import the LLM added. Check it doesn't cross module boundaries.
4. Review every `except` block. Check it catches specific types.
5. Verify `__all__` exists on every new file.
6. If the LLM suggests a "compatibility wrapper" or "backwards-compatible
   shim" -- delete it. This codebase does full cutover, not gradual migration.

---

## 10. Frontend Conventions

The frontend is React + Vite + TypeScript with Tailwind CSS v4.

### Design system

Use the platform design system everywhere:

- Backgrounds: `bg-base`, `bg-surface`, `bg-elevated`
- Text: `text-text`, `text-text-muted`, `text-accent`
- Borders: `border-border`
- CSS variables: `var(--color-*)` for dynamic theming
- Components: `AilaCard`, `AilaBadge`, `EmptyState`, shadcn components

### Rules

- **No custom CSS files.** Tailwind utilities + CSS variables only.
- **No hardcoded hex colors.** Use CSS variables or Tailwind tokens.
- **No Tailwind arbitrary values** like `h-[720px]` or `bg-[#131313]`.
  Tailwind v4 does not generate them. Use inline `style={{ height: 720 }}`.
- **No `position: fixed` overlay layouts.** Pages render inside AppShell's
  content area.
- **CSS variables in SVG:** Recharts `fill` attributes do not resolve
  `var(--color-*)`. Use the `useThemeChartColors()` hook to resolve hex values
  via `getComputedStyle`.

### Module frontend contribution

Modules contribute UI via `ModuleFrontendSpec` in `frontend/spec.ts`:

```typescript
export const frontendSpec: ModuleFrontendSpec = {
  moduleId: "my_module",
  nav: [{ id: "my_module.home", slot: "sidebar.main", label: "My Module",
          to: "/my_module", order: 100 }],
  routes: [{ id: "my_module.home", path: "/my_module", title: "My Module",
             nav: true, slot: "page.full", page: MyModulePage }],
};
```

See `src/aila/modules/hello_world/frontend/` for a working example.

---

## 11. Startup Scripts

| Script | Platform | Usage |
|---|---|---|
| `start.sh` | Windows (Git Bash) | `bash start.sh` / `bash start.sh stop` |
| `start-linux.sh` | Linux / macOS | `./start-linux.sh` / `./start-linux.sh stop` |
| `make dev` | Any (prints instructions) | `make backend`, `make frontend`, `make worker` in separate terminals |

The startup scripts load `.env`, start audit-mcp, the FastAPI backend, 5 ARQ
workers (default, vr, vulnerability, forensics, sbd_nfr), and the Vite frontend.
Logs go to `/tmp/aila_*.log`.

---

## Questions

Open an issue. There is no chat channel.