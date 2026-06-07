# Contributing to AILA

AILA is licensed under AGPL-3.0. By contributing, you agree that your contributions
will be licensed under the same terms.

## Prerequisites

- Python 3.11+
- Node.js 20+ and `corepack enable` (frontend uses pnpm)
- `pip install -e ".[dev]"` for backend development dependencies
- Docker (for `make dev-up` Postgres + Redis) OR host-installed Postgres 15+ with pgvector and Redis 7+
- OpenAI-compatible API key for LLM-backed features
- Vulnerability-module e2e tests require 4 reachable SSH VMs (`ubuntu-vm`, `arch-vm`, `alpine-vm`, `debian-vm`)

## Development Setup

```bash
git clone <repo-url>
cd AILA
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
pip install -e ".[dev]"
corepack enable && pnpm install
```

Or `make install` for the same two-step bundle. See [docs/QUICKSTART.md](docs/QUICKSTART.md) for the full zero-to-running walkthrough (database, env vars, services).

## Running Tests

```bash
# Unit tests (fast, no infra needed)
python -m pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py

# E2E tests (requires live VMs + LLM config)
python -m pytest tests/test_e2e.py -v

# Honesty audit (must exit 0)
python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py

# Linter
python -m ruff check src/aila/
```

## Before Submitting a PR

Every PR must pass all four gates:

1. **Unit tests pass** -- `pytest` exits 0
2. **Honesty audit clean** -- 0 findings (or whitelist entry with justification)
3. **Ruff clean** -- no lint violations
4. **Golden rules respected** -- see `docs/GOLDEN_RULES.md`

## Code Standards

### Architecture

- **Platform provides, modules consume.** Platform code (`src/aila/platform/`) must never
  import from any module (`src/aila/modules/`).
- **Modules are isolated.** A module must never import from another module's package.
- **Contracts live in `contracts/`.** Pydantic models that cross boundaries go in `contracts/`,
  never scattered in implementation files.
- **One tool per concern.** Tools are single-responsibility. CRUD lifecycle tools on one
  resource are acceptable (up to 6 actions); unrelated concerns in one tool are not.

### Style

- **Google-style docstrings.** Every public class and function gets a docstring.
- **Type annotations on every public function.** `-> dict` is not a type. Use Pydantic models
  or TypedDict for structured returns.
- **No `**kwargs` passthrough** without validation. If a function accepts `**kwargs`, it must
  validate keys against a known set.
- **No bare `except Exception: pass`.** Log at minimum. Re-raise if possible.
  `__del__` finalizers are the only accepted exception.

### What Not To Do

- No TODO/FIXME in committed code. File an issue instead.
- No dead code. If it's not called, delete it.
- No copy-paste. If the same pattern appears in 3+ places, extract it.
- No over-engineering. A factory for one class is waste. Three similar lines beat a premature abstraction.
- No AI slop. Boilerplate docstrings that restate the signature, defensive `isinstance` checks on
  values you just constructed, and wrapper functions that add nothing are all rejected.

### Honesty Audit

AILA has a built-in 15-rule AST-based honesty checker. If your code triggers a finding,
either fix it or add a whitelist entry in `honesty_whitelist.py` with a comment explaining
why the pattern is acceptable. Unjustified whitelist entries will be rejected.

## Module Development

New modules go in `src/aila/modules/<your_module>/`. Use `src/aila/modules/_template/` as
the starting point. A module must implement:

- `module.py` with a class implementing `ModuleProtocol`
- `contracts/` for Pydantic boundary models
- `tools/` for platform Tool subclasses
- `services/` for business logic
- `db_models/` for SQLModel tables (if needed)

See `docs/MODULE_STANDARD.md` for the full specification.

## Commit Messages

- Concise subject line (imperative mood, under 72 chars)
- Body explains **why**, not what
- Reference issue numbers where applicable

## Questions?

Open an issue. There is no Slack or Discord yet.
