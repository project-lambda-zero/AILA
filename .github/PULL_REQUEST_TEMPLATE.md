## What this PR does

One-paragraph summary of the change.

## Why

The problem this addresses, or the feature being delivered.

## How to verify

Steps a reviewer can take to confirm the change works as described.

## Quality gates

Per `CONTRIBUTING.md`, every PR must pass these:

- [ ] Unit tests pass: `pytest tests/ --ignore=tests/test_e2e.py --ignore=tests/test_e2e_live.py`
- [ ] Honesty audit clean: `python -m aila.tools.honesty_audit src/aila --whitelist honesty_whitelist.py`
- [ ] Ruff clean: `python -m ruff check src/aila/`
- [ ] Golden rules respected (`docs/GOLDEN_RULES.md`)
- [ ] If frontend changed: `pnpm -r run type-check` and `pnpm --filter @aila/shell run build` both pass

## Related issues

Closes #
