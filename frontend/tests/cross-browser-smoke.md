# Cross-Browser Smoke Tests

## Overview

Playwright is configured with three browser projects in `playwright.config.ts`.
Cross-browser coverage is scoped to the most critical flows to keep CI time reasonable.

## Browser Projects

| Project | Scope | Test Files |
|---------|-------|------------|
| `chromium` | Full E2E suite (all spec files) | `tests/e2e/**/*.spec.ts` |
| `firefox` | Cross-browser smoke: auth + dashboard + systems list | See below |
| `webkit` | Cross-browser smoke: auth + dashboard + systems list | See below |

## Cross-Browser Smoke Scope (Firefox + WebKit)

These spec files run in all three browsers:

- `tests/e2e/auth/login.spec.ts` — Login form, auth flow, logout, redirect
- `tests/e2e/dashboard/dashboard.spec.ts` — Widget grid, drag handles, JS errors
- `tests/e2e/systems/systems-list.spec.ts` — Systems table, filters, badges

**Rationale:** These three flows cover the auth gate and the two most used features.
Running the full suite in three browsers would be impractical in a dev environment.

## How to Run

### Full suite (Chromium only)

```bash
cd frontend
npx playwright test
```

### Specific browser

```bash
# Firefox only
npx playwright test --project=firefox

# WebKit only
npx playwright test --project=webkit

# All browsers (cross-browser scope only for firefox/webkit)
npx playwright test
```

### Specific test file in specific browser

```bash
npx playwright test tests/e2e/auth/login.spec.ts --project=firefox
```

### UI mode (interactive)

```bash
npx playwright test --ui
```

## Prerequisites

1. Backend running on `http://127.0.0.1:8000`
2. Frontend dev server running on `http://localhost:3000` (auto-started by Playwright config)
3. Browser binaries installed: `npx playwright install`

## Expected Results

All tests in the smoke scope must pass in Chromium, Firefox, and WebKit before a
release is considered cross-browser verified.

The full suite (Chromium only) must pass for feature-level verification.
