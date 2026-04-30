# AILA Frontend Test Inventory

**Phase origin:** 150 (Testing & Verification)
**Last refreshed:** 2026-04-16
**Status:** Repository inventory refreshed against the current tree. Historical
coverage numbers from Phase 150 are kept below only where explicitly labeled as
historical.

Current caveats:
- `frontend/tests/e2e/ux/onboarding.spec.ts` is now a legacy spec. The current
  shell removed the first-run onboarding wizard and routes users to the Docs
  tab for guidance.
- The notification bell is covered as a header/dropdown surface. The current
  shell does not ship a dedicated `/notifications` inbox page.

---

## 1. E2E Inventory

All Playwright specs live under `frontend/tests/e2e/`. Auth helper:
`helpers/auth.ts`.

| Directory | Spec Files | Key Coverage |
|-----------|------------|--------------|
| `176a/` | 8 | Shell regressions: docs tab, sidebar, redirects, row click behavior, reports, error envelope, status badges |
| `a11y/` | 1 | WCAG 2.1 AA axe-core audit |
| `admin/` | 1 | Audit logs, API keys, platform config, system health |
| `auth/` | 1 | Login form, auth flow, invalid creds, logout, protected route redirect |
| `dashboard/` | 1 | Widget grid, JS errors, drag handles, header nav |
| `executive/` | 4 | Compliance evidence, risk PDF, SbD hash, scheduled report flows |
| `findings/` | 4 | Findings table, kanban, bulk actions, finding detail |
| `notifications/` | 2 | Bell icon, dropdown, SSE endpoint. No standalone inbox route in current shell |
| `radar/` | 1 | Radar page topology flow |
| `sbd-nfr/` | 2 | Assessments list and report preview |
| `systems/` | 3 | Systems list, detail, CSV import |
| `ux/` | 4 | Command palette, offline banner, responsive empty states. Includes one legacy onboarding spec |
| `viz/` | 1 | Visualization page and export surfaces |

**Repository inventory:** 33 `*.spec.ts` files under `frontend/tests/e2e/`.

The suite is designed around a real backend. Whether every spec currently
passes depends on the live backend and the status of legacy specs such as
`ux/onboarding.spec.ts`.

---

## 2. Vitest Inventory

All Vitest files live under `frontend/src/`.

| Location | Files | Coverage Focus |
|----------|-------|----------------|
| `src/app/__tests__/` | 6 | Router structure, docs page, sidebar, providers, error boundary |
| `src/components/aila/__tests__/` | 3 | Badge tokens, status rendering, table behavior |
| `src/components/filters/__tests__/` | 1 | JQL filter bar interactions |
| `src/hooks/` | 6 | Mobile breakpoint, online status, reduced motion, search history, SSE hook behavior |
| `src/lib/__tests__/` | 4 | API/data/error envelopes, SSE client parsing |
| `src/platform/features/admin/__tests__/` | 6 | Audit detail, OIDC providers, teams, health, LLM log |
| `src/platform/features/chat/__tests__/` | 1 | Session/thread UI behavior |
| `src/platform/features/radar/` | 1 | Topology helpers |
| `src/platform/features/tasks/__tests__/` | 1 | Task list rendering |
| `src/platform/features/viz/` | 1 | Chart export behavior |
| `src/test/` | 1 | Render harness smoke test |

**Repository inventory:** 31 `*.test.ts` / `*.test.tsx` files under
`frontend/src/`.

---

## 3. Historical Coverage Snapshot (Phase 150)

These numbers are the original Phase 150 coverage snapshot. They were measured
on a much smaller subset of the current frontend tree: hooks,
`topologyUtils.ts`, and `useChartExport.ts`. They should not be read as
current full-frontend coverage.

| Metric | Result | Threshold |
|--------|--------|-----------|
| Statements | 94.57% | 80% |
| Branches | 83.67% | 70% |
| Functions | 100% | 80% |
| Lines | 96.01% | 80% |

---

## 4. Accessibility Snapshot

The original Phase 150 accessibility pass targeted these routes:

| Page | Notes |
|------|-------|
| `/login` | Public login page |
| `/` | Dashboard shell |
| `/systems` | Systems data table |
| `/vulnerability/findings` | Complex findings table |
| `/assessments` | SbD workflow surface |
| `/radar` | ReactFlow-based graph, with targeted axe exceptions |
| `/admin/audit` | Admin audit view |

ReactFlow-generated SVG still requires targeted axe exceptions for
`scrollable-region-focusable` and `aria-allowed-attr`.

---

## 5. How To Run

### Unit tests

```bash
cd frontend
npm run test
npm run test:coverage
```

### E2E tests

```bash
cd frontend
npm run test:e2e
npx playwright test --project=firefox
npx playwright test --project=webkit
npx playwright test tests/e2e/a11y/
```

### Storybook visual regression

```bash
cd frontend
npm run storybook
npm run test:storybook:baseline
npm run test-storybook
```

---

## 6. Known Limitations

1. `useSSE.ts` contains a live streaming loop that is better covered by E2E and
   live SSE exercise than by pure unit tests.
2. `tests/e2e/ux/onboarding.spec.ts` is legacy and no longer matches the
   shipped shell.
3. The notification bell and unread count are implemented, but the current
   shell does not route `/notifications` to a dedicated inbox page.
4. E2E reliability still depends on a live backend on `http://127.0.0.1:8000`.
