# Phase 176a Playwright Suite

End-to-end specs that gate the merge of Phase 176a (operator console runtime
fixes). One spec file per D-item group from
`.planning/phases/176-operator-console-completion/176a-CONTEXT.md`.

## Layout

```
tests/e2e/176a/
├── README.md                  ← you are here
├── helpers/
│   ├── fixtures.ts            ← Playwright `test.extend` with authedPage,
│   │                            seedTasks, seedReports, seedAssessments,
│   │                            namespacedTeardown
│   └── db-seed.ts             ← namespace allocation + REST seed helpers
├── __screenshots__/.gitkeep   ← screenshot output dir (full-page PNGs)
├── sidebar.spec.ts            ← D-01, D-02, D-27
├── docs-tab.spec.ts           ← D-03, D-33
├── row-click.spec.ts          ← D-04, D-14, D-32
├── status-badges.spec.ts      ← D-05, D-21, D-22
├── reports.spec.ts            ← D-07, D-08, D-13, D-16, D-17, D-18, D-28
├── sbd-redirect.spec.ts       ← D-09, D-19
├── error-envelope.spec.ts     ← D-10*, D-20, D-23, D-24, D-25, D-26, D-31
└── module-id.spec.ts          ← D-06, D-15
```

## Test isolation + teardown

Every test that mutates the backend uses a per-test namespace string of the
form

```
e2e_<sanitised_test_title>_<timestamp_ms>
```

obtained from `helpers/db-seed.ts::getNamespace(testInfo)`. All seeded
records carry the namespace as a literal substring of a name/title field
(e.g. `title="Report — e2e_reports_render_1734200000000"`). The
`namespacedTeardown(namespace)` fixture is invoked from `test.afterEach` and
deletes by prefix.

Rationale: the dev backend is shared across spec files when run in parallel.
A namespace prefix lets each test allocate, mutate and tear down its own
data without coordinating with other tests, and lets a partial run be
cleaned up afterwards by re-running teardown with the same prefix
(`teardownPrefix("e2e_")`).

### When the seeder cannot reach the backend

If the dev API is offline at fixture setup time, `seedTasks` /
`seedReports` raise a clear error. Tests that require real seeded data are
skipped via `test.skip()` rather than silently using fake data — see
`feedback_no_mock_data` (project rule).

### Forced-error interception

Specs that need to assert the error envelope contract use
`page.route(url, route => route.fulfill({ ... }))` with synthesised JSON
bodies. This tests the FRONTEND error pipeline, not a real backend bug, and
is explicitly permitted by gap-fix-03 #6.

## Running

The dev frontend listens on port 3000 (see `package.json` `dev` script
and `playwright.config.ts` `webServer.url`). Playwright will start it
automatically via `webServer.command = "npm run dev"`.

```
cd frontend
npx playwright test tests/e2e/176a/ --reporter=list
```

For a single spec:

```
npx playwright test tests/e2e/176a/sidebar.spec.ts --reporter=list
```

To enumerate without running:

```
npx playwright test tests/e2e/176a/ --list
```

## Acceptance criteria (D-30)

Every test asserts ALL THREE of:

1. **URL** — `await expect(page).toHaveURL(/expected/)`.
2. **Render** — at least one heading or region locator visible.
3. **No-error** — `Internal Server Error` literal absent; AppErrorBoundary
   fallback absent (unless the test is the crash-injection spec itself).

Screenshot-only tests are forbidden. A screenshot is captured **in addition
to** the three assertions, never as a substitute.

## CI

`.github/workflows/*.yml` (whichever invokes `playwright test` without a
path argument) automatically picks up `tests/e2e/176a/` because the
`playwright.config.ts` `testDir` value is `./tests/e2e`. No CI changes
required beyond the existing matrix.

## Maintenance notes

- The `/__test__/crash` route used by `error-envelope.spec.ts` is gated on
  `import.meta.env.DEV` in `frontend/src/app/router.tsx` — it is never
  registered in production bundles. Do not promote it to a non-DEV path.
- Status badge selectors target the `aila-badge-status-<status>` class
  applied by `AilaBadge`; that class is the canonical hook. If `data-status`
  is added in a later patch, both selectors continue to work.
- Hint strings in `error-envelope.spec.ts` are inlined from
  `src/aila/api/errors/hints.py` per gap-fix-03 #7. Update the spec when
  hints change.
