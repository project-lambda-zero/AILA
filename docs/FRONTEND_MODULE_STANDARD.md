# Frontend Module Standard

This document defines the frontend architecture standard for AILA's browser UI.

It exists to keep the frontend:
- modular
- cohesive
- truthful
- compatible with the permanent FastAPI backend boundary

## Core Principle

**Platform owns chrome and composition. Modules own contributions.**

Platform owns:
- header
- footer
- sidebar renderer
- auth/session boundary
- route host
- page frame
- shared loading/error/retry primitives
- shared API and SSE client infrastructure

Modules own:
- page content
- route declarations
- sidebar metadata
- dashboard/detail panels
- query and mutation hooks for their own public API

Module developers should not need to edit central frontend files after the platform shell exists.

## Non-Negotiable Rules

1. FastAPI stays. The frontend consumes existing HTTP and SSE endpoints.
2. The frontend never talks to the database, storage internals, or local artifact paths directly.
3. The frontend never infers success, progress, or availability that the backend did not confirm.
4. Module frontend code must live inside the module directory.
5. Shared shell/layout behavior belongs to the platform frontend layer, not to modules.

## Target Layout

```text
frontend/
  src/
    app/
      shell/
      router/
      auth/
      layout/
    platform/
      api/
      sse/
      ui/
      extension-registry/

src/aila/modules/<module_id>/
  frontend/
    spec.ts
    nav.ts
    routes.tsx
    queries.ts
    mutations.ts
    panels.tsx
    widgets.tsx
    screens/
      ...
    components/
      ...
    types.ts
```

Notes:
- `frontend/` is the app shell and platform frontend infrastructure.
- `src/aila/modules/<module_id>/frontend/` is the only place a module developer should need to touch for frontend contributions.

## Required Module Frontend Files

Every module that contributes frontend UI must provide:

- `frontend/spec.ts`
- `frontend/routes.tsx`
- `frontend/nav.ts`

Strongly expected for non-trivial modules:

- `frontend/queries.ts`
- `frontend/mutations.ts`
- `frontend/panels.tsx`
- `frontend/types.ts`

Optional:

- `frontend/widgets.tsx`
- `frontend/screens/*`
- `frontend/components/*`

## ModuleFrontendSpec

Each module exports one explicit manifest. Platform does not guess from file names or component names.

Example shape:

```ts
export interface ModuleFrontendSpec {
  moduleId: string
  nav?: NavContribution[]
  routes?: RouteContribution[]
  panels?: PanelContribution[]
  widgets?: WidgetContribution[]
}
```

Example:

```ts
import { nav } from "./nav"
import { routes } from "./routes"
import { panels } from "./panels"

export const frontendSpec = {
  moduleId: "vulnerability",
  nav,
  routes,
  panels,
} satisfies ModuleFrontendSpec
```

## Route Standard

Modules may expose multiple pages. Platform understands them only through explicit route entries.

Example:

```tsx
export const routes = [
  {
    id: "vulnerability.findings",
    path: "/vulnerability/findings",
    page: FindingsListPage,
    title: "Findings",
    nav: true,
    slot: "page.full",
  },
  {
    id: "vulnerability.finding-detail",
    path: "/vulnerability/findings/:findingId",
    page: FindingDetailPage,
    title: "Finding Detail",
    nav: false,
    slot: "page.full",
  },
  {
    id: "vulnerability.reports",
    path: "/vulnerability/reports",
    page: ReportsPage,
    title: "Reports",
    nav: true,
    slot: "page.full",
  },
]
```

Rules:
- every route needs a stable `id`
- every route needs a stable `path`
- detail/action routes usually use `nav: false`
- platform mounts routes from manifests; modules do not edit central route tables

## Navigation Standard

Sidebar entries are metadata, not UI ownership.

Example:

```ts
export const nav = [
  {
    id: "vulnerability.findings-nav",
    slot: "sidebar.main",
    label: "Findings",
    to: "/vulnerability/findings",
    order: 20,
  },
  {
    id: "vulnerability.reports-nav",
    slot: "sidebar.main",
    label: "Reports",
    to: "/vulnerability/reports",
    order: 30,
  },
]
```

Rules:
- platform renders the sidebar
- modules only contribute nav items
- modules do not render or replace sidebar UI

## Extension Slots

Platform provides a fixed set of extension points. Modules may contribute only to declared slots.

Initial slots:

- `sidebar.main`
- `dashboard.primary`
- `system.detail`
- `task.detail`
- `finding.detail`
- `report.detail`
- `page.full`

Rules:
- modules may contribute content to slots
- modules may not invent new slots on their own
- adding a new slot is platform work

## API Consumption Rules

Frontend module code may consume only:
- platform REST endpoints
- module-owned REST endpoints
- platform SSE endpoints
- module-owned SSE endpoints

Frontend module code must not consume:
- raw DB models
- Python implementation details
- CLI payload shapes
- local filesystem paths
- storage-layer data contracts that are not part of the HTTP surface

## Truthfulness Rules

The frontend must follow the same honesty rules as the backend:

- no fake progress
- no fake success state
- no invented rows or counts
- no silent fallback from live state to stale assumptions
- no hidden re-analysis on read views

If the backend cannot provide what the UI needs:
- show an explicit unavailable/error state
- record the backend gap separately
- do not patch around it with guessed frontend behavior

## Query and Mutation Rules

Module screens must not call raw `fetch()` directly from page components.

Use the module boundary:
- `queries.ts` for reads
- `mutations.ts` for writes

Good:

```ts
// frontend/queries.ts
export function useFindingsList(params: FindingsListParams) {
  return useQuery({
    queryKey: ["vulnerability", "findings", params],
    queryFn: () => client.vulnerability.listFindings(params),
  })
}
```

Bad:

```ts
// inside page component
const data = await fetch("/vulnerability/findings")
```

## Import Boundary Rules

Allowed imports from a module frontend file:
- platform frontend infrastructure
- shared UI primitives
- generated or shared API client types
- files inside the same module's `frontend/`

Forbidden imports:
- another module's `frontend/`
- another module's backend internals
- `src/aila/storage/*`
- `src/aila/modules/<other_module>/*`
- central app route definitions
- central sidebar definitions

Short version:

**Modules may contribute to the shell. They may not rewire the shell.**

## Platform Responsibilities

The platform frontend layer must provide:
- module spec loader
- route registry builder
- nav registry builder
- slot renderer
- auth/session provider
- API client provider
- SSE client helpers
- page frame and shell layout
- standardized loading/error/empty/unavailable components

Without this infrastructure, module authors will be forced back into central edits. That is a platform failure, not a module failure.

## Module Developer Workflow

To add a new frontend page for an existing module:

1. Add a screen component under `src/aila/modules/<module_id>/frontend/screens/`
2. Add a route entry in `frontend/routes.tsx`
3. Add a nav entry in `frontend/nav.ts` if the page belongs in the sidebar
4. Add query/mutation hooks in `frontend/queries.ts` or `frontend/mutations.ts`
5. Export everything through `frontend/spec.ts`

No central route table edits.
No central sidebar config edits.
No shell edits.

## Worked Example

Example `src/aila/modules/vulnerability/frontend/spec.ts`:

```ts
import { nav } from "./nav"
import { panels } from "./panels"
import { routes } from "./routes"

export const frontendSpec = {
  moduleId: "vulnerability",
  nav,
  routes,
  panels,
} satisfies ModuleFrontendSpec
```

Example `src/aila/modules/vulnerability/frontend/panels.tsx`:

```tsx
export const panels = [
  {
    id: "vulnerability.system-summary",
    slot: "system.detail",
    order: 20,
    render: VulnerabilitySystemPanel,
  },
  {
    id: "vulnerability.report-summary",
    slot: "report.detail",
    order: 10,
    render: VulnerabilityReportPanel,
  },
]
```

Example `src/aila/modules/vulnerability/frontend/nav.ts`:

```ts
export const nav = [
  {
    id: "vulnerability.findings",
    slot: "sidebar.main",
    label: "Findings",
    to: "/vulnerability/findings",
    order: 20,
  },
]
```

## Frontend-Only Phase Rule

If a milestone or phase is declared frontend-only:
- no Python file edits
- no backend route additions
- no backend schema rewrites

Any missing endpoint or unusable contract becomes a separate backend follow-up.

## UI Component Standard

**Platform owns the design system. Modules consume it — they do not extend or replace it.**

### Required: Use PatternFly + Platform CSS

Module screens **must** build their UI from:

1. **PatternFly v6 components** — `@patternfly/react-core`, `@patternfly/react-icons`, `@patternfly/react-table`
2. **Platform utility classes** — `.button`, `.data-table`, `.metric-card`, `.page-frame`, `.banner`, `.badge--*`, `.field`, `.stack`, `.metric-grid`, `.table-card`, `.callout`, `.pill`, `.code-block`, etc.
3. **Platform CSS custom properties** — `--accent`, `--critical`, `--high`, `--medium`, `--healthy`, `--canvas`, `--panel`, `--border`, `--text-primary`, `--text-secondary`, etc.

### Forbidden

Module developers must **not**:

- Add a `frontend/styles.css` file to apply cosmetic CSS that duplicates or overrides platform styles
- Hardcode colors, font sizes, spacing, or border-radius values inline or in local stylesheets
- Override PatternFly CSS variables (e.g. `--pf-v6-*`) inside module files
- Import a third-party UI library (`chakra-ui`, `shadcn`, `mantine`, etc.)
- Create custom layout grids or shell structures that conflict with `PageFrame`

### Allowed Exception: Complex Data Visualizations

If a module requires a genuinely complex, custom data display that cannot be composed from PatternFly + platform classes — such as:
- An interactive graph renderer (D3, Cytoscape, WebGL)
- A custom timeline or Gantt chart
- A domain-specific canvas visualization

…then a scoped `frontend/styles.css` limited to that visualization component is acceptable. It must:
- Use `--pf-v6-*` or platform CSS vars wherever possible for colors/spacing
- Be scoped to a unique wrapper class (e.g. `.vulnerability-graph { … }`)
- Not override any global or PatternFly class names

### Correct Pattern

```tsx
// ✓ Good — uses PF + platform classes
import { Card, CardBody, Label } from "@patternfly/react-core";

export function FindingCard({ finding }: { finding: VulnerabilityFinding }) {
  return (
    <Card>
      <CardBody>
        <span className={`badge badge--${finding.severity.toLowerCase()}`}>
          {finding.severity}
        </span>
        <p className="text-muted">{finding.description}</p>
      </CardBody>
    </Card>
  );
}
```

```tsx
// ✗ Bad — custom CSS, hardcoded colors, invented layout
import "./custom-findings.css"; // ← forbidden
export function FindingCard({ finding }) {
  return (
    <div style={{ background: "#1a1e2c", padding: "16px", borderRadius: "8px" }}>
      <span style={{ color: "#ff0000" }}>{finding.severity}</span>
    </div>
  );
}
```

### Platform CSS Reference

The platform CSS lives at `frontend/src/platform/ui/styles.css`. Do not import it in module code — it is globally applied. Use its class names directly.

Key utility classes available to all modules:

| Class | Purpose |
|-------|---------|
| `.button`, `.button--secondary`, `.button--danger` | Buttons |
| `.data-table` | Sortable/filterable tables |
| `.metric-card` | KPI stat card |
| `.table-card` | Card wrapping a table |
| `.badge--critical/high/medium/low/unknown` | Severity badges |
| `.banner--warning/danger/success` | Inline alert banners |
| `.field`, `.field__input` | Form fields |
| `.page-frame` | Page content wrapper (use `PageFrame` component instead) |
| `.code-block`, `.code-inline` | Monospace display |
| `.stack`, `.stack--tight` | Vertical flex stacks |
| `.metric-grid` | Auto-fit metric card grid |
| `.empty-state` | Empty/no-data state |
| `.text-muted`, `.text-link` | Typographic utilities |

## Anti-Patterns

- module-owned full app layouts
- modules editing central route files
- modules editing central sidebar files
- pages calling raw fetch directly
- frontend using raw DB/storage field names as public UI contracts
- module frontend importing another module's frontend code
- UI inventing live state because the backend is inconvenient
- **module-level `styles.css` for cosmetic overrides** (hardcoded colors, spacing, typography)
- **reinventing platform classes** (e.g. custom status badges instead of `.badge--*`, custom cards instead of `Card` from PatternFly)
- **importing third-party UI libraries** not already in the platform bundle
- **overriding `--pf-v6-*` CSS variables** from within a module file

## One-Sentence Rule

**Platform owns the frame; modules declare and own their contributions.**
