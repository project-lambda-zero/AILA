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

## Workspace Package Requirements

The frontend is a pnpm workspace. Every module's `frontend/` directory is its own workspace package consumed by `@aila/shell` via `workspace:*`.

Current module frontend packages: `@aila/hello-world-frontend`, `@aila/vulnerability-frontend`, `@aila/forensics-frontend`, `@aila/vr-frontend`.

### Required workspace files

Every module's frontend directory MUST contain:

- `package.json` — name `@aila/<module>-frontend` (kebab-case), private, `main: "./spec.ts"`
- `tsconfig.json` — extends `@aila/typescript-config/react-module`

Reference template: `src/aila/modules/hello_world/frontend/`. The shell registers each module by package-name import in `frontend/src/platform/extension-registry/loadModuleSpecs.ts`.

### Required source files

Every module that contributes frontend UI must provide:

- `frontend/spec.ts` — exports `frontendSpec: ModuleFrontendSpec`
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

### Dependency declaration

Every bare import in a module's source MUST be declared in that module's `package.json`:

| Import category                                                   | Section in `package.json` | Version reference                |
|-------------------------------------------------------------------|---------------------------|----------------------------------|
| Shell-owned framework / router / data layer / design system       | `peerDependencies`        | `catalog:<group>`                |
| Module-specific runtime dep (e.g., `@dnd-kit/core`, `@xyflow/react`) | `dependencies`         | `catalog:<group>` (preferred) or literal if not shared |
| Test / storybook tooling                                          | `devDependencies`         | `catalog:<group>`                |

pnpm strict mode rejects undeclared bare imports at install time, so `pnpm install` fails any module that uses a package it did not declare. Cross-module imports (`@aila/<other>-frontend`) are forbidden by convention; reviewers must reject them.

`pnpm-workspace.yaml` defines the catalog groups currently in use: `react19`, `router`, `vite`, `tailwind`, `query`, `ui`, `testing`, `storybook`, `types`, `maps`, `data`, `dnd`, `flow`, plus the top-level `catalog:` slot (TypeScript). Shared versions live there; modules and the shell reference them by `catalog:<group>` so a single edit propagates.

See `.claude/rules/frontend-workspace.md` for the full ruleset.

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

### Required: Use the AILA design system

Module screens MUST build their UI from:

1. **AILA shared components** at `frontend/src/components/aila/` — re-exported by the shell. The canonical surface is `AilaCard`, `AilaBadge` (severity prop: `critical | high | medium | low | informational | unknown`), `AilaTable`, `EmptyState`, `KpiTile`, and `AilaChart`. Modules consume these as React components, NOT as CSS utility classes.
2. **shadcn/ui primitives** — re-exported under `@platform/ui/*` when a module needs a primitive AILA components do not yet wrap (Dialog, Popover, DropdownMenu, ...).
3. **AILA design tokens** — CSS variables under the `--color-*` namespace declared in `frontend/src/styles/globals.css`. Module styles MUST reference tokens (`color: var(--color-mint)`), never literal hex colours.

No legacy CSS framework is installed. The Tailwind layer is v4; module classes must be reachable from the shell's `@source` directives (see "Tailwind v4 source discovery" below).

### Forbidden

Module developers must **not**:

- Add a `frontend/styles.css` file to apply cosmetic CSS that duplicates or overrides platform styles
- Hardcode colors, font sizes, spacing, or border-radius values inline or in local stylesheets
- Override AILA design tokens (e.g. `--color-*`) inside module files
- Import a third-party UI library (`chakra-ui`, `mantine`, etc.) outside the shell-curated shadcn re-exports
- Create custom layout grids or shell structures that conflict with `PageFrame`

### Allowed Exception: Complex Data Visualizations

If a module requires a genuinely complex, custom data display that cannot be composed from AILA components + shadcn primitives — such as:
- An interactive graph renderer (D3, Cytoscape, WebGL)
- A custom timeline or Gantt chart
- A domain-specific canvas visualization

…then a scoped `frontend/styles.css` limited to that visualization component is acceptable. It must:
- Use `--color-*` design tokens wherever possible for colors/spacing
- Be scoped to a unique wrapper class (e.g. `.vulnerability-graph { … }`)
- Not override any global AILA component class names

### Correct Pattern

```tsx
// ✓ Good — uses AILA components + design tokens
import { AilaCard, AilaBadge } from "@/components/aila";

export function FindingCard({ finding }: { finding: VulnerabilityFinding }) {
  return (
    <AilaCard>
      <AilaBadge severity={finding.severity.toLowerCase()}>
        {finding.severity}
      </AilaBadge>
      <p style={{ color: "var(--color-text-muted)" }}>{finding.description}</p>
    </AilaCard>
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

### Platform Design System Reference

Global styles and Tailwind directives live at `frontend/src/styles/globals.css`. Modules do not import it; the shell loads it at boot.

Key components available to all modules:

| Component | Purpose | Key props |
|---|---|---|
| `AilaCard` | Bordered panel with optional header / footer | `header`, `footer`, `tone` |
| `AilaBadge` | Severity / state pill | `severity` (critical/high/medium/low/informational/unknown), `children` |
| `AilaTable` | Striped data table with sortable headers | `columns`, `rows`, `onSort` |
| `EmptyState` | Centred empty-list placeholder | `title`, `body`, `action` |
| `KpiTile` | Headline metric tile | `label`, `value`, `delta` |
| `AilaChart` | Recharts wrapper with CSS-var → hex resolution | uses `useThemeChartColors()` |

### Tailwind v4 Content Scan

Tailwind v4 generates CSS rules ONLY for classes it finds during its content scan. The scan starts at the directory containing the entry CSS file (`frontend/src/styles/globals.css` → scans `frontend/src/` and below) and ignores `node_modules/` by default.

**Module frontends live OUTSIDE `frontend/src/`** — they're at `src/aila/modules/<name>/frontend/` and reached via pnpm workspace symlinks in `node_modules/@aila/<name>-frontend/`. Tailwind does NOT scan them by default.

If you forget the `@source` directive: any class you add in a module-side file that isn't ALSO used somewhere inside `frontend/src/` will have NO CSS rule generated. The element gets `class="bottom-6 right-6"` but no `bottom: 1.5rem` rule exists, so it falls back to flow position. Common symptom: `position: fixed` elements anchor to the wrong place.

**Fix when shipping a new module's frontend**:

Add one line per module to `frontend/src/styles/globals.css` (right after the `@import "tailwindcss";` block):

```css
@source "../../../src/aila/modules/<your_module>/frontend/**/*.{ts,tsx}";
```

Already wired for: `vr`, `vulnerability`, `forensics`, `hello_world`. If you copy `_template/` to start a new module, add the line at the same time.

Verify by curl on the running dev server: `curl http://localhost:3000/src/styles/globals.css | grep "\.your-new-class"` — if the rule exists, Tailwind is scanning correctly.

## Implementation Gotchas

These traps catch every contributor at least once. Read once, save a
debugging session later.

### `react-router`, not `react-router-dom`

React Router v7 unified the two packages. Every import in this codebase
resolves from `react-router`:

```ts
// CORRECT
import { Link, useNavigate } from "react-router";

// WRONG — package is not installed; tsc and pnpm both fail
import { Link, useNavigate } from "react-router-dom";
```

The catalog entry is `catalog:router`. Modules that route declare
`"react-router": "catalog:router"` in `peerDependencies`.

### Tailwind v4 arbitrary values do not generate CSS

`class="h-[720px] bg-[#131313]"` produces no CSS rules under Tailwind v4
— the scanner cannot see the values. The element renders at the default
height with the default background and silently loses the intent.

Use an inline `style` for one-off literal values, or add a token:

```tsx
// CORRECT
<div className="bg-surface" style={{ height: 720 }} />

// WRONG — both classes are dropped
<div className="h-[720px] bg-[#131313]" />
```

Arbitrary values that need to be reused belong in the design system,
not inline.

### Recharts `fill` / `stroke` do not resolve CSS `var(--…)`

An SVG `fill="var(--color-accent)"` does not resolve through CSS
variables — the chart renders empty (or with the SVG default colour).
Theme switches do not propagate either.

Resolve the variable in JS via `getComputedStyle` (the
`useThemeChartColors()` hook already does this) and pass the resolved
string:

```tsx
const colors = useThemeChartColors();
<Bar dataKey="count" fill={colors.accent} />
```

The hook re-reads on `data-theme` changes so charts stay in sync with
the active theme.

### pnpm strict mode rejects undeclared imports

Every bare import in a module's frontend MUST be declared in that
module's `package.json`. Adding `import { foo } from "some-pkg"` without
a matching entry in `dependencies`, `peerDependencies`, or
`devDependencies` fails `pnpm install` with
`ERR_PNPM_UNDECLARED_DEPENDENCY`. See the dep ownership matrix above.

---

## Anti-Patterns

- module-owned full app layouts
- modules editing central route files
- modules editing central sidebar files
- pages calling raw fetch directly
- frontend using raw DB/storage field names as public UI contracts
- module frontend importing another module's frontend code
- UI inventing live state because the backend is inconvenient
- **module-level `styles.css` for cosmetic overrides** (hardcoded colors, spacing, typography)
- **reinventing platform components** (e.g. custom status badges instead of `AilaBadge`, custom cards instead of `AilaCard`)
- **importing third-party UI libraries** not already in the platform bundle
- **overriding `--color-*` design tokens** from within a module file

## One-Sentence Rule

**Platform owns the frame; modules declare and own their contributions.**
