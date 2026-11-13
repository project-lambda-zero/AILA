# Frontend Module Standard

This document defines how AILA's browser UI is structured and how a module's surface is added to it.

The frontend is a single React SPA, `@aila/shell`, in `frontend/`. There are no per-module frontend packages: no module owns a `frontend/` directory, and modules contribute UI by adding entries to the shell's console navigation and page registry.

It exists to keep the frontend:
- cohesive
- truthful
- compatible with the permanent FastAPI backend boundary

## Core Principle

**The shell owns chrome, windows, and composition. A module surface is data plus page components registered inside the shell.**

The shell (`frontend/src/App.tsx`, `frontend/src/console/`) owns:
- the login gate and auth/session store (`frontend/src/api/auth.ts`)
- the left rail (`LeftRail.tsx`), chat console (`ChatConsole.tsx`), command palette, notifications, settings overlay
- the window host: open windows, focus, z-order, minimize dock, fullscreen
- page resolution (`resolvePage` in `frontend/src/console/pages/registry.tsx`)
- the wizard catalog (`frontend/src/console/wizards/registry.ts`) and the widget catalog (`frontend/src/console/widgets/catalog.tsx`)
- the API client, query hooks, and SSE client (`frontend/src/api/`)

A module's frontend surface consists of:
- a `ModuleDef` entry in `MODULES` (`frontend/src/console/nav.ts`)
- one page entry per rail page, either a declarative `PageConfig` (`frontend/src/console/pages/configs.ts`) or a bespoke component in `BESPOKE` (`frontend/src/console/pages/registry.tsx`)
- optional wizard entries (`frontend/src/console/wizards/registry.ts`)
- API hooks and types for its backend routes (`frontend/src/api/`)

## Non-Negotiable Rules

1. FastAPI stays. The frontend consumes existing HTTP and SSE endpoints.
2. The frontend never talks to the database, storage internals, or local artifact paths directly.
3. The frontend never infers success, progress, or availability that the backend did not confirm.
4. Module-specific page components live under `frontend/src/console/pages/<module>/` (for example `pages/forensics/`, `pages/vulnerability/`, `pages/malware/`).
5. Shared shell behavior (window chrome, rail, chat, wizards shell, widgets) is not forked per module.

## Layout

```text
frontend/
  package.json                # @aila/shell
  vite.config.ts
  tsconfig.json               # extends @aila/typescript-config
  .oxlintrc.json              # oxlint + tools/oxlint anti-slop rules
  src/
    main.tsx                  # QueryClientProvider + mount
    App.tsx                   # shell host: windows, rail, chat, routing of window keys
    theme.ts                  # theme registry (slug -> [data-theme] block)
    styles/globals.css        # design-system tokens, plain CSS
    api/                      # fetch client, auth, SSE, react-query hooks, response types
    console/
      nav.ts                  # MODULES, ADMIN_CATS, GOD_TIER_ADMIN_ITEMS
      contract.ts             # ModulePageProps and the other shell/panel prop contracts
      css.ts                  # css("a:b;c:d") -> React style object
      pages/
        registry.tsx          # PAGE_REGISTRY, BESPOKE pages, resolvePage()
        configs.ts            # PAGE_CONFIGS for declarative DataPage lists
        formSpecs.ts          # create/edit form field specs
        DataPage.tsx          # the generic list + detail + actions page
        data/                 # DataPage parts: RowTable, FilterBar, DetailPanel, useDataRows, types
        admin/ forensics/ malware/ vulnerability/ ...   # module- or area-specific pages
      wizards/                # WizardShell, registry.ts (WIZARDS), field helpers
      widgets/                # WidgetHost, catalog.tsx, layout.ts, one component per widget kind
      window/                 # ConsoleWindow primitive
    desktop/                  # decorative desktop background
packages/typescript-config/   # @aila/typescript-config: ./base, ./react-vite, ./react-module
```

The workspace members are listed in `pnpm-workspace.yaml`: `frontend`, `packages/*`, `tools/oxlint`.

## Stack

`frontend/package.json` runtime dependencies are `react`, `react-dom`, `@tanstack/react-query`, `zustand`, `monaco-editor`, and `@monaco-editor/react`. Styling is plain CSS custom properties in `frontend/src/styles/globals.css` plus inline styles built with `css()` from `frontend/src/console/css.ts`. There is no CSS framework, no client-side router, and no charting or drag-and-drop library; windows are managed by the shell host, not URL routes.

Shared versions are pinned through the pnpm catalogs in `pnpm-workspace.yaml` (`typescript`, `react19`, `vite`, `query`, `ui`, `lint`, `types`). `frontend/package.json` references them as `catalog:<name>`; never write literal versions for catalog-managed packages. Adding a dependency means adding it to a catalog and referencing it from `frontend/package.json`. Do not hand-edit `pnpm-lock.yaml`; run `pnpm install`.

## Page Model

A page is a window the shell opens. The window state (`WindowState` in `frontend/src/console/window/types.ts`) carries a `registryKey`, a `section`, and an optional `investigationId`. Page keys have the form `<moduleKey>:<section>`, for example `vr:targets`, `malware:observations`, `admin:users`. `openNamedPage` in `App.tsx` ignores a key that `resolvePage` cannot resolve.

A registered page is a `PageEntry`:

```ts
interface PageEntry {
  title: string;
  render: (p: ModulePageProps) => JSX.Element;
}
```

`ModulePageProps` (`frontend/src/console/contract.ts`) is what the shell supplies to every page: window chrome (`windowId`, `title`, `isFocused`, `onFocus`, `onBack`, `onMinimize`, `isFullscreen`, `onToggleFullscreen`), in-window sub-routing (`section`, `onNavigate`), the bound entity (`investigationId`), and `onOpenPage` to hand off to another registered window. A bespoke page spreads the chrome props into `<ConsoleWindow>` (`frontend/src/console/window/`); it does not draw its own title bar or window frame.

### Declarative pages (`DataPage`)

Most list pages need no component. Add a `PageConfig` to `PAGE_CONFIGS` in `frontend/src/console/pages/configs.ts`:

```ts
"vr:targets": {
  title: "vr \u00b7 targets",
  endpoint: "/vr/targets",
  columns: [c("display_name", "name"), c("kind"), c("status")],
  filters: [{ name: "status", label: "status", type: "select" }],
},
```

`registry.tsx` wraps every `PAGE_CONFIGS` entry in `<DataPage config configKey {...p} />` automatically. Create/edit forms come from `frontend/src/console/pages/formSpecs.ts`. Server-side pagination and filters are enabled per filter (`server: true`) where the backend route supports `?q=` style filtering.

### Bespoke pages

When a page needs behavior `DataPage` cannot express, add a component under `frontend/src/console/pages/<module>/`, load it lazily in `registry.tsx` (`lazy(() => import(...))`), and add it to `BESPOKE` under the same `<moduleKey>:<section>` key. A bespoke entry overrides a `PAGE_CONFIGS` entry with the same key (for example `vr:patterns`, which wraps `DataPage` with extra controls). `registry.tsx` wraps every entry in one shared `Suspense` boundary, so pages must not add their own page-level loading shell.

## Navigation

The left rail is generated from `MODULES` in `frontend/src/console/nav.ts`:

```ts
interface ModuleDef { id: string; label: string; noun: string; pages: PageDef[] }
interface PageDef   { id: string; label: string; href: string | null; group?: string }
```

A `PageDef.id` is the label with spaces replaced by `-` (helpers `page()` and `grouped()` build them), so the page labelled `fuzz campaigns` has id `fuzz-campaigns` and resolves to the registry key `vr:fuzz-campaigns`. `group` makes the rail render a separator before the first page of each contiguous group. Admin pages are listed in `ADMIN_CATS` and resolve under the `admin:` prefix; entries in `GOD_TIER_ADMIN_ITEMS` are hidden from non-god-tier admins in the rail and must also gate inside the page.

A rail entry with no registry entry is a dead link. Add the page entry in the same change as the nav entry.

## Adding a Module Surface

1. Ship the backend routes first (see `docs/MODULE_STANDARD.md`, Frontend Endpoint Standard).
2. Add response types and hooks under `frontend/src/api/` (for example `forensics.ts`, `malwareHooks.ts`, `vulnerability.ts`).
3. Add a `ModuleDef` to `MODULES` in `frontend/src/console/nav.ts`.
4. For each page: add a `PageConfig` to `configs.ts` (and a form spec in `formSpecs.ts` if rows are created or edited), or add a bespoke component and a `BESPOKE` entry in `registry.tsx`.
5. For guided flows, add a `WizardDef` to `WIZARDS` in `frontend/src/console/wizards/registry.ts` and render the flow inside `WizardShell`. Each wizard entry must open a surface that exists (`{ kind: "intake" }` or `{ kind: "page", moduleKey, section }`).
6. Run `pnpm --filter @aila/shell run type-check` and `pnpm --filter @aila/shell run lint`.

Frontend dependencies for a module go in `frontend/package.json` through a catalog entry. There is no per-module `package.json`.

## Widgets

A widget is a read-only live-state surface docked around the chat panel as a floating `ConsoleWindow`. Kinds are declared in `WIDGET_KINDS` (`frontend/src/console/widgets/types.ts`); `WIDGET_CATALOG` in `catalog.tsx` is keyed by `Record<WidgetKind, WidgetCatalogEntry>`, so adding a kind forces a catalog entry. The layout is persisted through `PUT /widgets/layout` and edited on the `admin:widget-layout` page. Widgets read their own data and render body content only; `WidgetHost` owns the chrome.

## API Consumption Rules

Frontend code may consume only:
- platform REST endpoints
- module-owned REST endpoints
- platform SSE endpoints
- module-owned SSE endpoints

Frontend code must not consume:
- raw DB models
- Python implementation details
- CLI payload shapes
- local filesystem paths
- storage-layer data contracts that are not part of the HTTP surface

The API base is derived from the page hostname on port 8000 (`API_BASE` in `frontend/src/api/client.ts`); requests carry a Bearer access token the auth store holds in memory. A 401 renews the token once through the refresh cookie (one refresh shared by concurrent requests) and retries the request; the user is signed out only when that renewal fails. A page load restores the session the same way. Module helpers that need the raw `Response` (downloads, SSE) call `authorizedFetch` to get the same handling.

## Truthfulness Rules

The frontend follows the same honesty rules as the backend:

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

Page components do not call `fetch()` directly. Reads and writes go through `frontend/src/api/`:
- `client.ts` (`apiFetch`, `apiFetchEnvelope`, `ApiError`) is the only place that talks to `fetch`
- react-query hooks (`hooks.ts`, `malwareHooks.ts`, and the per-area files) own query keys
- `mutations.ts` owns shared write helpers
- `sse.ts` and `liveEvents.tsx` own authenticated SSE streams (fetch-based, with backoff reconnect)

Good:

```ts
// frontend/src/api/hooks.ts
return useQuery({
  queryKey: ["vr", "investigations"],
  queryFn: () => /* apiFetch(...) */,
});
```

Bad:

```ts
// inside a page component
const data = await fetch("/vulnerability/findings")
```

## UI Component Standard

- Use the shell's primitives: `ConsoleWindow`, `DataPage` and its `data/` parts, `WizardShell`, the shared badges (`frontend/src/console/pages/badges.tsx`), and the toast helper (`frontend/src/console/toast.tsx`).
- Style with the design-system CSS custom properties from `frontend/src/styles/globals.css` (`var(--text-faint)`, `var(--font-mono)`, ...) and with `css()` inline style strings. Do not introduce a CSS framework or a second styling convention.
- SVG attributes (`fill`, `stroke`) in custom visualizations must not rely on `var(--...)` unless the specific attribute is verified to resolve it; read the theme tokens at runtime instead.
- Themes are slugs on `<html data-theme>` declared in `frontend/src/theme.ts` and styled in `globals.css`; add a theme in both places.
- JSX text children are verbatim. An escape such as `\u00b7` written as bare JSX text renders literally; use the glyph or a string literal `{"\u00b7"}`.

## Anti-Patterns

- editing `LeftRail.tsx` or `App.tsx` to special-case one module instead of adding data to `MODULES` / the registries
- a nav entry with no registry entry, or a wizard entry that opens nothing
- a bespoke page drawing its own window title bar instead of using `ConsoleWindow`
- raw `fetch()` in a page component
- optimistic UI that reports success before the backend confirms
- literal dependency versions in `frontend/package.json`
- importing from a lazily loaded page in `App.tsx` (pages are reached only through `resolvePage`)

## One-Sentence Rule

**The shell owns the window and composition; a module adds nav data, page entries, and API hooks, and every claim the UI makes comes from the backend.**
