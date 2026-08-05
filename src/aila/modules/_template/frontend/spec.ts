import type { ModuleFrontendSpec } from "@platform/extension-registry/types";

/** Minimal ModuleFrontendSpec for the _template scaffold.
 *
 *  This is the smallest legal shape: a module id and no
 *  contributions. Copy this directory alongside the backend
 *  _template when starting a new module and:
 *
 *    1. Rename the package to `@aila/<module>-frontend` and
 *       change `moduleId` here to the backend module id.
 *    2. Add contributions to `nav`, `routes`, `panels`, and/or
 *       `widgets`. hello_world/frontend/spec.ts is the canonical
 *       minimum -- one NavContribution in slot "sidebar.main" plus
 *       one RouteContribution in slot "page.full" pointing at a
 *       lazy-imported page component.
 *    3. Add `@source "../../../src/aila/modules/<name>/frontend/**\/*.{ts,tsx}";`
 *       to frontend/src/styles/globals.css so Tailwind v4 scans
 *       module-side class names (see CLAUDE.md Common Mistake #15).
 *    4. Add `"@aila/<module>-frontend": "workspace:*"` to
 *       frontend/package.json (the shell) and run `pnpm install`.
 *
 *  The shell's `loadModuleFrontendSpecs` discovers every
 *  modules/*\/frontend/spec.ts via a Vite glob and unlike the
 *  backend loader does NOT skip underscore-prefixed directories --
 *  the scaffold IS discovered, contributes nothing, and is
 *  therefore inert until a copier fills in nav/routes.
 */
export const frontendSpec = {
  moduleId: "_template",
} satisfies ModuleFrontendSpec;
