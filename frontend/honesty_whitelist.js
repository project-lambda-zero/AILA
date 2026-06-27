/**
 * Frontend Honesty Audit Whitelist
 *
 * Central registry for accepted rule suppressions in frontend source files.
 *
 * Format: [filename_suffix, rule_id, detail]
 *   - filename_suffix : matches the END of the file path (forward slashes; cross-platform)
 *   - rule_id         : the honesty-audit rule id (e.g., "as_any", "console_statement")
 *   - detail          : human-readable justification (must be non-empty)
 *
 * Validation: every entry must be exactly [string, string, string].
 *
 * Maintenance:
 *   To suppress a finding: append a tuple here with a meaningful justification.
 *   To remove a suppression: delete the entry and fix the underlying code.
 *   Do NOT add inline suppression comments in source -- use this registry.
 */

function validate(entries) {
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (!Array.isArray(e) || e.length !== 3) {
      throw new Error(
        `HONESTY_WHITELIST[${i}] must be a 3-element array, got: ${JSON.stringify(e)}`
      );
    }
    if (!e.every((s) => typeof s === "string" && s.length > 0)) {
      throw new Error(
        `HONESTY_WHITELIST[${i}] all elements must be non-empty strings, got: ${JSON.stringify(e)}`
      );
    }
  }
  return entries;
}

export const HONESTY_WHITELIST = validate([
  // ---------------------------------------------------------------------------
  // console_statement -- intentional production console usage
  // ---------------------------------------------------------------------------

  [
    "src/main.tsx",
    "console_statement",
    "App bootstrap -- console.error used for React error boundary reporting before structured logger is available at this layer",
  ],
  [
    "src/app/ErrorBoundary.tsx",
    "console_statement",
    "Error boundary -- console.error logs uncaught React tree errors; no structured logger available at this layer",
  ],
  [
    "src/app/router.tsx",
    "console_statement",
    "Router lazy-import error logging; wrapped in dev-mode guard for chunk load failures",
  ],
  [
    "src/app/screens/DocsPage.tsx",
    "console_statement",
    "DocsPage is a developer utility screen; console usage is intentional for debug output to devtools",
  ],
  [
    "src/app/screens/ServerErrorPage.tsx",
    "console_statement",
    "Error screen -- logs raw error details to console for developer debugging; users only see the UI message",
  ],
  [
    "src/lib/apiErrorHandler.ts",
    "console_statement",
    "API error handler -- console.error used for unexpected errors before structured logger hooks are wired at this layer",
  ],
  [
    "src/platform/features/dashboard/widgetRegistry.ts",
    "console_statement",
    "Widget registry -- console.warn fires on duplicate widget registration; intentional developer-facing guard",
  ],

  // ---------------------------------------------------------------------------
  // direct_env_access -- import.meta.env.DEV at application entry points
  // ---------------------------------------------------------------------------

  [
    "src/app/router.tsx",
    "direct_env_access",
    "import.meta.env.DEV is a Vite build-time boolean constant (tree-shaken in production), not a runtime env read. Used at router entry to conditionally include dev-only test routes that are never bundled into production builds.",
  ],

  // ---------------------------------------------------------------------------
  // theme_hardcode -- hex color values in TSX files that cannot use CSS variables
  // ---------------------------------------------------------------------------

  [
    "src/components/aila/AilaBadge.tsx",
    "theme_hardcode",
    "AilaBadge uses fixed brand gradient colors that are intentionally not part of the themeable token system",
  ],
  [
    "src/app/screens/LoginParticles.tsx",
    "theme_hardcode",
    "Particle system requires concrete hex values for tsParticles config object; CSS variable strings cannot be passed to the tsParticles color API",
  ],
  [
    "src/platform/features/dashboard/DashboardGrid.tsx",
    "theme_hardcode",
    "React-grid-layout resize handle requires inline hex via style prop; the library callback does not support CSS variable resolution",
  ],
  [
    "src/platform/features/settings/SettingsPage.tsx",
    "theme_hardcode",
    "SettingsPage renders live theme preview swatches for all 12 AILA themes. Each swatch must display its theme's exact brand colors regardless of the currently active theme, making CSS variable tokens incorrect here -- they would resolve to the active theme, not the previewed one.",
  ],
  [
    "src/app/screens/ForbiddenPage.tsx",
    "theme_hardcode",
    "ForbiddenPage inline CSS block uses #fbbf24 (Tailwind amber-400) for a decorative warning accent. Should be migrated to var(--color-warning) once that token is defined in globals.css.",
  ],
  [
    "src/app/screens/ServerErrorPage.tsx",
    "theme_hardcode",
    "ServerErrorPage uses #ef4444 as fallback inside var(--color-critical, #ef4444) -- the hex is a CSS fallback value, not a primary color assignment. The var() form is the canonical reference.",
  ],
  [
    "src/app/screens/LoginPage.tsx",
    "theme_hardcode",
    "LoginPage uses #000 as fallback inside var(--primary-foreground, #000) -- CSS fallback value, not a primary assignment.",
  ],
  [
    "src/platform/features/systems/ConnectivityBadge.tsx",
    "theme_hardcode",
    "ConnectivityBadge uses #97dbbe as fallback inside var(--color-connectivity-online, #97dbbe) -- CSS fallback value only; the var() token is the canonical reference.",
  ],
  [
    "src/components/ui/input.tsx",
    "theme_hardcode",
    "shadcn/ui input uses dark: Tailwind modifier with bracket hex values. These are Part 13 (Phase 183) violations -- dark: classes need removal. Tracked in phase 183-13.",
  ],
  [
    "src/components/ui/textarea.tsx",
    "theme_hardcode",
    "shadcn/ui textarea uses dark: Tailwind modifier with bracket hex values. Part 13 (Phase 183) violation -- tracked for dark: cleanup in phase 183-13.",
  ],

  // ---------------------------------------------------------------------------
  // double_cast -- `as unknown as` patterns
  // ---------------------------------------------------------------------------

  [
    "src/platform/api/http.ts",
    "double_cast",
    "BodyInit cast from unknown: fetch() body accepts BodyInit but the JSON-serialized result type is string | ArrayBuffer | etc. The cast is sound because the caller controls the value. Narrowing to a specific union is not feasible without re-typing the entire fetch wrapper.",
  ],
  [
    "src/platform/features/dashboard/widgets/TrendWidget.tsx",
    "double_cast",
    "Recharts data prop is typed Record<string,unknown>[] but the backend returns a typed schema. The double-cast bridges the library's untyped prop with the typed response. Alternative: wrap Recharts with a typed adapter component.",
  ],
  [
    "src/platform/features/radar/RadarNode.tsx",
    "double_cast",
    "ReactFlow node data prop is typed as unknown by the library; casting to RadarNodeData is the standard ReactFlow pattern when using custom node types without re-typing the entire graph.",
  ],

  // ---------------------------------------------------------------------------
  // missing_response_type -- authorizedRequestJson without <T>
  // ---------------------------------------------------------------------------

  [
    "src/components/shell/NotificationBell.tsx",
    "missing_response_type",
    "POST /notifications/{id}/read and /notifications/read-all return no meaningful response body (204-equivalent). Adding <void> or <unknown> would be misleading about the intended contract. Should use a typed void response model once the backend defines one.",
  ],

  // ---------------------------------------------------------------------------
  // theme_hardcode -- viz components that pass colors to canvas/library APIs
  // ---------------------------------------------------------------------------

  [
    "src/platform/features/viz/GeographicMap.tsx",
    "theme_hardcode",
    "Leaflet marker icons are rendered on an HTML canvas; CSS custom properties are not resolved in canvas paint operations. SEVERITY_HEX provides fallback hex values that match the --color-* tokens. The comment in source documents this constraint explicitly.",
  ],
  [
    "src/platform/features/viz/SystemHeatmap.tsx",
    "theme_hardcode",
    "SystemHeatmap passes color strings to a backgroundColor inline style that drives a computed opacity matrix. CSS var() strings are not valid in this position because the value is manipulated arithmetically (opacity blending). Hex values mirror the --color-* token values documented in the inline comments.",
  ],

  // ---------------------------------------------------------------------------
  // todo_comment -- tracked aspirational comments
  // (none currently -- add entries with linked issue reference in detail when needed)
  // ---------------------------------------------------------------------------
]);
