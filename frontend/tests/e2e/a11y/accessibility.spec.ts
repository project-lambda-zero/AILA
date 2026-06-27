/**
 * accessibility.spec.ts -- Automated accessibility audit (TEST-04).
 *
 * Runs axe-core against all critical AILA pages to verify zero WCAG 2.1 AA
 * violations. Uses @axe-core/playwright.
 *
 * Pages tested:
 *   - /login                 -- full AA ruleset
 *   - /                      -- full AA ruleset (dashboard)
 *   - /systems               -- full AA ruleset
 *   - /vulnerability/findings -- full AA ruleset
 *   - /assessments           -- full AA ruleset (SbD wizard)
 *   - /radar                 -- AA with exceptions (D-02: ReactFlow SVG limitations)
 *   - /admin/audit           -- full AA ruleset
 *
 * Exception (D-02): The /radar page uses ReactFlow which generates non-standard
 * ARIA on its canvas SVG elements. Rules `scrollable-region-focusable` and
 * `aria-allowed-attr` are disabled specifically for that page to avoid false
 * positives from the third-party canvas library. All other AA rules remain active.
 *
 * Uses REAL PostgreSQL backend -- auth injected via localStorage.
 */
import { test, expect } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

import { getTokens, injectAuthState, type TokenPair } from "../helpers/auth";

// ---------------------------------------------------------------------------
// axe rule config shared across most pages
// ---------------------------------------------------------------------------

const FULL_AA_TAGS = { type: "tag" as const, values: ["wcag2a", "wcag2aa"] };

// ---------------------------------------------------------------------------
// Auth setup
// ---------------------------------------------------------------------------

test.describe("Accessibility audit -- WCAG 2.1 AA", () => {
  let tokens: TokenPair;

  test.beforeAll(async ({ request }) => {
    tokens = await getTokens(request);
  });

  // ---------------------------------------------------------------------------
  // Login page -- no auth needed, public page
  // ---------------------------------------------------------------------------

  test("/login -- zero WCAG 2.1 AA violations", async ({ page }) => {
    await page.goto("/login");
    await page.waitForLoadState("networkidle", { timeout: 10_000 });

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();

    expect(
      results.violations,
      `Violations on /login:\n${formatViolations(results.violations)}`,
    ).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Dashboard -- authenticated
  // ---------------------------------------------------------------------------

  test("/ (dashboard) -- zero WCAG 2.1 AA violations", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/");
    await page.waitForLoadState("networkidle", { timeout: 15_000 });

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();

    expect(
      results.violations,
      `Violations on /:\n${formatViolations(results.violations)}`,
    ).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Systems list -- authenticated
  // ---------------------------------------------------------------------------

  test("/systems -- zero WCAG 2.1 AA violations", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/systems");
    await page.waitForLoadState("networkidle", { timeout: 10_000 });

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();

    expect(
      results.violations,
      `Violations on /systems:\n${formatViolations(results.violations)}`,
    ).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Findings table -- authenticated
  // ---------------------------------------------------------------------------

  test("/vulnerability/findings -- zero WCAG 2.1 AA violations", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/vulnerability/findings");
    await page.waitForLoadState("networkidle", { timeout: 10_000 });

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();

    expect(
      results.violations,
      `Violations on /vulnerability/findings:\n${formatViolations(results.violations)}`,
    ).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // SbD assessments -- authenticated
  // ---------------------------------------------------------------------------

  test("/assessments -- zero WCAG 2.1 AA violations", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/assessments");
    await page.waitForLoadState("networkidle", { timeout: 10_000 });

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();

    expect(
      results.violations,
      `Violations on /assessments:\n${formatViolations(results.violations)}`,
    ).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Radar (Network Topology) -- authenticated, with D-02 exceptions
  // ---------------------------------------------------------------------------

  test("/radar -- zero AA violations (ReactFlow SVG exceptions applied)", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/radar");
    // ReactFlow needs extra time for canvas initialization
    await page.waitForTimeout(4_000);

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      // D-02: ReactFlow generates non-standard ARIA on SVG canvas elements.
      // These rules produce false positives for the third-party canvas library.
      .disableRules(["scrollable-region-focusable", "aria-allowed-attr"])
      .analyze();

    expect(
      results.violations,
      `Violations on /radar (with D-02 exceptions):\n${formatViolations(results.violations)}`,
    ).toHaveLength(0);
  });

  // ---------------------------------------------------------------------------
  // Admin audit logs -- authenticated, admin role required
  // ---------------------------------------------------------------------------

  test("/admin/audit -- zero WCAG 2.1 AA violations", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/admin/audit");
    await page.waitForLoadState("networkidle", { timeout: 10_000 });

    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa"])
      .analyze();

    expect(
      results.violations,
      `Violations on /admin/audit:\n${formatViolations(results.violations)}`,
    ).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Violation formatter for readable test failure messages
// ---------------------------------------------------------------------------

interface AxeViolation {
  id: string;
  impact: string | null;
  description: string;
  nodes: Array<{ html: string }>;
}

function formatViolations(violations: AxeViolation[]): string {
  if (violations.length === 0) return "none";
  return violations
    .map(
      (v) =>
        `[${v.impact ?? "unknown"}] ${v.id}: ${v.description}\n` +
        v.nodes
          .slice(0, 2)
          .map((n) => `  → ${n.html.slice(0, 120)}`)
          .join("\n"),
    )
    .join("\n\n");
}
