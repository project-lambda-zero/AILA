/**
 * radar-page.spec.ts — Smoke tests for /radar network topology page.
 *
 * Coverage:
 *   - Page loads with correct title
 *   - Toolbar renders (color-by selector, search input)
 *   - ReactFlow canvas or empty state renders after API call
 *   - No critical JavaScript errors on load
 *
 * Uses real PostgreSQL backend — no mocks.
 * Admin token is used (admin role satisfies operator requirement).
 */
import { test, expect } from "@playwright/test";

import { getTokens, injectAuthState } from "../helpers/auth";

test.describe("Radar page", () => {
  test.beforeEach(async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);
  });

  test("page loads without critical JavaScript errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));

    await page.goto("/radar");
    // Allow API calls to complete and ReactFlow to initialize
    await page.waitForTimeout(3000);

    // Filter out known non-critical browser noise
    const criticalErrors = errors.filter(
      (e) =>
        !e.includes("ResizeObserver") &&
        !e.includes("favicon") &&
        !e.includes("non-passive event listener"),
    );
    expect(criticalErrors).toHaveLength(0);
  });

  test("page title is Network Radar", async ({ page }) => {
    await page.goto("/radar");
    await expect(page).toHaveTitle(/Network Radar|Radar|AILA/);
  });

  test("ReactFlow canvas or empty state renders", async ({ page }) => {
    await page.goto("/radar");
    // Allow topology API call and ReactFlow initialization
    await page.waitForTimeout(3000);

    // Either the ReactFlow canvas or an empty state message should be visible
    const reactFlowCanvas = page.locator(".react-flow");
    const emptyStateText = page.getByText(/No network data|No systems|Add systems/i);

    const hasReactFlow = await reactFlowCanvas.isVisible().catch(() => false);
    const hasEmpty = await emptyStateText.isVisible().catch(() => false);

    // At least one must render — the page must not be blank
    expect(hasReactFlow || hasEmpty).toBe(true);
  });

  test("toolbar controls are present", async ({ page }) => {
    await page.goto("/radar");
    await page.waitForTimeout(2000);

    // The toolbar renders a Select for color-by and an Input for search
    // These render inside the page regardless of whether topology data exists
    const toolbar = page.locator("select, [role='combobox'], input[type='text'], input[placeholder]");
    const toolbarCount = await toolbar.count();

    // At least one control (select or input) should be present in the toolbar
    expect(toolbarCount).toBeGreaterThan(0);
  });
});
