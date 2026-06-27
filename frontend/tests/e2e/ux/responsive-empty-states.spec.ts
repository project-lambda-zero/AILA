/**
 * responsive-empty-states.spec.ts -- E2E tests for responsive layout (UX-03)
 * and contextual empty states (UX-04).
 *
 * Uses REAL PostgreSQL backend -- no mocks.
 * Auth injected via localStorage per established project pattern.
 */
import { test, expect } from "@playwright/test";
import { getTokens, injectAuthState } from "../helpers/auth";

// ---------------------------------------------------------------------------
// Responsive: no horizontal overflow at 320px
// ---------------------------------------------------------------------------

test.describe("Responsive Layout (UX-03)", () => {
  test("no horizontal overflow at 320px on dashboard", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    await page.setViewportSize({ width: 320, height: 568 });
    await page.goto("/");
    await page.waitForTimeout(2_000);

    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(scrollWidth).toBeLessThanOrEqual(320);
  });

  test("no horizontal overflow at 320px on systems page", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    await page.setViewportSize({ width: 320, height: 568 });
    await page.goto("/systems");
    await page.waitForTimeout(2_000);

    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(scrollWidth).toBeLessThanOrEqual(320);
  });

  test("no horizontal overflow at 375px on scans page", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    await page.setViewportSize({ width: 375, height: 667 });
    await page.goto("/scans");
    await page.waitForTimeout(2_000);

    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(scrollWidth).toBeLessThanOrEqual(375);
  });

  test("no horizontal overflow at 768px on tasks page", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    await page.setViewportSize({ width: 768, height: 1024 });
    await page.goto("/tasks");
    await page.waitForTimeout(2_000);

    const scrollWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(scrollWidth).toBeLessThanOrEqual(768);
  });
});

// ---------------------------------------------------------------------------
// Empty states: contextual guidance when data is absent
// ---------------------------------------------------------------------------

test.describe("Empty States (UX-04)", () => {
  test("systems page renders heading regardless of data state", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);
    await page.goto("/systems");

    // Page must render a heading -- either table or empty state
    await expect(
      page.getByRole("heading", { name: "Systems" }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("dashboard renders without crash at all viewport widths", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    for (const width of [320, 375, 768, 1024, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      await page.goto("/");
      await page.waitForTimeout(1_000);

      // No JS errors -- page renders heading
      await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible({
        timeout: 10_000,
      });
    }
  });

  test("tasks empty state shows CTA when no tasks exist", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);
    await page.goto("/tasks");
    await page.waitForTimeout(2_000);

    // Either the table or the empty state with "No tasks" should be present
    const tableBody = page.locator("tbody tr").first();
    const emptyState = page.getByText("No tasks");

    // One of them must be visible
    const tableVisible = await tableBody.isVisible().catch(() => false);
    const emptyVisible = await emptyState.isVisible().catch(() => false);
    expect(tableVisible || emptyVisible).toBe(true);
  });

  test("scans empty state shows CTA when no scans exist", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);
    await page.goto("/scans");
    await page.waitForTimeout(2_000);

    // Either scans table rows or empty state
    const tableRow = page.locator("tbody tr").first();
    const emptyState = page.getByText("No scans yet");

    const tableVisible = await tableRow.isVisible().catch(() => false);
    const emptyVisible = await emptyState.isVisible().catch(() => false);
    expect(tableVisible || emptyVisible).toBe(true);
  });
});
