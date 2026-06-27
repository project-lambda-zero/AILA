/**
 * command-palette.spec.ts -- E2E tests for cmd+k command palette (UX-02).
 *
 * Uses REAL PostgreSQL backend -- no mocks.
 * Auth injected via localStorage per established project pattern.
 */
import { test, expect } from "@playwright/test";
import { getTokens, injectAuthState } from "../helpers/auth";

test.describe("Command Palette (UX-02)", () => {
  test("Ctrl+K opens the command palette", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);
    await page.goto("/systems");
    await page.waitForTimeout(1_000);

    // Open palette with keyboard shortcut
    await page.keyboard.press("Control+k");

    // Command dialog / input should be visible
    const paletteInput = page.locator('[placeholder*="Search"], [placeholder*="Command"]').first();
    await expect(paletteInput).toBeVisible({ timeout: 5_000 });
  });

  test("recently-viewed items appear in empty-query palette", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    // Visit two pages to populate recently-viewed
    await page.goto("/systems");
    await page.waitForTimeout(500);
    await page.goto("/scans");
    await page.waitForTimeout(500);

    // Open palette -- no query
    await page.keyboard.press("Control+k");
    await page.waitForTimeout(500);

    // "Recently Viewed" heading should appear
    await expect(page.getByText("Recently Viewed")).toBeVisible({ timeout: 5_000 });
  });

  test("command mode shows navigation commands with > prefix", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);
    await page.goto("/");
    await page.waitForTimeout(1_000);

    // Open palette
    await page.keyboard.press("Control+k");
    await page.waitForTimeout(300);

    // Type command prefix
    const input = page.locator('[cmdk-input], input[type="text"]').first();
    await input.fill(">dashboard");

    // "Go to Dashboard" should appear
    await expect(page.getByText("Go to Dashboard")).toBeVisible({ timeout: 5_000 });
  });

  test("clicking navigation command closes palette and navigates", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);
    await page.goto("/scans");
    await page.waitForTimeout(1_000);

    // Open palette
    await page.keyboard.press("Control+k");
    await page.waitForTimeout(300);

    // Type command to go to systems
    const input = page.locator('[cmdk-input], input[type="text"]').first();
    await input.fill(">systems");

    // Click "Go to Systems"
    await page.getByText("Go to Systems").click();

    // Should navigate to /systems
    await expect(page).toHaveURL(/\/systems/, { timeout: 5_000 });
  });
});
