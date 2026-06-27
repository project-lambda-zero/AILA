/**
 * offline-banner.spec.ts -- E2E tests for offline mode banner (UX-07).
 *
 * Uses Playwright's context.setOffline() to simulate network loss.
 * Auth injected via localStorage per established project pattern.
 */
import { test, expect } from "@playwright/test";
import { getTokens, injectAuthState } from "../helpers/auth";

test.describe("Offline Banner (UX-07)", () => {
  test("offline banner appears when network is disabled", async ({ page, context, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    // Load page while online
    await page.goto("/");
    await page.waitForTimeout(2_000);

    // Simulate going offline
    await context.setOffline(true);
    await page.waitForTimeout(1_000);

    // Offline banner should appear
    const banner = page.getByTestId("offline-banner");
    await expect(banner).toBeVisible({ timeout: 5_000 });

    // Banner should contain "Offline" text
    await expect(banner).toContainText("Offline");

    // Restore network
    await context.setOffline(false);
  });

  test("offline banner disappears when network is restored", async ({ page, context, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    await page.goto("/");
    await page.waitForTimeout(2_000);

    // Go offline
    await context.setOffline(true);
    await page.waitForTimeout(500);

    // Verify offline banner visible
    await expect(page.getByTestId("offline-banner")).toBeVisible({ timeout: 5_000 });

    // Restore network
    await context.setOffline(false);
    await page.waitForTimeout(1_000);

    // Banner should disappear
    await expect(page.getByTestId("offline-banner")).not.toBeVisible({ timeout: 5_000 });
  });

  test("offline banner shows read-only mode indicator", async ({ page, context, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    await page.goto("/");
    await page.waitForTimeout(2_000);

    await context.setOffline(true);
    await page.waitForTimeout(500);

    const banner = page.getByTestId("offline-banner");
    await expect(banner).toBeVisible({ timeout: 5_000 });
    await expect(banner).toContainText("read-only");

    await context.setOffline(false);
  });
});
