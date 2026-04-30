/**
 * onboarding.spec.ts — E2E tests for the first-run onboarding wizard (UX-01).
 *
 * Uses REAL PostgreSQL backend — no mocks.
 * Auth injected via localStorage per established project pattern.
 */
import { test, expect } from "@playwright/test";
import { getTokens, injectAuthState } from "../helpers/auth";

// ---------------------------------------------------------------------------
// Helper: clear localStorage before navigation
// ---------------------------------------------------------------------------

async function clearLocalStorage(page: import("@playwright/test").Page): Promise<void> {
  // Set baseURL before clearing so we are on the right origin
  await page.goto("/");
  await page.evaluate(() => localStorage.clear());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test.describe("Onboarding Wizard (UX-01)", () => {
  test("wizard appears on first visit when localStorage is cleared", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    // Clear onboarding flag to simulate first visit
    await page.addInitScript(() => {
      localStorage.removeItem("aila-onboarding-done");
    });

    await page.goto("/");

    // Wizard dialog should be visible
    await expect(page.getByText("Welcome to AILA")).toBeVisible({ timeout: 10_000 });
  });

  test("wizard can be skipped and does not reappear on reload", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    // Clear onboarding flag
    await page.addInitScript(() => {
      localStorage.removeItem("aila-onboarding-done");
    });

    await page.goto("/");

    // Wait for wizard to appear
    await expect(page.getByText("Welcome to AILA")).toBeVisible({ timeout: 10_000 });

    // Click "Skip setup"
    await page.getByText("Skip setup").click();

    // Wizard should be gone
    await expect(page.getByText("Welcome to AILA")).not.toBeVisible({ timeout: 5_000 });

    // Reload — wizard should NOT reappear (localStorage flag set)
    await page.reload();
    await page.waitForTimeout(2_000);
    await expect(page.getByText("Welcome to AILA")).not.toBeVisible();
  });

  test("wizard advances from welcome to register system step", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    // Clear onboarding flag
    await page.addInitScript(() => {
      localStorage.removeItem("aila-onboarding-done");
    });

    await page.goto("/");

    // Wait for step 1 — welcome
    await expect(page.getByText("Welcome to AILA")).toBeVisible({ timeout: 10_000 });

    // Click "Get Started"
    await page.getByRole("button", { name: /Get Started/i }).click();

    // Step 2 should show register system form
    await expect(page.getByText("Register a System")).toBeVisible({ timeout: 5_000 });
    await expect(page.getByLabelText(/System name/i)).toBeVisible();
    await expect(page.getByLabelText(/Host/i)).toBeVisible();
  });

  test("wizard does not appear when already completed", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);

    // Pre-set onboarding as done
    await page.addInitScript(() => {
      localStorage.setItem("aila-onboarding-done", "true");
    });

    await page.goto("/");
    await page.waitForTimeout(2_000);

    // Wizard should NOT appear
    await expect(page.getByText("Welcome to AILA")).not.toBeVisible();
  });
});
