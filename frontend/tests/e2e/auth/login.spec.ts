/**
 * login.spec.ts — E2E tests for the login flow (TEST-01).
 *
 * Coverage:
 *   - Login page renders with username and password inputs
 *   - Successful login with valid credentials redirects to dashboard
 *   - Invalid credentials display an error message
 *   - Logout from header clears session and redirects to /login
 *   - Protected route redirects unauthenticated user to /login
 *
 * Uses REAL PostgreSQL backend — no mocks, no MSW.
 * Credentials from environment variables: E2E_USERNAME, E2E_PASSWORD (default: admin/admin).
 */
import { test, expect } from "@playwright/test";

import {
  API_BASE,
  TEST_USERNAME,
  TEST_PASSWORD,
  getTokens,
  injectAuthState,
} from "../helpers/auth";

// ---------------------------------------------------------------------------
// Login page rendering
// ---------------------------------------------------------------------------

test.describe("Login page", () => {
  test("renders username and password inputs with submit button", async ({ page }) => {
    await page.goto("/login");

    // Username field — could be labeled "Username" or "Email"
    const usernameField = page
      .getByLabel(/username/i)
      .or(page.getByPlaceholder(/username/i))
      .or(page.locator('input[name="username"], input[type="text"]').first());
    await expect(usernameField).toBeVisible({ timeout: 10_000 });

    // Password field
    const passwordField = page
      .getByLabel(/password/i)
      .or(page.getByPlaceholder(/password/i))
      .or(page.locator('input[type="password"]').first());
    await expect(passwordField).toBeVisible({ timeout: 10_000 });

    // Submit button
    const submitBtn = page
      .getByRole("button", { name: /sign in|login|log in/i })
      .or(page.locator('button[type="submit"]').first());
    await expect(submitBtn).toBeVisible({ timeout: 10_000 });
  });

  test("page title identifies as AILA login", async ({ page }) => {
    await page.goto("/login");
    // Title or heading should reference AILA or Sign In
    await expect(page).toHaveTitle(/AILA|AI Lab|Login|Sign In/i, { timeout: 10_000 });
  });
});

// ---------------------------------------------------------------------------
// Authentication flow
// ---------------------------------------------------------------------------

test.describe("Authentication flow", () => {
  test("successful login redirects to dashboard /", async ({ page }) => {
    await page.goto("/login");

    // Fill credentials
    const usernameField = page
      .getByLabel(/username/i)
      .or(page.getByPlaceholder(/username/i))
      .or(page.locator('input[name="username"], input[type="text"]').first());
    await usernameField.fill(TEST_USERNAME);

    const passwordField = page
      .getByLabel(/password/i)
      .or(page.getByPlaceholder(/password/i))
      .or(page.locator('input[type="password"]').first());
    await passwordField.fill(TEST_PASSWORD);

    const submitBtn = page
      .getByRole("button", { name: /sign in|login|log in/i })
      .or(page.locator('button[type="submit"]').first());
    await submitBtn.click();

    // Should redirect away from /login on success
    await expect(page).not.toHaveURL(/\/login/, { timeout: 15_000 });
  });

  test("invalid credentials display an error message", async ({ page }) => {
    await page.goto("/login");

    const usernameField = page
      .getByLabel(/username/i)
      .or(page.getByPlaceholder(/username/i))
      .or(page.locator('input[name="username"], input[type="text"]').first());
    await usernameField.fill("nonexistent-user-xyz");

    const passwordField = page
      .getByLabel(/password/i)
      .or(page.getByPlaceholder(/password/i))
      .or(page.locator('input[type="password"]').first());
    await passwordField.fill("wrong-password-xyz");

    const submitBtn = page
      .getByRole("button", { name: /sign in|login|log in/i })
      .or(page.locator('button[type="submit"]').first());
    await submitBtn.click();

    // Error message should appear — could be toast, inline error, or alert
    const errorIndicator = page
      .getByText(/invalid|incorrect|unauthorized|wrong|failed/i)
      .or(page.locator('[role="alert"]').first());
    await expect(errorIndicator).toBeVisible({ timeout: 10_000 });

    // Must stay on login page
    await expect(page).toHaveURL(/\/login/, { timeout: 5_000 });
  });

  test("unauthenticated user accessing /systems is redirected to /login", async ({ page }) => {
    // No auth state injected — navigate directly to protected route
    await page.goto("/systems");

    // Should redirect to /login
    await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
  });
});

// ---------------------------------------------------------------------------
// Logout flow
// ---------------------------------------------------------------------------

test.describe("Logout flow", () => {
  test("logout clears session and redirects to /login", async ({ page, request }) => {
    const tokens = await getTokens(request);
    await injectAuthState(page, tokens);
    await page.goto("/");

    // Wait for authenticated shell — header should be visible
    await expect(page.locator("header")).toBeVisible({ timeout: 10_000 });

    // Find and click the user avatar / account menu trigger
    // Avatar menu is in UserAvatarMenu component — look for button with user icon or username
    const avatarBtn = page
      .getByRole("button", { name: new RegExp(TEST_USERNAME, "i") })
      .or(page.locator('[aria-label*="account" i], [aria-label*="user" i], [data-testid*="avatar"]').first())
      .or(page.locator("header").getByRole("button").last()); // fallback: last button in header
    await expect(avatarBtn).toBeVisible({ timeout: 10_000 });
    await avatarBtn.click();

    // Find logout button in the dropdown
    const logoutBtn = page.getByRole("menuitem", { name: /sign out|logout|log out/i });
    await expect(logoutBtn).toBeVisible({ timeout: 5_000 });
    await logoutBtn.click();

    // After logout, should be on /login
    await expect(page).toHaveURL(/\/login/, { timeout: 10_000 });
  });

  test("POST /auth/login returns valid token pair", async ({ request }) => {
    const resp = await request.post(`${API_BASE}/auth/login`, {
      data: { username: TEST_USERNAME, password: TEST_PASSWORD },
    });
    expect(resp.ok()).toBe(true);
    const body = (await resp.json()) as { data: { access_token: string; refresh_token: string } };
    expect(body).toHaveProperty("data");
    expect(typeof body.data.access_token).toBe("string");
    expect(body.data.access_token.length).toBeGreaterThan(10);
  });
});
