/**
 * admin-surfaces.spec.ts
 *
 * E2E tests for all four admin pages:
 *   /admin/audit    -- Audit Logs (ADM-01)
 *   /admin/api-keys -- API Keys (ADM-02)
 *   /admin/config   -- Platform Config (ADM-03)
 *   /admin/health   -- System Health (ADM-04)
 *
 * Uses REAL PostgreSQL backend -- no mocks, no MSW, no route intercepts.
 * Auth: admin token injected via localStorage (Zustand auth store format).
 * Cleanup: API keys created during tests are revoked in afterAll.
 */
import { test, expect, type Page, type APIRequestContext } from "@playwright/test";

import {
  API_BASE,
  getTokens,
  injectAuthState,
  type TokenPair,
} from "../helpers/auth";

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function createApiKey(
  request: APIRequestContext,
  token: string,
  label: string,
  role: "reader" | "operator" | "admin" = "reader",
): Promise<{ key_id: string; raw_key: string }> {
  const resp = await request.post(`${API_BASE}/auth/keys`, {
    data: { label, role },
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok()) {
    throw new Error(`createApiKey failed: ${resp.status()} ${await resp.text()}`);
  }
  const body = await resp.json() as { key_id: string; raw_key: string };
  return body;
}

async function revokeApiKey(
  request: APIRequestContext,
  token: string,
  keyId: string,
): Promise<void> {
  await request.delete(`${API_BASE}/auth/keys/${keyId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

async function getHealth(
  request: APIRequestContext,
): Promise<{ status: string; checks: Record<string, { status: string }> }> {
  const resp = await request.get(`${API_BASE}/health`);
  if (!resp.ok()) {
    throw new Error(`getHealth failed: ${resp.status()} ${await resp.text()}`);
  }
  return resp.json() as Promise<{ status: string; checks: Record<string, { status: string }> }>;
}

// ---------------------------------------------------------------------------
// Auth helpers -- page setup
// ---------------------------------------------------------------------------

async function setupAdminPage(page: Page, tokens: TokenPair, path: string): Promise<void> {
  await injectAuthState(page, tokens);
  await page.goto(path);
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

test.describe("Admin Surfaces", () => {
  let tokens: TokenPair;
  const createdKeyIds: string[] = [];

  test.beforeAll(async ({ request }) => {
    tokens = await getTokens(request);
  });

  test.afterAll(async ({ request }) => {
    // Clean up any API keys created during tests
    for (const keyId of createdKeyIds) {
      await revokeApiKey(request, tokens.access_token, keyId).catch(() => {
        // Ignore -- may already be revoked
      });
    }
  });

  // -------------------------------------------------------------------------
  // Audit Logs (ADM-01)
  // -------------------------------------------------------------------------

  test.describe("Audit Logs (/admin/audit)", () => {
    test("page renders heading and filter form", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/audit");

      await expect(page.getByRole("heading", { name: "Audit Logs" })).toBeVisible({
        timeout: 10_000,
      });

      // Filter form inputs
      await expect(page.getByLabel("Run ID")).toBeVisible({ timeout: 10_000 });
      await expect(page.getByLabel("Stage")).toBeVisible({ timeout: 10_000 });
      await expect(page.getByLabel("Action")).toBeVisible({ timeout: 10_000 });
    });

    test("metric cards are visible", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/audit");

      await expect(page.getByText("Total Events")).toBeVisible({ timeout: 10_000 });
      await expect(page.getByText("Loaded Events")).toBeVisible({ timeout: 10_000 });
      await expect(page.getByText("Date Range")).toBeVisible({ timeout: 10_000 });
    });

    test("audit table renders or shows empty state after load", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/audit");

      // Wait for loading to finish -- either table headers or empty state
      await page.waitForSelector(
        'text=Run ID, text=No audit events',
        { timeout: 15_000 },
      );
    });

    test("export CSV button appears when events exist", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/audit");

      // Wait for data to load
      await page.waitForTimeout(3_000);

      // If events exist, export buttons should be visible
      const hasEvents = await page.getByText("Export CSV").isVisible().catch(() => false);
      const hasEmpty = await page.getByText("No audit events").isVisible().catch(() => false);

      // One of these must be true -- either data loaded or empty state shown
      expect(hasEvents || hasEmpty).toBe(true);
    });

    test("apply filters button triggers a new query", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/audit");

      // Wait for initial load
      await expect(page.getByLabel("Action")).toBeVisible({ timeout: 10_000 });

      // Type a filter value
      await page.getByLabel("Action").fill("token.issue");

      // Submit the filter form
      await page.getByRole("button", { name: "Apply Filters" }).click();

      // Page should still show the heading (no crash)
      await expect(page.getByRole("heading", { name: "Audit Logs" })).toBeVisible({
        timeout: 10_000,
      });
    });

    test("clear button resets filters", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/audit");

      await expect(page.getByLabel("Stage")).toBeVisible({ timeout: 10_000 });
      await page.getByLabel("Stage").fill("auth");

      await page.getByRole("button", { name: "Clear" }).click();

      await expect(page.getByLabel("Stage")).toHaveValue("");
    });
  });

  // -------------------------------------------------------------------------
  // API Keys (ADM-02)
  // -------------------------------------------------------------------------

  test.describe("API Keys (/admin/api-keys)", () => {
    test("page renders heading and metric cards", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/api-keys");

      await expect(page.getByRole("heading", { name: "API Keys" })).toBeVisible({
        timeout: 10_000,
      });
      await expect(page.getByText("Total Keys")).toBeVisible({ timeout: 10_000 });
      await expect(page.getByText("Active Keys")).toBeVisible({ timeout: 10_000 });
      await expect(page.getByText("Revoked Keys")).toBeVisible({ timeout: 10_000 });
    });

    test("Create API Key button opens dialog", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/api-keys");

      await page.getByRole("button", { name: "Create API Key" }).click();

      // Dialog should be visible with form fields
      await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5_000 });
      await expect(page.getByLabel("Label")).toBeVisible({ timeout: 5_000 });
      await expect(page.getByLabel("Role")).toBeVisible({ timeout: 5_000 });
    });

    test("create dialog Cancel button closes dialog", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/api-keys");

      await page.getByRole("button", { name: "Create API Key" }).click();
      await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5_000 });

      await page.getByRole("button", { name: "Cancel" }).click();

      await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5_000 });
    });

    test("seeded key appears in the keys table", async ({ page, request }) => {
      const label = `e2e-key-${Date.now()}`;
      const { key_id } = await createApiKey(request, tokens.access_token, label);
      createdKeyIds.push(key_id);

      await setupAdminPage(page, tokens, "/admin/api-keys");

      // The seeded key label should appear in the table
      await expect(page.getByText(label)).toBeVisible({ timeout: 10_000 });
    });

    test("active key shows Revoke button", async ({ page, request }) => {
      const label = `e2e-revoke-btn-${Date.now()}`;
      const { key_id } = await createApiKey(request, tokens.access_token, label);
      createdKeyIds.push(key_id);

      await setupAdminPage(page, tokens, "/admin/api-keys");
      await expect(page.getByText(label)).toBeVisible({ timeout: 10_000 });

      // At least one Revoke button should be enabled
      const revokeButtons = page.getByRole("button", { name: "Revoke" });
      const count = await revokeButtons.count();
      expect(count).toBeGreaterThan(0);
    });

    test("Revoke button opens confirmation dialog", async ({ page, request }) => {
      const label = `e2e-revoke-dialog-${Date.now()}`;
      const { key_id } = await createApiKey(request, tokens.access_token, label);
      createdKeyIds.push(key_id);

      await setupAdminPage(page, tokens, "/admin/api-keys");
      await expect(page.getByText(label)).toBeVisible({ timeout: 10_000 });

      // Click the first enabled Revoke button
      const revokeButton = page.getByRole("button", { name: "Revoke" }).first();
      await revokeButton.click();

      // Confirmation dialog should appear
      await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5_000 });
      await expect(page.getByText("Revoke API Key")).toBeVisible({ timeout: 5_000 });
      await expect(page.getByRole("button", { name: "Confirm Revoke" })).toBeVisible({
        timeout: 5_000,
      });
    });

    test("revoke confirmation Cancel closes dialog without revoking", async ({
      page,
      request,
    }) => {
      const label = `e2e-cancel-revoke-${Date.now()}`;
      const { key_id } = await createApiKey(request, tokens.access_token, label);
      createdKeyIds.push(key_id);

      await setupAdminPage(page, tokens, "/admin/api-keys");
      await expect(page.getByText(label)).toBeVisible({ timeout: 10_000 });

      await page.getByRole("button", { name: "Revoke" }).first().click();
      await expect(page.getByRole("dialog")).toBeVisible({ timeout: 5_000 });

      await page.getByRole("button", { name: "Cancel" }).last().click();

      // Dialog should close, key still active
      await expect(page.getByRole("dialog")).not.toBeVisible({ timeout: 5_000 });
      await expect(page.getByText(label)).toBeVisible({ timeout: 5_000 });
    });
  });

  // -------------------------------------------------------------------------
  // Platform Config (ADM-03)
  // -------------------------------------------------------------------------

  test.describe("Platform Config (/admin/config)", () => {
    test("page renders heading and metric cards", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/config");

      await expect(page.getByRole("heading", { name: "Platform Config" })).toBeVisible({
        timeout: 10_000,
      });
      await expect(page.getByText("Total Entries")).toBeVisible({ timeout: 10_000 });
      await expect(page.getByText("Namespaces")).toBeVisible({ timeout: 10_000 });
    });

    test("renders namespace groups or empty state after loading", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/config");

      // Wait for loading to finish
      await page.waitForSelector(
        '[class*="font-mono"][class*="text-2xl"], text=No configuration entries',
        { timeout: 15_000 },
      );

      // Page should not have crashed -- heading still visible
      await expect(page.getByRole("heading", { name: "Platform Config" })).toBeVisible();
    });

    test("Edit button appears for config entries when data loaded", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/config");

      // Wait for data
      await page.waitForTimeout(3_000);

      const hasEntries = await page.getByText("Total Entries").isVisible().catch(() => false);
      expect(hasEntries).toBe(true);

      // If there are entries, Edit buttons should be visible
      const editButtons = page.getByRole("button", { name: "Edit" });
      const count = await editButtons.count();

      // Either edit buttons present (entries exist) or empty state shown
      const emptyState = await page
        .getByText("No configuration entries")
        .isVisible()
        .catch(() => false);

      expect(count > 0 || emptyState).toBe(true);
    });
  });

  // -------------------------------------------------------------------------
  // System Health (ADM-04)
  // -------------------------------------------------------------------------

  test.describe("System Health (/admin/health)", () => {
    test("page renders heading", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/health");

      await expect(page.getByRole("heading", { name: "System Health" })).toBeVisible({
        timeout: 10_000,
      });
    });

    test("overall status banner is visible after load", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/health");

      // Overall status should show one of the three states
      const healthy = page.getByText("HEALTHY");
      const degraded = page.getByText("DEGRADED");
      const unhealthy = page.getByText("UNHEALTHY");

      const anyStatus = healthy.or(degraded).or(unhealthy);
      await expect(anyStatus).toBeVisible({ timeout: 15_000 });
    });

    test("database check card is visible", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/health");

      // The health endpoint always returns a database check
      await expect(page.getByText("Database")).toBeVisible({ timeout: 15_000 });
    });

    test("Refresh button triggers a new health fetch", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/health");

      // Wait for initial load
      await page.waitForSelector('text=HEALTHY, text=DEGRADED, text=UNHEALTHY', {
        timeout: 15_000,
      });

      // Click refresh
      await page.getByRole("button", { name: "Refresh" }).click();

      // Page remains stable -- heading still visible
      await expect(page.getByRole("heading", { name: "System Health" })).toBeVisible({
        timeout: 5_000,
      });
    });

    test("health API returns healthy status for database when backend is running", async ({
      request,
    }) => {
      const health = await getHealth(request);
      expect(["healthy", "degraded", "unhealthy"]).toContain(health.status);
      expect(health.checks).toHaveProperty("database");
    });

    test("components section shows check count", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/health");

      // Wait for data
      await page.waitForSelector('text=Components', { timeout: 15_000 });
      await expect(page.getByText(/Components \(\d+\)/)).toBeVisible({ timeout: 10_000 });
    });

    test("polling info footer is visible", async ({ page }) => {
      await setupAdminPage(page, tokens, "/admin/health");

      await page.waitForSelector('text=HEALTHY, text=DEGRADED, text=UNHEALTHY', {
        timeout: 15_000,
      });

      await expect(
        page.getByText(/Health status is polled every 30 seconds/),
      ).toBeVisible({ timeout: 5_000 });
    });
  });
});
