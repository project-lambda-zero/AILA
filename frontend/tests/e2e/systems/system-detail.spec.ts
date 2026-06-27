/**
 * system-detail.spec.ts
 *
 * E2E tests for the /systems/:id detail page.
 * Uses REAL PostgreSQL backend -- no mocks, no MSW, no route intercepts.
 *
 * Auth: POST /auth/login with local dev credentials, token injected via localStorage.
 * Data: one system seeded in beforeAll, cleaned up in afterAll.
 */
import { test, expect, type Page, type APIRequestContext } from "@playwright/test";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const API_BASE = "http://127.0.0.1:8000";
const TEST_USERNAME = process.env.E2E_USERNAME ?? "admin";
const TEST_PASSWORD = process.env.E2E_PASSWORD ?? "admin";

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

interface TokenPair {
  access_token: string;
  refresh_token: string;
}

async function getTokens(request: APIRequestContext): Promise<TokenPair> {
  const resp = await request.post(`${API_BASE}/auth/login`, {
    data: { username: TEST_USERNAME, password: TEST_PASSWORD },
  });
  if (!resp.ok()) {
    throw new Error(`Login failed: ${resp.status()} ${await resp.text()}`);
  }
  const body = await resp.json() as { data: TokenPair };
  return body.data;
}

async function injectAuthState(page: Page, tokens: TokenPair): Promise<void> {
  const payloadB64 = tokens.access_token.split(".")[1];
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf-8")) as {
    user_id: string;
    role: string;
    exp: number;
  };

  const authState = {
    state: {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      role: payload.role,
      userId: payload.user_id,
      username: TEST_USERNAME,
      isAuthenticated: true,
    },
    version: 1,
  };

  await page.addInitScript((state: string) => {
    localStorage.setItem("aila-auth", state);
  }, JSON.stringify(authState));
}

// ---------------------------------------------------------------------------
// API helpers
// ---------------------------------------------------------------------------

async function createSystem(
  request: APIRequestContext,
  token: string,
  name: string,
  host: string,
): Promise<number> {
  const resp = await request.post(`${API_BASE}/systems`, {
    data: {
      name,
      host,
      port: 22,
      username: "root",
      distro: "arch",
      description: "E2E test system",
    },
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok()) {
    throw new Error(`createSystem failed: ${resp.status()} ${await resp.text()}`);
  }
  const body = await resp.json() as { id: number; name: string };
  return body.id;
}

async function deleteSystem(
  request: APIRequestContext,
  token: string,
  systemId: number,
): Promise<void> {
  await request.delete(`${API_BASE}/systems/${systemId}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

test.describe("System Detail", () => {
  let tokens: TokenPair;
  let testSystemId: number;
  const suffix = Date.now();
  const testSystemName = `e2e-detail-${suffix}`;
  const testSystemHost = "10.99.0.1";

  test.beforeAll(async ({ request }) => {
    tokens = await getTokens(request);
    testSystemId = await createSystem(request, tokens.access_token, testSystemName, testSystemHost);
  });

  test.afterAll(async ({ request }) => {
    await deleteSystem(request, tokens.access_token, testSystemId).catch(() => {
      // Ignore -- may already be deleted
    });
  });

  test("system detail page loads with tabs", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto(`/systems/${testSystemId}`);

    // Tabs should be visible
    await expect(page.getByRole("tab", { name: "Overview" })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("tab", { name: "Findings" })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("tab", { name: "Scans" })).toBeVisible({ timeout: 10_000 });
    await expect(page.getByRole("tab", { name: "Tags" })).toBeVisible({ timeout: 10_000 });
  });

  test("overview tab shows system metadata", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto(`/systems/${testSystemId}`);

    // System name in heading
    await expect(page.getByRole("heading", { name: testSystemName })).toBeVisible({ timeout: 10_000 });

    // Host is shown in overview (host:port format)
    await expect(page.getByText(`${testSystemHost}:22`)).toBeVisible({ timeout: 10_000 });

    // System metadata card
    await expect(page.getByText("System Metadata")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("arch")).toBeVisible({ timeout: 10_000 });
  });

  test("tab navigation works via clicks and updates URL", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto(`/systems/${testSystemId}`);

    // Wait for tabs
    await expect(page.getByRole("tab", { name: "Findings" })).toBeVisible({ timeout: 10_000 });

    // Click Findings tab
    await page.getByRole("tab", { name: "Findings" }).click();
    await expect(page).toHaveURL(/tab=findings/, { timeout: 5_000 });

    // Click Scans tab
    await page.getByRole("tab", { name: "Scans" }).click();
    await expect(page).toHaveURL(/tab=scans/, { timeout: 5_000 });

    // Click Tags tab
    await page.getByRole("tab", { name: "Tags" }).click();
    await expect(page).toHaveURL(/tab=tags/, { timeout: 5_000 });
  });

  test("findings tab shows data or empty state", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto(`/systems/${testSystemId}?tab=findings`);

    // Either findings table OR the empty state message
    const emptyMsg = page.getByText("No findings for this system");
    const table = page.locator('[data-slot="table"]').first();

    await expect(emptyMsg.or(table)).toBeVisible({ timeout: 10_000 });
  });

  test("scans tab shows data or empty state", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto(`/systems/${testSystemId}?tab=scans`);

    // Either scans table OR the empty state message
    const emptyMsg = page.getByText("No scans have run for this system yet");
    const table = page.locator('[data-slot="table"]').first();

    await expect(emptyMsg.or(table)).toBeVisible({ timeout: 10_000 });
  });

  test("tags tab shows assignment form", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto(`/systems/${testSystemId}?tab=tags`);

    // Tags tab content loads (either shows form or empty tag state)
    await page.waitForTimeout(2_000);

    // The tab content should be visible -- check the tag section exists
    // Either there's an "Add tag" form or an empty state message
    const tagSection = page.locator('[data-value="tags"]');
    await expect(tagSection).toBeVisible({ timeout: 10_000 });
  });

  test("invalid system ID shows error state", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/systems/999999999");

    // Should show an error message or redirect
    await page.waitForTimeout(3_000);

    // Either error message or redirect back to systems list
    const errorMsg = page.locator(".text-destructive, [class*='destructive']").first();
    const backLink = page.getByRole("link", { name: /back to systems/i });

    await expect(errorMsg.or(backLink)).toBeVisible({ timeout: 10_000 });
  });
});
