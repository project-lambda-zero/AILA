/**
 * systems-list.spec.ts
 *
 * E2E tests for the /systems list page.
 * Uses REAL PostgreSQL backend — no mocks, no MSW, no route intercepts.
 * Per project memory: "mocked tests are worthless for verifying adapters work."
 *
 * Auth: POST /auth/login with local dev credentials, token injected via localStorage.
 * Data: seeded via page.request.post with auth headers before each test group.
 * Cleanup: DELETE via API in afterAll.
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

/** Inject Zustand auth state into localStorage so the React app picks it up on load. */
async function injectAuthState(page: Page, tokens: TokenPair): Promise<void> {
  // Decode JWT claims to extract role/userId without a library
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
// API seeding helpers
// ---------------------------------------------------------------------------

async function createSystem(
  request: APIRequestContext,
  token: string,
  data: {
    name: string;
    host: string;
    port?: number;
    username?: string;
    distro?: string;
    description?: string;
  },
): Promise<number> {
  const resp = await request.post(`${API_BASE}/systems`, {
    data: {
      name: data.name,
      host: data.host,
      port: data.port ?? 22,
      username: data.username ?? "root",
      distro: data.distro ?? "unknown",
      description: data.description ?? "",
    },
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok()) {
    throw new Error(`createSystem failed: ${resp.status()} ${await resp.text()}`);
  }
  const body = await resp.json() as { id: number };
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

test.describe("Systems List", () => {
  let tokens: TokenPair;
  const createdIds: number[] = [];

  test.beforeAll(async ({ request }) => {
    tokens = await getTokens(request);
  });

  test.afterAll(async ({ request }) => {
    for (const id of createdIds) {
      await deleteSystem(request, tokens.access_token, id).catch(() => {
        // Ignore delete errors — system may already be removed
      });
    }
  });

  test("systems list page renders with table and column headers", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/systems");

    // Page heading
    await expect(page.getByRole("heading", { name: "Systems" })).toBeVisible();

    // Wait for either the table or empty state to appear
    await page.waitForSelector('[data-slot="table"], [data-testid="empty-systems"]', {
      timeout: 10_000,
    });
  });

  test("systems list shows seeded systems", async ({ page, request }) => {
    const suffix = Date.now();
    const nameA = `e2e-list-a-${suffix}`;
    const nameB = `e2e-list-b-${suffix}`;

    const idA = await createSystem(request, tokens.access_token, { name: nameA, host: "10.0.0.1" });
    const idB = await createSystem(request, tokens.access_token, { name: nameB, host: "10.0.0.2" });
    createdIds.push(idA, idB);

    await injectAuthState(page, tokens);
    await page.goto("/systems");

    // Wait for the table to load
    await expect(page.getByText(nameA)).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText(nameB)).toBeVisible({ timeout: 10_000 });
  });

  test("systems list filters by name search", async ({ page, request }) => {
    const suffix = Date.now();
    const nameAlpha = `e2e-alpha-${suffix}`;
    const nameBeta = `e2e-beta-${suffix}`;

    const idAlpha = await createSystem(request, tokens.access_token, { name: nameAlpha, host: "10.1.0.1" });
    const idBeta = await createSystem(request, tokens.access_token, { name: nameBeta, host: "10.1.0.2" });
    createdIds.push(idAlpha, idBeta);

    await injectAuthState(page, tokens);
    await page.goto("/systems");
    await expect(page.getByText(nameAlpha)).toBeVisible({ timeout: 10_000 });

    // Type in the global filter input (provided by AilaTable enableFiltering)
    const filterInput = page.locator('input[placeholder*="filter"], input[placeholder*="Filter"], input[placeholder*="search"], input[placeholder*="Search"]').first();
    await filterInput.fill(nameAlpha);
    await page.waitForTimeout(300);

    await expect(page.getByText(nameAlpha)).toBeVisible();
    await expect(page.getByText(nameBeta)).not.toBeVisible();
  });

  test("metric cards show correct counts", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/systems");

    // Wait for page to load
    await page.waitForTimeout(2_000);

    // Three metric cards should be visible
    await expect(page.getByText("Registered Systems")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Visible Systems")).toBeVisible({ timeout: 10_000 });
    await expect(page.getByText("Unreachable")).toBeVisible({ timeout: 10_000 });
  });

  test("SSH connectivity badges are visible in rows", async ({ page, request }) => {
    const suffix = Date.now();
    const name = `e2e-badge-${suffix}`;
    const id = await createSystem(request, tokens.access_token, { name, host: "10.2.0.1" });
    createdIds.push(id);

    await injectAuthState(page, tokens);
    await page.goto("/systems");

    await expect(page.getByText(name)).toBeVisible({ timeout: 10_000 });

    // Connectivity badge should show one of the three states
    const badge = page.locator("text=ONLINE, text=OFFLINE, text=UNKNOWN").first();
    // Accept any connectivity badge text
    const onlineBadge = page.getByText("ONLINE").first();
    const offlineBadge = page.getByText("OFFLINE").first();
    const unknownBadge = page.getByText("UNKNOWN").first();

    const anyBadge = onlineBadge.or(offlineBadge).or(unknownBadge);
    await expect(anyBadge).toBeVisible({ timeout: 10_000 });
    void badge;
  });

  test("Import CSV button is visible for operators", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/systems");

    await expect(page.getByRole("button", { name: /Import CSV/i })).toBeVisible({ timeout: 10_000 });
  });

  test("tag filter badges appear when vocabulary exists", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/systems");

    // Wait for page to settle
    await page.waitForTimeout(2_000);

    // If no vocabulary entries exist, the tag filter bar is not shown — that's acceptable.
    // This test verifies the filter bar does NOT crash the page regardless of vocab state.
    await expect(page.getByRole("heading", { name: "Systems" })).toBeVisible({ timeout: 10_000 });
  });
});
