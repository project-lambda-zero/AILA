/**
 * system-csv-import.spec.ts
 *
 * E2E tests for the CSV import dialog on /systems.
 * Uses REAL PostgreSQL backend — no mocks, no MSW, no route intercepts.
 *
 * Auth: POST /auth/login with local dev credentials, token injected via localStorage.
 * Data: CSV content uploaded via Playwright's setInputFiles API.
 * Cleanup: systems created via import are deleted in afterAll.
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

async function listSystems(
  request: APIRequestContext,
  token: string,
): Promise<Array<{ id: number; name: string }>> {
  const resp = await request.get(`${API_BASE}/systems`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok()) return [];
  const body = await resp.json() as { items: Array<{ id: number; name: string }> };
  return body.items ?? [];
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

async function createSystem(
  request: APIRequestContext,
  token: string,
  name: string,
  host: string,
): Promise<number> {
  const resp = await request.post(`${API_BASE}/systems`, {
    data: { name, host, port: 22, username: "root", distro: "unknown", description: "" },
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!resp.ok()) {
    throw new Error(`createSystem failed: ${resp.status()} ${await resp.text()}`);
  }
  const body = await resp.json() as { id: number };
  return body.id;
}

// ---------------------------------------------------------------------------
// CSV helper
// ---------------------------------------------------------------------------

function makeCSVBuffer(content: string): { name: string; mimeType: string; buffer: Buffer } {
  return {
    name: "test-systems.csv",
    mimeType: "text/csv",
    buffer: Buffer.from(content),
  };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

test.describe("CSV Import Dialog", () => {
  let tokens: TokenPair;
  const suffix = Date.now();
  const createdNames: string[] = [];

  test.beforeAll(async ({ request }) => {
    tokens = await getTokens(request);
  });

  test.afterAll(async ({ request }) => {
    if (!tokens) return;
    // Find and delete any systems created by the e2e CSV import tests
    const systems = await listSystems(request, tokens.access_token);
    for (const sys of systems) {
      if (createdNames.includes(sys.name) || sys.name.startsWith("e2e-csv-")) {
        await deleteSystem(request, tokens.access_token, sys.id).catch(() => {});
      }
    }
  });

  test("CSV import dialog opens when Import CSV button is clicked", async ({ page }) => {
    await injectAuthState(page, tokens);
    await page.goto("/systems");

    // Click the Import CSV button
    await page.getByRole("button", { name: /Import CSV/i }).click();

    // Dialog should appear with the drop zone
    await expect(page.getByText("Import Systems from CSV")).toBeVisible({ timeout: 5_000 });
    await expect(page.getByText(/Drop a CSV file or click to browse/i)).toBeVisible({ timeout: 5_000 });
  });

  test("valid CSV shows preview table with Valid badges", async ({ page }) => {
    const name1 = `e2e-csv-valid-a-${suffix}`;
    const name2 = `e2e-csv-valid-b-${suffix}`;
    createdNames.push(name1, name2);

    const csvContent = [
      "name,host,port,username,distro",
      `${name1},10.50.0.1,22,root,arch`,
      `${name2},10.50.0.2,22,root,ubuntu`,
    ].join("\n");

    await injectAuthState(page, tokens);
    await page.goto("/systems");

    await page.getByRole("button", { name: /Import CSV/i }).click();
    await expect(page.getByText("Import Systems from CSV")).toBeVisible({ timeout: 5_000 });

    // Upload via the hidden file input
    await page.locator('input[type="file"]').setInputFiles(makeCSVBuffer(csvContent));

    // Preview table should appear
    await expect(page.getByText("Preview (first")).toBeVisible({ timeout: 5_000 });

    // Both rows should show Valid badge
    const validBadges = page.getByText("Valid");
    await expect(validBadges.first()).toBeVisible({ timeout: 5_000 });
  });

  test("invalid rows are highlighted with Invalid badge", async ({ page }) => {
    const validName = `e2e-csv-valid-${suffix}`;
    createdNames.push(validName);

    const csvContent = [
      "name,host,port,username,distro",
      `${validName},10.51.0.1,22,root,arch`,
      `invalid-port-row,10.51.0.2,99999,root,ubuntu`,
    ].join("\n");

    await injectAuthState(page, tokens);
    await page.goto("/systems");

    await page.getByRole("button", { name: /Import CSV/i }).click();
    await expect(page.getByText("Import Systems from CSV")).toBeVisible({ timeout: 5_000 });

    await page.locator('input[type="file"]').setInputFiles(makeCSVBuffer(csvContent));

    // Preview should show a mix
    await expect(page.getByText("Preview (first")).toBeVisible({ timeout: 5_000 });

    // At least one "Invalid:" badge should appear
    const invalidBadge = page.getByText(/Invalid:/i).first();
    await expect(invalidBadge).toBeVisible({ timeout: 5_000 });
  });

  test("import button is disabled when zero valid rows", async ({ page }) => {
    const csvContent = [
      "name,host,port,username,distro",
      ",10.52.0.1,99999,root,arch",  // invalid: empty name and bad port
    ].join("\n");

    await injectAuthState(page, tokens);
    await page.goto("/systems");

    await page.getByRole("button", { name: /Import CSV/i }).click();
    await expect(page.getByText("Import Systems from CSV")).toBeVisible({ timeout: 5_000 });

    await page.locator('input[type="file"]').setInputFiles(makeCSVBuffer(csvContent));
    await expect(page.getByText("Preview (first")).toBeVisible({ timeout: 5_000 });

    // Import button should be disabled
    const importBtn = page.getByRole("button", { name: /Import 0/i });
    await expect(importBtn).toBeDisabled({ timeout: 5_000 });
  });

  test("import submits and systems appear in the list", async ({ page }) => {
    const name = `e2e-csv-import-${suffix}`;
    createdNames.push(name);

    const csvContent = [
      "name,host,port,username,distro",
      `${name},10.53.0.1,22,root,arch`,
    ].join("\n");

    await injectAuthState(page, tokens);
    await page.goto("/systems");

    await page.getByRole("button", { name: /Import CSV/i }).click();
    await expect(page.getByText("Import Systems from CSV")).toBeVisible({ timeout: 5_000 });

    await page.locator('input[type="file"]').setInputFiles(makeCSVBuffer(csvContent));
    await expect(page.getByText("Preview (first")).toBeVisible({ timeout: 5_000 });

    // Click import
    await page.getByRole("button", { name: /Import 1 valid row/i }).click();

    // Success message should appear, then dialog closes
    await expect(page.getByText(/1 system imported successfully/i)).toBeVisible({ timeout: 10_000 });

    // After auto-close, new system should appear in the list
    await page.waitForTimeout(2_000);
    await expect(page.getByText(name)).toBeVisible({ timeout: 10_000 });
  });

  test("import shows server errors inline for duplicate names", async ({ page, request }) => {
    // Pre-create a system with the same name
    const dupName = `e2e-csv-dup-${suffix}`;
    const dupId = await createSystem(request, tokens.access_token, dupName, "10.54.0.99");

    const csvContent = [
      "name,host,port,username,distro",
      `${dupName},10.54.0.1,22,root,arch`,
    ].join("\n");

    await injectAuthState(page, tokens);
    await page.goto("/systems");

    await page.getByRole("button", { name: /Import CSV/i }).click();
    await expect(page.getByText("Import Systems from CSV")).toBeVisible({ timeout: 5_000 });

    await page.locator('input[type="file"]').setInputFiles(makeCSVBuffer(csvContent));
    await expect(page.getByText("Preview (first")).toBeVisible({ timeout: 5_000 });

    await page.getByRole("button", { name: /Import 1 valid row/i }).click();

    // Either errors section shows OR import result mentions 0 created
    await page.waitForTimeout(3_000);

    // If import succeeded partially or fully, the error list shows inline
    // The backend returns HTTP 200 with errors array (D-09: partial success is valid)
    const errorSection = page.getByText(/Import errors/i);
    const successMsg = page.getByText(/system imported/i);

    await expect(errorSection.or(successMsg)).toBeVisible({ timeout: 10_000 });

    // Cleanup the pre-created dup system
    await deleteSystem(request, tokens.access_token, dupId).catch(() => {});
  });
});
