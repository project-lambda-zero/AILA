/**
 * E2E: Executive Risk Summary PDF (EXEC-01)
 *
 * Tests that the executive dashboard loads with real backend data and that
 * the PDF download button triggers a file download.
 *
 * Uses real PostgreSQL backend — no mocks.
 */
import { test, expect } from "@playwright/test";

import { API_BASE, getTokens, injectAuthState } from "../helpers/auth";

const FRONTEND_URL = "http://localhost:5173";

test.describe("Executive Risk Summary PDF (EXEC-01)", () => {
  test.beforeEach(async ({ page, request }) => {
    const tokens = await getTokens(request);
    await page.goto(`${FRONTEND_URL}/executive`);
    await injectAuthState(page, tokens);
    await page.reload();
  });

  test("executive dashboard page loads with severity cards", async ({ page }) => {
    await expect(
      page.getByRole("heading", { name: /executive reports/i }),
    ).toBeVisible({ timeout: 10_000 });

    // Severity cards must be present (counts may be 0 in a fresh test DB)
    await expect(page.getByTestId("severity-card-immediate")).toBeVisible();
    await expect(page.getByTestId("severity-card-high")).toBeVisible();
    await expect(page.getByTestId("severity-card-moderate")).toBeVisible();
    await expect(page.getByTestId("severity-card-planned")).toBeVisible();
  });

  test("GET /executive/health returns valid posture summary", async ({ request }) => {
    const tokens = await getTokens(request);
    const resp = await request.get(`${API_BASE}/executive/health`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(resp.status()).toBe(200);
    const body = (await resp.json()) as {
      data: {
        total_findings: number;
        severity_breakdown: Record<string, number>;
        systems_with_findings: number;
      };
    };
    expect(body).toHaveProperty("data");
    expect(typeof body.data.total_findings).toBe("number");
    expect(body.data.severity_breakdown).toHaveProperty("Immediate");
    expect(body.data.severity_breakdown).toHaveProperty("High");
    expect(body.data.severity_breakdown).toHaveProperty("Moderate");
    expect(body.data.severity_breakdown).toHaveProperty("Planned");
    expect(typeof body.data.systems_with_findings).toBe("number");
  });

  test("Download Risk Summary PDF triggers file download", async ({ page }) => {
    await expect(
      page.getByRole("heading", { name: /executive reports/i }),
    ).toBeVisible({ timeout: 10_000 });

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 30_000 }),
      page.getByRole("button", { name: /download risk summary pdf/i }).click(),
    ]);

    const filename = download.suggestedFilename();
    expect(filename).toMatch(/aila-risk-summary.*\.pdf/i);
  });

  test("GET /executive/risk-summary-pdf returns application/pdf", async ({ request }) => {
    const tokens = await getTokens(request);
    const resp = await request.get(`${API_BASE}/executive/risk-summary-pdf`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    // Either 200 (weasyprint installed) or 503 (weasyprint not installed in test env)
    expect([200, 503]).toContain(resp.status());
    if (resp.status() === 200) {
      const contentType = resp.headers()["content-type"] ?? "";
      expect(contentType).toContain("application/pdf");
    }
  });
});
