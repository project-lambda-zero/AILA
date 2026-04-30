/**
 * E2E: Scheduled Reports Management (EXEC-02)
 *
 * Tests that the scheduled reports management UI loads, can create a report,
 * and can delete it — using the real backend.
 *
 * Uses real PostgreSQL backend — no mocks.
 */
import { test, expect } from "@playwright/test";

import { API_BASE, getTokens, injectAuthState } from "../helpers/auth";

const FRONTEND_URL = "http://localhost:5173";
const TEST_REPORT_NAME = `E2E Test Report ${Date.now()}`;

test.describe("Scheduled Reports Management (EXEC-02)", () => {
  test.beforeEach(async ({ page, request }) => {
    const tokens = await getTokens(request);
    await page.goto(`${FRONTEND_URL}/executive/scheduled-reports`);
    await injectAuthState(page, tokens);
    await page.reload();
  });

  test("scheduled reports page loads and shows heading", async ({ page }) => {
    await expect(
      page.getByRole("heading", { name: /scheduled reports/i }),
    ).toBeVisible({ timeout: 10_000 });
  });

  test("GET /scheduled-reports returns list (admin required)", async ({ request }) => {
    const tokens = await getTokens(request);
    const resp = await request.get(`${API_BASE}/scheduled-reports`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    // Admin credentials expected in E2E env — 200 or 403 (non-admin test user)
    expect([200, 403]).toContain(resp.status());
    if (resp.status() === 200) {
      const body = (await resp.json()) as { data: unknown[] };
      expect(Array.isArray(body.data)).toBe(true);
    }
  });

  test("can create and delete a scheduled report via API", async ({ request }) => {
    const tokens = await getTokens(request);

    // Create
    const createResp = await request.post(`${API_BASE}/scheduled-reports`, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        "Content-Type": "application/json",
      },
      data: {
        name: TEST_REPORT_NAME,
        report_type: "risk_summary",
        cron_expression: "0 9 * * MON",
        recipient_emails_json: "[]",
        config_json: "{}",
        is_active: true,
      },
    });

    if (createResp.status() === 403) {
      test.skip(); // Non-admin test user — skip CRUD test
      return;
    }

    expect(createResp.status()).toBe(201);
    const created = (await createResp.json()) as { data: { id: string } };
    const reportId = created.data.id;
    expect(typeof reportId).toBe("string");

    // Delete
    const deleteResp = await request.delete(
      `${API_BASE}/scheduled-reports/${encodeURIComponent(reportId)}`,
      { headers: { Authorization: `Bearer ${tokens.access_token}` } },
    );
    expect(deleteResp.status()).toBe(204);

    // Verify it's gone
    const listResp = await request.get(`${API_BASE}/scheduled-reports`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const list = (await listResp.json()) as { data: Array<{ id: string }> };
    expect(list.data.find((r) => r.id === reportId)).toBeUndefined();
  });

  test("trigger endpoint returns queued status", async ({ request }) => {
    const tokens = await getTokens(request);

    // Create a report to trigger
    const createResp = await request.post(`${API_BASE}/scheduled-reports`, {
      headers: {
        Authorization: `Bearer ${tokens.access_token}`,
        "Content-Type": "application/json",
      },
      data: {
        name: `E2E Trigger Test ${Date.now()}`,
        report_type: "risk_summary",
        cron_expression: "0 9 * * MON",
        recipient_emails_json: "[]",
        config_json: "{}",
        is_active: true,
      },
    });

    if (createResp.status() === 403) {
      test.skip();
      return;
    }

    const created = (await createResp.json()) as { data: { id: string } };
    const reportId = created.data.id;

    // Trigger
    const triggerResp = await request.post(
      `${API_BASE}/scheduled-reports/${encodeURIComponent(reportId)}/trigger`,
      { headers: { Authorization: `Bearer ${tokens.access_token}` } },
    );
    expect(triggerResp.status()).toBe(200);
    const triggerBody = (await triggerResp.json()) as { data: { status: string } };
    expect(triggerBody.data.status).toBe("queued");

    // Cleanup
    await request.delete(`${API_BASE}/scheduled-reports/${encodeURIComponent(reportId)}`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
  });
});
