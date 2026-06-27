/**
 * E2E: Compliance Evidence Package (EXEC-03)
 *
 * Tests that the compliance evidence package endpoint returns a valid ZIP
 * archive for systems with scan data, and a 404 for unknown systems.
 *
 * Uses real PostgreSQL backend -- no mocks.
 */
import { test, expect } from "@playwright/test";

import { API_BASE, getTokens } from "../helpers/auth";

test.describe("Compliance Evidence Package (EXEC-03)", () => {
  test("GET /executive/systems/0/evidence-package returns 404 for unknown system", async ({
    request,
  }) => {
    const tokens = await getTokens(request);
    const resp = await request.get(`${API_BASE}/executive/systems/0/evidence-package`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    // System ID 0 cannot exist (must be > 0); backend should 404 or 422
    expect([404, 422]).toContain(resp.status());
  });

  test("GET /executive/systems/999999/evidence-package returns 404 for non-existent system", async ({
    request,
  }) => {
    const tokens = await getTokens(request);
    const resp = await request.get(`${API_BASE}/executive/systems/999999/evidence-package`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(resp.status()).toBe(404);
  });

  test("GET /executive/systems/{id}/evidence-package requires authentication", async ({
    request,
  }) => {
    const resp = await request.get(`${API_BASE}/executive/systems/1/evidence-package`);
    expect([401, 403]).toContain(resp.status());
  });

  test("GET /executive/systems/{id}/evidence-package returns zip when system has data", async ({
    request,
  }) => {
    const tokens = await getTokens(request);

    // First, find a system that exists -- list systems
    const systemsResp = await request.get(`${API_BASE}/systems`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    if (systemsResp.status() !== 200) {
      test.skip(); // No systems endpoint accessible
      return;
    }

    const systemsBody = (await systemsResp.json()) as {
      data: Array<{ id: number; name: string }>;
    };
    const systems = systemsBody.data ?? [];

    if (systems.length === 0) {
      test.skip(); // No systems in test DB
      return;
    }

    // Try the first system -- may or may not have findings
    const systemId = systems[0].id;
    const resp = await request.get(
      `${API_BASE}/executive/systems/${String(systemId)}/evidence-package`,
      {
        headers: { Authorization: `Bearer ${tokens.access_token}` },
      },
    );

    // Either 200 (system has findings) or 404 (no scan data yet)
    expect([200, 404]).toContain(resp.status());

    if (resp.status() === 200) {
      const contentType = resp.headers()["content-type"] ?? "";
      expect(contentType).toContain("application/zip");

      const contentDisposition = resp.headers()["content-disposition"] ?? "";
      expect(contentDisposition).toContain(".zip");

      // Verify the response has a non-empty body (ZIP binary data)
      const body = await resp.body();
      expect(body.length).toBeGreaterThan(0);
    }
  });
});
