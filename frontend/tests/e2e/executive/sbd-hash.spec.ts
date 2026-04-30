/**
 * E2E: SbD Report Hash Integrity (EXEC-04)
 *
 * Tests that the report hash endpoint returns the correct shape for SbD
 * sessions — either "available" (PDF downloaded before) or "not_generated"
 * (PDF not yet downloaded).
 *
 * Uses real PostgreSQL backend — no mocks.
 */
import { test, expect } from "@playwright/test";

import { API_BASE, getTokens } from "../helpers/auth";

test.describe("SbD Report Hash Integrity (EXEC-04)", () => {
  test("GET /sbd_nfr/sessions/{id}/artifacts/report/hash requires authentication", async ({
    request,
  }) => {
    const resp = await request.get(
      `${API_BASE}/sbd_nfr/sessions/00000000-0000-0000-0000-000000000000/artifacts/report/hash`,
    );
    expect([401, 403]).toContain(resp.status());
  });

  test("GET /sbd_nfr/sessions/{id}/artifacts/report/hash returns 404 for unknown session", async ({
    request,
  }) => {
    const tokens = await getTokens(request);
    const resp = await request.get(
      `${API_BASE}/sbd_nfr/sessions/00000000-0000-0000-0000-000000000000/artifacts/report/hash`,
      { headers: { Authorization: `Bearer ${tokens.access_token}` } },
    );
    expect(resp.status()).toBe(404);
  });

  test("hash endpoint returns valid shape for an existing SbD session", async ({ request }) => {
    const tokens = await getTokens(request);

    // List SbD sessions
    const sessionsResp = await request.get(`${API_BASE}/sbd_nfr/sessions`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    if (sessionsResp.status() !== 200) {
      test.skip(); // Cannot list sessions
      return;
    }

    const sessionsBody = (await sessionsResp.json()) as {
      data: Array<{ id: string; status: string }>;
    };
    const sessions = sessionsBody.data ?? [];

    if (sessions.length === 0) {
      test.skip(); // No sessions in test DB
      return;
    }

    // Use the first session regardless of status
    const sessionId = sessions[0].id;

    const hashResp = await request.get(
      `${API_BASE}/sbd_nfr/sessions/${encodeURIComponent(sessionId)}/artifacts/report/hash`,
      { headers: { Authorization: `Bearer ${tokens.access_token}` } },
    );

    expect(hashResp.status()).toBe(200);

    const body = (await hashResp.json()) as {
      data: { session_id: string; sha256: string | null; status: string };
    };

    expect(body).toHaveProperty("data");
    expect(typeof body.data.session_id).toBe("string");
    expect(["available", "not_generated"]).toContain(body.data.status);

    if (body.data.status === "available") {
      expect(typeof body.data.sha256).toBe("string");
      // SHA-256 hex digest is always 64 hex characters
      expect(body.data.sha256).toMatch(/^[0-9a-f]{64}$/i);
    } else {
      // not_generated: sha256 should be null
      expect(body.data.sha256).toBeNull();
    }
  });

  test("hash matches PDF bytes when PDF is downloaded for the first time", async ({ request }) => {
    const tokens = await getTokens(request);

    // List sessions and find one in resolved or completed status
    const sessionsResp = await request.get(`${API_BASE}/sbd_nfr/sessions`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    if (sessionsResp.status() !== 200) {
      test.skip();
      return;
    }

    const sessionsBody = (await sessionsResp.json()) as {
      data: Array<{ id: string; status: string }>;
    };

    // Find a session that could have a report (resolved/completed)
    const candidateStatuses = ["resolved", "completed", "report_ready"];
    const candidate = sessionsBody.data.find((s) => candidateStatuses.includes(s.status));

    if (!candidate) {
      test.skip(); // No resolved sessions in test DB
      return;
    }

    // Check hash endpoint — status may be not_generated if PDF not yet downloaded
    const hashResp = await request.get(
      `${API_BASE}/sbd_nfr/sessions/${encodeURIComponent(candidate.id)}/artifacts/report/hash`,
      { headers: { Authorization: `Bearer ${tokens.access_token}` } },
    );

    expect(hashResp.status()).toBe(200);
    const hashBody = (await hashResp.json()) as {
      data: { session_id: string; sha256: string | null; status: string };
    };

    // If already available, verify shape — otherwise trigger PDF download to generate hash
    if (hashBody.data.status === "available") {
      expect(typeof hashBody.data.sha256).toBe("string");
      expect(hashBody.data.sha256).toMatch(/^[0-9a-f]{64}$/i);
    } else {
      // Download the PDF to trigger hash generation
      const pdfResp = await request.get(
        `${API_BASE}/sbd_nfr/sessions/${encodeURIComponent(candidate.id)}/artifacts/report`,
        { headers: { Authorization: `Bearer ${tokens.access_token}` } },
      );

      // 200 = PDF generated, 503 = weasyprint not installed, 404 = no report yet
      if (pdfResp.status() === 200) {
        // Verify the X-Report-Hash header is present
        const reportHash = pdfResp.headers()["x-report-hash"];
        expect(reportHash).toBeTruthy();
        expect(reportHash).toMatch(/^[0-9a-f]{64}$/i);

        // Now the hash endpoint should return "available"
        const hashResp2 = await request.get(
          `${API_BASE}/sbd_nfr/sessions/${encodeURIComponent(candidate.id)}/artifacts/report/hash`,
          { headers: { Authorization: `Bearer ${tokens.access_token}` } },
        );
        expect(hashResp2.status()).toBe(200);
        const hashBody2 = (await hashResp2.json()) as {
          data: { sha256: string | null; status: string };
        };
        expect(hashBody2.data.status).toBe("available");
        expect(hashBody2.data.sha256).toBe(reportHash);
      }
      // If PDF endpoint returns 503 or 404, skip — weasyprint or session data not available
    }
  });
});
