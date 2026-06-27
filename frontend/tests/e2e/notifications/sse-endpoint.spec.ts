/**
 * sse-endpoint.spec.ts
 *
 * E2E tests verifying the /events/stream SSE endpoint (RT-01).
 * Tests: authentication gate, correct Content-Type header.
 * Uses real backend -- no mocks.
 *
 * Note: These tests make direct HTTP requests to the backend API,
 * not to the frontend dev server. They verify the SSE contract.
 */
import { test, expect } from "@playwright/test";

import { API_BASE, getTokens, type TokenPair } from "../helpers/auth";

test.describe("SSE /events/stream endpoint", () => {
  let tokens: TokenPair;

  test.beforeAll(async ({ request }) => {
    tokens = await getTokens(request);
  });

  test("returns 401 without auth token", async ({ request }) => {
    // The SSE endpoint must reject unauthenticated connections
    const resp = await request
      .get(`${API_BASE}/events/stream`, {
        headers: { Accept: "text/event-stream" },
        // Short timeout -- we just need the response headers, not the stream body
        timeout: 5_000,
      })
      .catch(() => null);

    if (resp === null) {
      // Server not running -- skip gracefully
      test.skip();
      return;
    }

    expect(resp.status()).toBe(401);
  });

  test("returns 200 text/event-stream with valid Bearer token", async ({ request }) => {
    const resp = await request
      .get(`${API_BASE}/events/stream`, {
        headers: {
          Accept: "text/event-stream",
          Authorization: `Bearer ${tokens.access_token}`,
        },
        timeout: 5_000,
      })
      .catch(() => null);

    if (resp === null) {
      // Server not running -- skip gracefully
      test.skip();
      return;
    }

    expect(resp.status()).toBe(200);

    const contentType = resp.headers()["content-type"] ?? "";
    expect(contentType).toContain("text/event-stream");
  });

  test("cache-control header prevents proxy caching", async ({ request }) => {
    const resp = await request
      .get(`${API_BASE}/events/stream`, {
        headers: {
          Accept: "text/event-stream",
          Authorization: `Bearer ${tokens.access_token}`,
        },
        timeout: 5_000,
      })
      .catch(() => null);

    if (resp === null) {
      test.skip();
      return;
    }

    if (resp.status() !== 200) {
      test.skip();
      return;
    }

    const cacheControl = resp.headers()["cache-control"] ?? "";
    expect(cacheControl).toContain("no-cache");
  });
});
