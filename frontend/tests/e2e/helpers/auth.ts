/**
 * auth.ts -- shared E2E auth helpers
 *
 * Provides getTokens() and injectAuthState() used across all E2E test suites.
 * Uses real PostgreSQL backend -- no mocks.
 */
import type { APIRequestContext, Page } from "@playwright/test";

export const API_BASE = "http://127.0.0.1:8000";
export const TEST_USERNAME = process.env.E2E_USERNAME ?? "admin";
export const TEST_PASSWORD = process.env.E2E_PASSWORD ?? "admin";

export interface TokenPair {
  access_token: string;
  refresh_token: string;
}

export async function getTokens(request: APIRequestContext): Promise<TokenPair> {
  const resp = await request.post(`${API_BASE}/auth/login`, {
    data: { username: TEST_USERNAME, password: TEST_PASSWORD },
  });
  if (!resp.ok()) {
    throw new Error(`Login failed: ${resp.status()} ${await resp.text()}`);
  }
  const body = (await resp.json()) as { data: TokenPair };
  return body.data;
}

/** Inject Zustand auth state into localStorage so the React app picks it up on load. */
export async function injectAuthState(page: Page, tokens: TokenPair): Promise<void> {
  const payloadB64 = tokens.access_token.split(".")[1];
  const payload = JSON.parse(
    Buffer.from(payloadB64, "base64url").toString("utf-8"),
  ) as { user_id: string; role: string; exp: number };

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
