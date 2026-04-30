/**
 * fixtures.ts — Phase 176a Playwright fixtures.
 *
 * Composed via test.extend so every spec can pull `authedPage` plus a
 * per-test `namespace` string and the optional seedTasks/seedReports
 * helpers without re-implementing auth + isolation each time.
 */
import {
  test as base,
  request as playwrightRequest,
  type APIRequestContext,
  type Page,
} from "@playwright/test";

import { getTokens, injectAuthState, type TokenPair } from "../../helpers/auth";
import {
  getNamespace,
  pingApi,
  seedTasks,
  teardownNamespace,
  type SeededTaskIds,
  type TaskStatus,
} from "./db-seed";

interface WorkerFixtures {
  /** Worker-scoped TokenPair — one login per Playwright worker (avoids 429 from
   *  the auth rate limiter while still hitting the real /auth/login endpoint). */
  tokens: TokenPair;
}

interface TestFixtures {
  /** Per-test namespace for seeded data. */
  namespace: string;
  /** Page already pre-loaded with auth state. */
  authedPage: Page;
  /** Async seed callback; pass the statuses you actually need. */
  seedTasks: (statuses: TaskStatus[]) => Promise<SeededTaskIds>;
  /** API request context bound to the auth token. */
  apiContext: APIRequestContext;
}

async function getTokensWithBackoff(
  request: APIRequestContext,
): Promise<TokenPair> {
  let lastErr: unknown = null;
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      return await getTokens(request);
    } catch (err) {
      lastErr = err;
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("429") || /rate limit/i.test(msg)) {
        // Auth rate limiter is 10/min — wait a bit and retry.
        await new Promise((r) => setTimeout(r, 7_000 * (attempt + 1)));
        continue;
      }
      throw err;
    }
  }
  throw lastErr ?? new Error("getTokens: exhausted retries");
}

export const test = base.extend<TestFixtures, WorkerFixtures>({
  // ── worker-scoped ──
  // Worker fixtures cannot depend on the per-test `request`; build our own
  // APIRequestContext with the Playwright top-level `request` factory.
  tokens: [
    async ({}, use) => {
      const ctx = await playwrightRequest.newContext();
      try {
        const reachable = await pingApi(ctx);
        if (!reachable) {
          throw new Error(
            `Backend API not reachable — refusing to run e2e tests against an ` +
              `absent backend (no mock fallback per project rules).`,
          );
        }
        const t = await getTokensWithBackoff(ctx);
        await use(t);
      } finally {
        await ctx.dispose();
      }
    },
    { scope: "worker" },
  ],

  // ── test-scoped ──
  namespace: async ({}, use, testInfo) => {
    await use(getNamespace(testInfo));
  },

  authedPage: async ({ page, tokens }, use) => {
    await injectAuthState(page, tokens);
    await use(page);
  },

  apiContext: async ({ request }, use) => {
    await use(request);
  },

  seedTasks: async ({ apiContext, tokens, namespace }, use) => {
    const seedFn = async (statuses: TaskStatus[]) => {
      return await seedTasks(apiContext, tokens, namespace, statuses);
    };
    await use(seedFn);
    await teardownNamespace(apiContext, tokens, namespace);
  },
});

export { expect } from "@playwright/test";
