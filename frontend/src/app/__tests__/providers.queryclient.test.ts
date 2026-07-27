import { describe, expect, it, vi } from "vitest";

// Mock toast + SSE provider to avoid DOM-heavy side effects in the smoke test.
vi.mock("@/components/ui/sonner", () => ({
  toast: { error: vi.fn(), success: vi.fn(), info: vi.fn() },
  Toaster: () => null,
}));
vi.mock("@/providers/SSEProvider", () => ({ SSEProvider: ({ children }: { children: unknown }) => children }));
vi.mock("@/providers/ThemeProvider", () => ({ ThemeProvider: ({ children }: { children: unknown }) => children }));

import { makeQueryClient } from "@app/providers";
import { apiErrorHandler } from "@/lib/apiErrorHandler";

describe("QueryClient (TanStack v5 cache wiring)", () => {
  it("wires apiErrorHandler on QueryCache config.onError (FE-A v5 path)", () => {
    const client = makeQueryClient();
    const cacheCfg = client.getQueryCache().config;
    expect(cacheCfg.onError).toBe(apiErrorHandler);
  });

  it("wires apiErrorHandler on MutationCache config.onError", () => {
    const client = makeQueryClient();
    const cacheCfg = client.getMutationCache().config;
    expect(cacheCfg.onError).toBe(apiErrorHandler);
  });

  it("does NOT wire onError via defaultOptions.queries (gap-fix-02 #1)", () => {
    const client = makeQueryClient();
    const defaults = client.getDefaultOptions();
    // v5 removed defaultOptions.queries.onError -- confirm it's unset.
    expect((defaults.queries as { onError?: unknown } | undefined)?.onError).toBeUndefined();
  });

  it("preserves existing retry + refetchOnWindowFocus defaults", () => {
    const client = makeQueryClient();
    const defaults = client.getDefaultOptions();
    expect(defaults.queries?.retry).toBe(1);
    expect(defaults.queries?.refetchOnWindowFocus).toBe(false);
  });

  it("bounds the cache with an explicit gcTime + staleTime (#47)", () => {
    const client = makeQueryClient();
    const defaults = client.getDefaultOptions();
    // The cache MUST NOT grow indefinitely; anything under 10 minutes is
    // an acceptable bound for the security posture that motivated this.
    const gcTime = defaults.queries?.gcTime;
    expect(typeof gcTime).toBe("number");
    expect(gcTime).toBeGreaterThan(0);
    expect(gcTime).toBeLessThanOrEqual(10 * 60 * 1000);
    // Similarly, a bounded staleTime prevents indefinite serve-from-cache
    // of a value that a caller did not explicitly opt into pinning.
    const staleTime = defaults.queries?.staleTime;
    expect(typeof staleTime).toBe("number");
    expect(staleTime).toBeGreaterThan(0);
  });
});
