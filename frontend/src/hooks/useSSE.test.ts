/**
 * useSSE.test.ts — unit tests for the useSSE hook (D-08 approach).
 *
 * useSSE connects to a real SSE endpoint with fetch + AbortController.
 * Testing the internal fetch streaming loop requires a live SSE server,
 * which is not available in unit test context.
 *
 * Per D-08: we test observable state machine outputs only:
 *   1. Initial state is "disconnected"
 *   2. When enabled=false, status stays "disconnected" and onStatusChange fires
 *   3. When enabled=true and fetch rejects, hook transitions through "connecting"
 *   4. AbortController.abort() is called on unmount
 *
 * The core streaming loop is covered by E2E (tests/e2e/notifications/sse-endpoint.spec.ts).
 */
import { renderHook, act } from "@testing-library/react";
import { describe, it, expect, vi, afterEach } from "vitest";

// ---------------------------------------------------------------------------
// Mock dependencies before hook import
// ---------------------------------------------------------------------------

vi.mock("@platform/api/http", () => ({
  buildApiUrl: (url: string) => `http://localhost:8000${url}`,
}));

vi.mock("@platform/auth/useAuthStore", () => ({
  useAuthStore: (selector: (s: { getAccessToken: () => Promise<string> }) => unknown) =>
    selector({ getAccessToken: async () => "mock-token" }),
}));

import { useSSE } from "./useSSE";

describe("useSSE", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  it("initial status is 'disconnected'", () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("no network")));
    const { result } = renderHook(() =>
      useSSE({ url: "/events", enabled: false, onEvent: vi.fn() }),
    );
    expect(result.current).toBe("disconnected");
  });

  it("stays 'disconnected' when enabled=false", () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("no network")));
    const { result } = renderHook(() =>
      useSSE({ url: "/events", enabled: false, onEvent: vi.fn() }),
    );
    expect(result.current).toBe("disconnected");
  });

  it("calls onStatusChange('disconnected') immediately when enabled=false", () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("no network")));
    const onStatusChange = vi.fn();
    renderHook(() =>
      useSSE({
        url: "/events",
        enabled: false,
        onEvent: vi.fn(),
        onStatusChange,
      }),
    );
    expect(onStatusChange).toHaveBeenCalledWith("disconnected");
  });

  it("transitions to 'connecting' when enabled=true (fetch mocked to reject)", async () => {
    // fetch resolves slowly — enough for connect() to transition to "connecting"
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(
        () => new Promise((_resolve, reject) => setTimeout(() => reject(new Error("no network")), 50)),
      ),
    );
    vi.useFakeTimers();

    const statusHistory: string[] = [];
    renderHook(() =>
      useSSE({
        url: "/events",
        enabled: true,
        onEvent: vi.fn(),
        onStatusChange: (s) => statusHistory.push(s),
      }),
    );

    // Allow the async connect() microtask to set "connecting" status
    await act(async () => {
      await Promise.resolve(); // flush microtasks
    });

    expect(statusHistory).toContain("connecting");
  });

  it("calls abort on unmount when a connection was attempted", async () => {
    const abortSpy = vi.fn();

    // Create a proper class constructor for AbortController
    class MockAbortController {
      abort = abortSpy;
      signal = {} as AbortSignal;
    }
    vi.stubGlobal("AbortController", MockAbortController);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(
        () => new Promise((_resolve, reject) => setTimeout(() => reject(new Error("no network")), 100)),
      ),
    );
    vi.useFakeTimers();

    const { unmount } = renderHook(() =>
      useSSE({ url: "/events", enabled: true, onEvent: vi.fn() }),
    );

    // Let connect() start and set abortRef.current
    await act(async () => {
      await Promise.resolve();
    });

    unmount();
    expect(abortSpy).toHaveBeenCalled();
  });

  it("does not call fetch when enabled=false", () => {
    const fetchMock = vi.fn().mockRejectedValue(new Error("no network"));
    vi.stubGlobal("fetch", fetchMock);

    renderHook(() =>
      useSSE({ url: "/events", enabled: false, onEvent: vi.fn() }),
    );

    expect(fetchMock).not.toHaveBeenCalled();
  });
});
