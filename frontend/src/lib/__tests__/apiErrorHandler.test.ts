import { describe, expect, it, vi, beforeEach } from "vitest";

// Mock the sonner wrapper BEFORE importing apiErrorHandler so the handler
// picks up the vi.fn() implementation.
const toastError = vi.fn();
vi.mock("@/components/ui/sonner", () => ({
  toast: {
    error: (...args: unknown[]) => toastError(...args),
    // unused in tests but part of the shadcn sonner wrapper surface
    success: vi.fn(),
    info: vi.fn(),
  },
  Toaster: () => null,
}));

// Mock useAuthStore so the 401 branch can be exercised without a real
// zustand store (and without triggering the location.assign redirect on
// a jsdom window we cannot pre-set safely).
const logout = vi.fn();
vi.mock("@platform/auth/useAuthStore", () => ({
  useAuthStore: {
    getState: () => ({ logout }),
  },
}));

import { apiErrorHandler } from "@/lib/apiErrorHandler";

beforeEach(() => {
  toastError.mockReset();
});

describe("apiErrorHandler", () => {
  it("renders message + hint + trace_id when an envelope is given directly", () => {
    apiErrorHandler({
      code: "MISSING_API_KEY",
      message: "no key configured",
      hint: "Go to Admin → API Keys",
      trace_id: "abc-trace",
    });

    expect(toastError).toHaveBeenCalledTimes(1);
    const [msg, opts] = toastError.mock.calls[0];
    expect(msg).toBe("no key configured");
    expect(opts.description).toContain("Go to Admin → API Keys");
    expect(opts.description).toContain("trace_id: abc-trace");
  });

  it("renders envelope from response.data (Axios-style)", () => {
    apiErrorHandler({
      response: {
        data: {
          code: "X",
          message: "wrapped",
          hint: null,
          trace_id: "t-x",
        },
      },
    });
    const [msg] = toastError.mock.calls[0];
    expect(msg).toBe("wrapped");
  });

  it("renders fallback 'Contact support' line when trace_id is null (D-26)", () => {
    apiErrorHandler({
      code: "Y",
      message: "oops",
      hint: null,
      trace_id: null,
    });
    const [, opts] = toastError.mock.calls[0];
    expect(opts.description).toMatch(/Contact support/);
    expect(opts.description).toMatch(/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
  });

  it("never surfaces the literal 'Internal Server Error' (D-10c)", () => {
    apiErrorHandler(new Error("Internal Server Error"));
    const [msg] = toastError.mock.calls[0];
    expect(msg).not.toBe("Internal Server Error");
    expect(String(msg)).not.toMatch(/Internal Server Error/);
  });

  it("shows offline message for TypeError 'Failed to fetch'", () => {
    apiErrorHandler(new TypeError("Failed to fetch"));
    const [msg] = toastError.mock.calls[0];
    expect(msg).toMatch(/Network request failed/);
  });

  it("swallows internal failures instead of rethrowing", () => {
    toastError.mockImplementationOnce(() => {
      throw new Error("toast exploded");
    });
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    expect(() => apiErrorHandler(new Error("something"))).not.toThrow();
    expect(consoleError).toHaveBeenCalled();
    consoleError.mockRestore();
  });

  it("uses Error.message for non-envelope Errors", () => {
    apiErrorHandler(new Error("some regular error"));
    const [msg] = toastError.mock.calls[0];
    expect(msg).toBe("some regular error");
  });

  // ---- #47: 401 clears the session, 403 does NOT ------------------------

  it("logs out on a 401 status (session invalid)", async () => {
    apiErrorHandler({ status: 401, message: "Unauthorized" });
    // The logout is scheduled from an inner async IIFE; flush microtasks.
    await Promise.resolve();
    await Promise.resolve();
    expect(logout).toHaveBeenCalledTimes(1);
    // A 401 short-circuits toast rendering -- it navigates instead.
    expect(toastError).not.toHaveBeenCalled();
  });

  it("does NOT log out on a 403 status (permission denied on live session)", async () => {
    apiErrorHandler({
      status: 403,
      code: "FORBIDDEN",
      message: "You lack the admin role for this operation",
      hint: null,
      trace_id: null,
    });
    await Promise.resolve();
    await Promise.resolve();
    expect(logout).not.toHaveBeenCalled();
    // The user sees a real error toast instead.
    expect(toastError).toHaveBeenCalledTimes(1);
    const [msg] = toastError.mock.calls[0];
    expect(msg).toBe("You lack the admin role for this operation");
  });

  it("still logs out on an auth-phrased error even without a status", async () => {
    apiErrorHandler({ message: "invalid token" });
    await Promise.resolve();
    await Promise.resolve();
    expect(logout).toHaveBeenCalledTimes(1);
  });
});
