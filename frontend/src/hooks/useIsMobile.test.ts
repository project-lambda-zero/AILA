/**
 * useIsMobile.test.ts — unit tests for the useIsMobile hook.
 *
 * Tests the 768px breakpoint logic using jsdom's window.innerWidth
 * and a stubbed window.matchMedia (jsdom does not implement matchMedia natively).
 */
import { renderHook, act } from "@testing-library/react";
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

import { useIsMobile } from "./use-mobile";

// ---------------------------------------------------------------------------
// matchMedia mock factory
// jsdom does not implement window.matchMedia — we stub it globally per test.
// ---------------------------------------------------------------------------

function mockMatchMedia(innerWidth: number) {
  const mobile = innerWidth < 768;
  const listeners = new Set<() => void>();

  const mql = {
    matches: mobile,
    media: `(max-width: 767px)`,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn((_event: string, handler: () => void) => {
      listeners.add(handler);
    }),
    removeEventListener: vi.fn((_event: string, handler: () => void) => {
      listeners.delete(handler);
    }),
    dispatchEvent: vi.fn(),
  };

  return {
    mql,
    triggerChange: () => listeners.forEach((fn) => fn()),
  };
}

describe("useIsMobile", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns false when window.innerWidth is 1024 (above 768)", () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1024 });
    const { mql } = mockMatchMedia(1024);
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue(mql));

    const { result } = renderHook(() => useIsMobile());
    expect(result.current).toBe(false);
  });

  it("returns true when window.innerWidth is 375 (below 768)", () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 375 });
    const { mql } = mockMatchMedia(375);
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue(mql));

    const { result } = renderHook(() => useIsMobile());
    expect(result.current).toBe(true);
  });

  it("returns false at exactly 768px (boundary is not mobile)", () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 768 });
    const { mql } = mockMatchMedia(768);
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue(mql));

    const { result } = renderHook(() => useIsMobile());
    expect(result.current).toBe(false);
  });

  it("updates to true when resize triggers matchMedia change listener", () => {
    // Start as desktop
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1024 });
    const { mql, triggerChange } = mockMatchMedia(1024);
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue(mql));

    const { result } = renderHook(() => useIsMobile());
    expect(result.current).toBe(false);

    act(() => {
      // Simulate window resize to mobile
      Object.defineProperty(window, "innerWidth", { configurable: true, value: 375 });
      triggerChange();
    });

    expect(result.current).toBe(true);
  });

  it("removes matchMedia event listener on unmount", () => {
    Object.defineProperty(window, "innerWidth", { configurable: true, value: 1024 });
    const { mql } = mockMatchMedia(1024);
    vi.stubGlobal("matchMedia", vi.fn().mockReturnValue(mql));

    const { unmount } = renderHook(() => useIsMobile());
    unmount();

    expect(mql.removeEventListener).toHaveBeenCalledWith("change", expect.any(Function));
  });
});
