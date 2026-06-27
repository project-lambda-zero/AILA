/**
 * useRecentlyViewed.test.ts -- unit tests for the useRecentlyViewed hook.
 *
 * Tests localStorage CRUD, excluded paths, deduplication, MAX_ITEMS cap,
 * path-to-label conversion, and clearRecent.
 *
 * Wraps the hook in MemoryRouter because it depends on useLocation.
 */
import { renderHook, act } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, it, expect, beforeEach } from "vitest";
import React from "react";

import { useRecentlyViewed } from "./useRecentlyViewed";

const STORAGE_KEY = "aila-recently-viewed";
const MAX_ITEMS = 5;

// ---------------------------------------------------------------------------
// Helper: render hook inside MemoryRouter at a given initial path
// ---------------------------------------------------------------------------

function renderAtPath(initialPath: string) {
  return renderHook(() => useRecentlyViewed(), {
    wrapper: ({ children }: { children: React.ReactNode }) =>
      React.createElement(MemoryRouter, { initialEntries: [initialPath] }, children),
  });
}

describe("useRecentlyViewed", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("starts with items already in localStorage on init", () => {
    const existing = [
      { path: "/systems", label: "Systems", visitedAt: Date.now() - 1000 },
    ];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));

    const { result } = renderAtPath("/systems");
    // The hook records /systems on mount, so it will still be there
    expect(result.current.items.some((i) => i.path === "/systems")).toBe(true);
  });

  it("records a visit when location is a non-excluded path", () => {
    const { result } = renderAtPath("/systems");
    expect(result.current.items.some((i) => i.path === "/systems")).toBe(true);
  });

  it("skips the /login excluded path", () => {
    const { result } = renderAtPath("/login");
    expect(result.current.items.some((i) => i.path === "/login")).toBe(false);
  });

  it("skips the /403 excluded path", () => {
    const { result } = renderAtPath("/403");
    expect(result.current.items.every((i) => i.path !== "/403")).toBe(true);
  });

  it("skips the /404 excluded path", () => {
    const { result } = renderAtPath("/404");
    expect(result.current.items.every((i) => i.path !== "/404")).toBe(true);
  });

  it("skips the /500 excluded path", () => {
    const { result } = renderAtPath("/500");
    expect(result.current.items.every((i) => i.path !== "/500")).toBe(true);
  });

  it("skips the /auth/callback excluded path", () => {
    const { result } = renderAtPath("/auth/callback");
    expect(result.current.items.every((i) => i.path !== "/auth/callback")).toBe(true);
  });

  it("deduplicates by path -- same path does not appear twice", () => {
    // Seed localStorage with one /systems entry
    const existing = [
      { path: "/systems", label: "Systems", visitedAt: Date.now() - 5000 },
    ];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));

    // Re-visit /systems
    const { result } = renderAtPath("/systems");
    const systemsCount = result.current.items.filter((i) => i.path === "/systems").length;
    expect(systemsCount).toBe(1);
  });

  it(`caps at MAX_ITEMS (${MAX_ITEMS})`, () => {
    // Seed localStorage with MAX_ITEMS entries
    const existing = Array.from({ length: MAX_ITEMS }, (_, idx) => ({
      path: `/page-${idx}`,
      label: `Page ${idx}`,
      visitedAt: Date.now() - idx * 1000,
    }));
    localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));

    const { result } = renderAtPath("/systems");
    // After adding /systems the total should not exceed MAX_ITEMS
    expect(result.current.items.length).toBeLessThanOrEqual(MAX_ITEMS);
  });

  it("clearRecent empties the items list", () => {
    const existing = [
      { path: "/systems", label: "Systems", visitedAt: Date.now() },
    ];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));

    const { result } = renderAtPath("/systems");
    expect(result.current.items.length).toBeGreaterThan(0);

    act(() => {
      result.current.clearRecent();
    });

    expect(result.current.items).toHaveLength(0);
  });

  it("clearRecent removes the localStorage entry", () => {
    const existing = [
      { path: "/systems", label: "Systems", visitedAt: Date.now() },
    ];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));

    const { result } = renderAtPath("/systems");

    act(() => {
      result.current.clearRecent();
    });

    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// pathToLabel -- test via the hook's label output
// ---------------------------------------------------------------------------

describe("useRecentlyViewed -- label generation", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("generates label 'Dashboard' for /", () => {
    const { result } = renderHook(() => useRecentlyViewed(), {
      wrapper: ({ children }: { children: React.ReactNode }) =>
        React.createElement(MemoryRouter, { initialEntries: ["/"] }, children),
    });
    const dashboardItem = result.current.items.find((i) => i.path === "/");
    expect(dashboardItem?.label).toBe("Dashboard");
  });

  it("generates label 'Systems' for /systems", () => {
    const { result } = renderAtPath("/systems");
    const item = result.current.items.find((i) => i.path === "/systems");
    expect(item?.label).toBe("Systems");
  });

  it("generates label 'Systems / Detail' for /systems/42", () => {
    const { result } = renderHook(() => useRecentlyViewed(), {
      wrapper: ({ children }: { children: React.ReactNode }) =>
        React.createElement(MemoryRouter, { initialEntries: ["/systems/42"] }, children),
    });
    const item = result.current.items.find((i) => i.path === "/systems/42");
    expect(item?.label).toBe("Systems / Detail");
  });

  it("generates label 'Admin' for /admin", () => {
    const { result } = renderHook(() => useRecentlyViewed(), {
      wrapper: ({ children }: { children: React.ReactNode }) =>
        React.createElement(MemoryRouter, { initialEntries: ["/admin"] }, children),
    });
    const item = result.current.items.find((i) => i.path === "/admin");
    expect(item?.label).toBe("Admin");
  });
});
