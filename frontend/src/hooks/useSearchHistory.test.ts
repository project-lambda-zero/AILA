/**
 * useSearchHistory.test.ts — unit tests for the useSearchHistory hook.
 *
 * Tests localStorage persistence, deduplication, MAX_ITEMS cap, and clearing.
 * Uses jsdom localStorage (cleared in afterEach via test/setup.ts).
 */
import { renderHook, act } from "@testing-library/react";
import { describe, it, expect, beforeEach } from "vitest";

import { useSearchHistory } from "./useSearchHistory";

const STORAGE_KEY = "aila-search-history";
const MAX_ITEMS = 10;

describe("useSearchHistory", () => {
  beforeEach(() => {
    localStorage.clear();
  });

  it("starts empty when localStorage is clear", () => {
    const { result } = renderHook(() => useSearchHistory());
    expect(result.current.items).toHaveLength(0);
  });

  it("addSearch adds a query to history", () => {
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      result.current.addSearch("CVE-2024-1234");
    });

    expect(result.current.items).toHaveLength(1);
    expect(result.current.items[0].query).toBe("CVE-2024-1234");
  });

  it("addSearch stores query with a numeric searchedAt timestamp", () => {
    const before = Date.now();
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      result.current.addSearch("test query");
    });

    const after = Date.now();
    expect(result.current.items[0].searchedAt).toBeGreaterThanOrEqual(before);
    expect(result.current.items[0].searchedAt).toBeLessThanOrEqual(after);
  });

  it("addSearch deduplicates case-insensitively (same query moves to front)", () => {
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      result.current.addSearch("apache");
      result.current.addSearch("nginx");
      result.current.addSearch("Apache"); // duplicate of "apache"
    });

    // "Apache" should be first, "apache" removed, "nginx" second
    expect(result.current.items).toHaveLength(2);
    expect(result.current.items[0].query).toBe("Apache");
    expect(result.current.items[1].query).toBe("nginx");
  });

  it("addSearch ignores whitespace-only queries", () => {
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      result.current.addSearch("   ");
    });

    expect(result.current.items).toHaveLength(0);
  });

  it("addSearch trims whitespace from queries", () => {
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      result.current.addSearch("  CVE-2024-99  ");
    });

    expect(result.current.items[0].query).toBe("CVE-2024-99");
  });

  it(`addSearch caps history at MAX_ITEMS (${MAX_ITEMS})`, () => {
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      for (let i = 0; i < MAX_ITEMS + 5; i++) {
        result.current.addSearch(`query-${i}`);
      }
    });

    expect(result.current.items).toHaveLength(MAX_ITEMS);
  });

  it("most recent query is always first", () => {
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      result.current.addSearch("first");
      result.current.addSearch("second");
      result.current.addSearch("third");
    });

    expect(result.current.items[0].query).toBe("third");
  });

  it("clearHistory empties the list", () => {
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      result.current.addSearch("query-one");
      result.current.addSearch("query-two");
    });
    expect(result.current.items).toHaveLength(2);

    act(() => {
      result.current.clearHistory();
    });

    expect(result.current.items).toHaveLength(0);
  });

  it("clearHistory removes the localStorage entry", () => {
    const { result } = renderHook(() => useSearchHistory());

    act(() => {
      result.current.addSearch("stored");
    });
    expect(localStorage.getItem(STORAGE_KEY)).not.toBeNull();

    act(() => {
      result.current.clearHistory();
    });

    expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
  });

  it("persists across hook unmount/remount via localStorage", () => {
    const { result: r1, unmount } = renderHook(() => useSearchHistory());

    act(() => {
      r1.current.addSearch("persistent-query");
    });
    unmount();

    // New instance reads from localStorage
    const { result: r2 } = renderHook(() => useSearchHistory());
    expect(r2.current.items[0].query).toBe("persistent-query");
  });

  it("loads existing items from localStorage on init", () => {
    const existing = [
      { query: "preloaded-search", searchedAt: Date.now() },
    ];
    localStorage.setItem(STORAGE_KEY, JSON.stringify(existing));

    const { result } = renderHook(() => useSearchHistory());
    expect(result.current.items[0].query).toBe("preloaded-search");
  });
});
