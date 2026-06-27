/**
 * useOnlineStatus.test.ts -- unit tests for the useOnlineStatus hook.
 *
 * Tests navigator.onLine tracking and localStorage lastSyncTime reading.
 * Uses jsdom environment (configured in vitest.config.ts).
 */
import { renderHook, act } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { useOnlineStatus } from "./useOnlineStatus";

describe("useOnlineStatus", () => {
  const originalNavigatorOnLine = Object.getOwnPropertyDescriptor(Navigator.prototype, "onLine");

  function mockOnLine(value: boolean) {
    Object.defineProperty(navigator, "onLine", {
      configurable: true,
      get: () => value,
    });
  }

  beforeEach(() => {
    localStorage.clear();
  });

  afterEach(() => {
    // Restore original descriptor if it existed
    if (originalNavigatorOnLine) {
      Object.defineProperty(Navigator.prototype, "onLine", originalNavigatorOnLine);
    }
  });

  it("returns isOnline=true when navigator.onLine is true", () => {
    mockOnLine(true);
    const { result } = renderHook(() => useOnlineStatus());
    expect(result.current.isOnline).toBe(true);
  });

  it("returns isOnline=false when navigator.onLine is false", () => {
    mockOnLine(false);
    const { result } = renderHook(() => useOnlineStatus());
    expect(result.current.isOnline).toBe(false);
  });

  it("updates isOnline=false when offline event fires", () => {
    mockOnLine(true);
    const { result } = renderHook(() => useOnlineStatus());
    expect(result.current.isOnline).toBe(true);

    act(() => {
      window.dispatchEvent(new Event("offline"));
    });

    expect(result.current.isOnline).toBe(false);
  });

  it("updates isOnline=true when online event fires after going offline", () => {
    mockOnLine(false);
    const { result } = renderHook(() => useOnlineStatus());
    expect(result.current.isOnline).toBe(false);

    act(() => {
      window.dispatchEvent(new Event("online"));
    });

    expect(result.current.isOnline).toBe(true);
  });

  it("returns lastSyncTime=null when localStorage is empty", () => {
    const { result } = renderHook(() => useOnlineStatus());
    expect(result.current.lastSyncTime).toBeNull();
  });

  it("reads lastSyncTime from localStorage on init", () => {
    const syncTime = "2026-04-09T12:00:00Z";
    localStorage.setItem("aila-last-sync", syncTime);

    const { result } = renderHook(() => useOnlineStatus());
    expect(result.current.lastSyncTime).toBe(syncTime);
  });

  it("refreshes lastSyncTime when coming back online", () => {
    mockOnLine(false);
    const { result } = renderHook(() => useOnlineStatus());

    // Set sync time in localStorage while offline
    const syncTime = "2026-04-09T15:30:00Z";
    localStorage.setItem("aila-last-sync", syncTime);

    act(() => {
      window.dispatchEvent(new Event("online"));
    });

    expect(result.current.lastSyncTime).toBe(syncTime);
  });

  it("removes event listeners on unmount (no lingering handlers)", () => {
    const addSpy = vi.spyOn(window, "addEventListener");
    const removeSpy = vi.spyOn(window, "removeEventListener");

    const { unmount } = renderHook(() => useOnlineStatus());

    // Listeners added on mount
    expect(addSpy).toHaveBeenCalledWith("online", expect.any(Function));
    expect(addSpy).toHaveBeenCalledWith("offline", expect.any(Function));

    unmount();

    // Listeners removed on unmount
    expect(removeSpy).toHaveBeenCalledWith("online", expect.any(Function));
    expect(removeSpy).toHaveBeenCalledWith("offline", expect.any(Function));
  });
});
