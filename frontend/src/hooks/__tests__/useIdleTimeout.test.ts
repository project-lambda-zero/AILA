import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useIdleTimeout } from "@/hooks/useIdleTimeout";

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

describe("useIdleTimeout (#47)", () => {
  it("fires onIdle after the configured timeout with no activity", () => {
    const onIdle = vi.fn();
    renderHook(() => useIdleTimeout({ onIdle, timeoutMs: 1_000 }));

    act(() => {
      vi.advanceTimersByTime(999);
    });
    expect(onIdle).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(2);
    });
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it("resets the timer when a presence event fires", () => {
    const onIdle = vi.fn();
    renderHook(() => useIdleTimeout({ onIdle, timeoutMs: 1_000 }));

    act(() => {
      vi.advanceTimersByTime(700);
    });
    act(() => {
      window.dispatchEvent(new Event("keydown"));
    });
    act(() => {
      vi.advanceTimersByTime(700);
    });
    // Total elapsed 1400ms but keydown at 700ms reset the timer to
    // t=700 -> deadline t=1700; we are only at t=1400 -> no fire yet.
    expect(onIdle).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(400);
    });
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it("fires at most once even if presence events arrive after the fire", () => {
    const onIdle = vi.fn();
    renderHook(() => useIdleTimeout({ onIdle, timeoutMs: 500 }));

    act(() => {
      vi.advanceTimersByTime(600);
    });
    expect(onIdle).toHaveBeenCalledTimes(1);

    act(() => {
      window.dispatchEvent(new Event("keydown"));
      vi.advanceTimersByTime(2_000);
    });
    expect(onIdle).toHaveBeenCalledTimes(1);
  });

  it("does not attach listeners when disabled", () => {
    const onIdle = vi.fn();
    const addSpy = vi.spyOn(window, "addEventListener");
    renderHook(() =>
      useIdleTimeout({ onIdle, timeoutMs: 100, enabled: false }),
    );
    // No presence-event listeners registered.
    for (const call of addSpy.mock.calls) {
      const name = call[0];
      expect([
        "pointerdown",
        "pointermove",
        "keydown",
        "scroll",
        "touchstart",
        "visibilitychange",
      ]).not.toContain(name);
    }
    act(() => {
      vi.advanceTimersByTime(10_000);
    });
    expect(onIdle).not.toHaveBeenCalled();
  });

  it("removes its listeners on unmount", () => {
    const onIdle = vi.fn();
    const removeSpy = vi.spyOn(window, "removeEventListener");
    const { unmount } = renderHook(() =>
      useIdleTimeout({ onIdle, timeoutMs: 1_000 }),
    );
    unmount();
    // One removeEventListener per PRESENCE_EVENTS entry.
    expect(removeSpy).toHaveBeenCalledTimes(6);
  });
});
