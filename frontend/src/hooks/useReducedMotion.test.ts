/**
 * useReducedMotion.test.ts -- unit tests for the useReducedMotion hook.
 *
 * The hook wraps motion/react's useReducedMotion, normalizing null → false.
 * We mock the motion/react module to control the return value.
 */
import { renderHook } from "@testing-library/react";
import { describe, it, expect, vi, beforeEach } from "vitest";

// ---------------------------------------------------------------------------
// Mock motion/react before importing the hook
// ---------------------------------------------------------------------------

vi.mock("motion/react", () => ({
  useReducedMotion: vi.fn(),
}));

import { useReducedMotion } from "./useReducedMotion";
import * as motionReact from "motion/react";

describe("useReducedMotion", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("returns false when motion/react returns null (preference not set)", () => {
    vi.mocked(motionReact.useReducedMotion).mockReturnValue(null);
    const { result } = renderHook(() => useReducedMotion());
    expect(result.current).toBe(false);
  });

  it("returns false when motion/react returns false (motion is ok)", () => {
    vi.mocked(motionReact.useReducedMotion).mockReturnValue(false);
    const { result } = renderHook(() => useReducedMotion());
    expect(result.current).toBe(false);
  });

  it("returns true when motion/react returns true (user prefers reduced motion)", () => {
    vi.mocked(motionReact.useReducedMotion).mockReturnValue(true);
    const { result } = renderHook(() => useReducedMotion());
    expect(result.current).toBe(true);
  });

  it("always returns a boolean (never null or undefined)", () => {
    vi.mocked(motionReact.useReducedMotion).mockReturnValue(null);
    const { result } = renderHook(() => useReducedMotion());
    expect(typeof result.current).toBe("boolean");
  });
});
