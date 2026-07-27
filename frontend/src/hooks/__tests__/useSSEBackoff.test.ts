import { describe, expect, it } from "vitest";

import { computeBackoffDelayMs } from "@/hooks/useSSE";

// The exported schedule (attempt: base ms):
//   0: 1_000, 1: 2_000, 2: 4_000, 3: 8_000, 4: 16_000, 5..: 30_000
// The jitter fraction is \u00b125% around the base step.

describe("computeBackoffDelayMs (#47 SSE jitter)", () => {
  it("returns a value near the base step when the random draw is 0.5", () => {
    // random()=0.5 -> (0.5*2 - 1) = 0 -> zero jitter -> exactly the base step.
    expect(computeBackoffDelayMs(0, () => 0.5)).toBe(1_000);
    expect(computeBackoffDelayMs(3, () => 0.5)).toBe(8_000);
  });

  it("subtracts up to 25% of the base step when random draw is 0", () => {
    // random()=0 -> -1 * (base * 0.25) = -25% of base
    expect(computeBackoffDelayMs(0, () => 0)).toBe(750);
    expect(computeBackoffDelayMs(2, () => 0)).toBe(3_000);
  });

  it("adds up to 25% of the base step when random draw approaches 1", () => {
    // random()=~1 -> +25% (strictly less than +25% because random is [0,1)).
    const delay = computeBackoffDelayMs(0, () => 0.9999);
    // Base 1000, +~25% -> ~1250 (rounded), never above 1250.
    expect(delay).toBeGreaterThan(1_000);
    expect(delay).toBeLessThanOrEqual(1_250);
  });

  it("caps at the 30s step for large attempt counters", () => {
    // The 30s cap is the last entry; higher attempts land there.
    // Zero-jitter random() -> exact base.
    expect(computeBackoffDelayMs(5, () => 0.5)).toBe(30_000);
    expect(computeBackoffDelayMs(50, () => 0.5)).toBe(30_000);
  });

  it("never returns a negative delay even with pathological input", () => {
    expect(computeBackoffDelayMs(-3, () => 0)).toBeGreaterThanOrEqual(0);
  });

  it("varies across successive calls when Math.random is used", () => {
    // Draw a handful of live samples and check they are not all identical --
    // this is a spot-check that we are actually consulting the RNG, not a
    // statistical assertion.
    const values = new Set<number>();
    for (let i = 0; i < 8; i += 1) values.add(computeBackoffDelayMs(2));
    expect(values.size).toBeGreaterThan(1);
  });
});
