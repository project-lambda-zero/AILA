import { describe, expect, it } from "vitest";

import { unwrap, type DataEnvelope } from "@/lib/dataEnvelope";

describe("dataEnvelope", () => {
  it("returns the data field of a well-formed envelope", () => {
    const env: DataEnvelope<number[]> = { data: [1, 2, 3], meta: { total: 3 } };
    expect(unwrap(env)).toEqual([1, 2, 3]);
  });

  it("returns nested object data unchanged", () => {
    const env: DataEnvelope<{ x: string }> = { data: { x: "y" } };
    expect(unwrap(env)).toEqual({ x: "y" });
  });

  it("throws when data field is missing", () => {
    const bad = { meta: { total: 0 } } as unknown as DataEnvelope<unknown>;
    expect(() => unwrap(bad)).toThrow(/Missing data field/);
  });

  it("throws when envelope is null or undefined", () => {
    expect(() => unwrap(null as unknown as DataEnvelope<unknown>)).toThrow();
    expect(() => unwrap(undefined as unknown as DataEnvelope<unknown>)).toThrow();
  });
});
