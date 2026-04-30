import { describe, expect, it } from "vitest";

import {
  isErrorEnvelope,
  parseErrorEnvelope,
  type ErrorEnvelope,
} from "@/lib/errorEnvelope";

describe("isErrorEnvelope", () => {
  it("accepts the exact 4-field canonical shape", () => {
    const env: ErrorEnvelope = {
      code: "MISSING_API_KEY",
      message: "no key",
      hint: "go to admin",
      trace_id: "abc-123",
    };
    expect(isErrorEnvelope(env)).toBe(true);
  });

  it("accepts null hint and null trace_id", () => {
    const env: ErrorEnvelope = {
      code: "X",
      message: "y",
      hint: null,
      trace_id: null,
    };
    expect(isErrorEnvelope(env)).toBe(true);
  });

  it("rejects objects missing fields", () => {
    expect(isErrorEnvelope({ code: "X" })).toBe(false);
    expect(isErrorEnvelope({ message: "X" })).toBe(false);
  });

  it("rejects wrong-type fields", () => {
    expect(
      isErrorEnvelope({ code: 1, message: "m", hint: null, trace_id: null }),
    ).toBe(false);
    expect(
      isErrorEnvelope({ code: "X", message: "m", hint: 5, trace_id: null }),
    ).toBe(false);
  });

  it("rejects non-objects", () => {
    expect(isErrorEnvelope(null)).toBe(false);
    expect(isErrorEnvelope(undefined)).toBe(false);
    expect(isErrorEnvelope("string")).toBe(false);
    expect(isErrorEnvelope(42)).toBe(false);
  });
});

describe("parseErrorEnvelope", () => {
  it("parses a valid envelope JSON body", async () => {
    const res = new Response(
      JSON.stringify({ code: "X", message: "y", hint: null, trace_id: "t" }),
      { status: 500, statusText: "Internal Server Error" },
    );
    const env = await parseErrorEnvelope(res);
    expect(env).toEqual({ code: "X", message: "y", hint: null, trace_id: "t" });
  });

  it("falls back to statusText for non-JSON bodies", async () => {
    const res = new Response("not json", { status: 502, statusText: "Bad Gateway" });
    const env = await parseErrorEnvelope(res);
    expect(env.code).toBe("UNKNOWN");
    expect(env.message).toBe("Bad Gateway");
    expect(env.hint).toBeNull();
    expect(env.trace_id).toBeNull();
  });

  it("falls back when JSON does not match envelope shape", async () => {
    const res = new Response(JSON.stringify({ unrelated: true }), {
      status: 500,
      statusText: "Something",
    });
    const env = await parseErrorEnvelope(res);
    expect(env.code).toBe("UNKNOWN");
  });
});
