import { describe, expect, it } from "vitest";

import {
  pickPostLoginTarget,
  sanitizeRedirectPath,
} from "@/lib/redirectAllowlist";

describe("sanitizeRedirectPath (#47 open-redirect defence)", () => {
  it("returns a valid same-origin path unchanged", () => {
    expect(sanitizeRedirectPath("/dashboard")).toBe("/dashboard");
    expect(sanitizeRedirectPath("/vulnerability/scans?id=abc")).toBe(
      "/vulnerability/scans?id=abc",
    );
    expect(sanitizeRedirectPath("/console#anchor")).toBe("/console#anchor");
  });

  it("collapses non-string values to /", () => {
    expect(sanitizeRedirectPath(null)).toBe("/");
    expect(sanitizeRedirectPath(undefined)).toBe("/");
    expect(sanitizeRedirectPath(42)).toBe("/");
    expect(sanitizeRedirectPath({ from: "/x" })).toBe("/");
  });

  it("collapses empty strings and non-slash-prefixed strings to /", () => {
    expect(sanitizeRedirectPath("")).toBe("/");
    expect(sanitizeRedirectPath("dashboard")).toBe("/");
    expect(sanitizeRedirectPath(" /leading-space")).toBe("/");
  });

  it("rejects protocol-relative URLs (open redirect via //)", () => {
    expect(sanitizeRedirectPath("//evil.example")).toBe("/");
    expect(sanitizeRedirectPath("//evil.example/path")).toBe("/");
    expect(sanitizeRedirectPath("///triple")).toBe("/");
  });

  it("rejects backslash-tricked protocol-relative URLs", () => {
    expect(sanitizeRedirectPath("/\\evil.example")).toBe("/");
  });

  it("rejects absolute URLs pointing off-origin", () => {
    expect(sanitizeRedirectPath("https://evil.example/steal")).toBe("/");
    expect(sanitizeRedirectPath("http://aila.local/valid")).toBe("/");
  });

  it("rejects javascript: and other URL schemes even path-embedded", () => {
    expect(sanitizeRedirectPath("javascript:alert(1)")).toBe("/");
    expect(sanitizeRedirectPath("/javascript:alert(1)")).toBe("/");
    expect(sanitizeRedirectPath("/data:text/html,<script>alert(1)</script>")).toBe(
      "/",
    );
    expect(sanitizeRedirectPath("/vbscript:msgbox(1)")).toBe("/");
  });

  it("rejects strings carrying control characters", () => {
    expect(sanitizeRedirectPath("/dashboard\n")).toBe("/");
    expect(sanitizeRedirectPath("/dash\x00board")).toBe("/");
    expect(sanitizeRedirectPath("/dash\x7fboard")).toBe("/");
  });
});

describe("pickPostLoginTarget", () => {
  it("prefers a router-state hint when present and safe", () => {
    expect(pickPostLoginTarget("/dashboard", "?next=/other")).toBe(
      "/dashboard",
    );
  });

  it("falls back to ?next= when router state is missing", () => {
    expect(pickPostLoginTarget(undefined, "?next=/dashboard")).toBe(
      "/dashboard",
    );
  });

  it("falls through to / when both are absent", () => {
    expect(pickPostLoginTarget(undefined, undefined)).toBe("/");
    expect(pickPostLoginTarget(null, "")).toBe("/");
  });

  it("sanitizes an unsafe router-state hint instead of promoting to ?next=", () => {
    // Even though `?next=/safe` exists, an unsafe state hint MUST collapse
    // to `/` -- otherwise a caller could pass `//evil` in state and get
    // the search-string reader to pick up its safer value, silently
    // ignoring the attack instead of forcing a fallback.
    expect(pickPostLoginTarget("//evil.example", "?next=/safe")).toBe("/");
  });

  it("sanitizes an unsafe ?next= value", () => {
    expect(pickPostLoginTarget(undefined, "?next=https://evil.example")).toBe(
      "/",
    );
  });

  it("accepts a URLSearchParams object as the search argument", () => {
    const params = new URLSearchParams();
    params.set("next", "/dashboard");
    expect(pickPostLoginTarget(undefined, params)).toBe("/dashboard");
  });
});
